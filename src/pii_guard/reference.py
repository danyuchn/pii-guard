"""Reference lists: deterministic seeding from a customer table.

Detection is context sensitive and misses nicknames, unusual spellings and
internal codes entirely.  A project usually already owns the list of values it
cares about -- a customer spreadsheet, an order export -- so this module turns
one of those tables into seed terms and shape patterns without asking a model
anything and without copying the table anywhere.

What is stored is a *description* of the source (its path, which column means
what, and any shape rule inferred from a column), never the values.  The values
are read from the original file when the service needs them, so editing the
spreadsheet is enough to update what gets masked.

Nothing here prints, logs or returns a value from the table.  The only
exception is :attr:`ColumnReport.samples`, which the local web page shows so a
person can confirm they picked the right column; it is capped at three values
per column and never crosses a log.
"""

from __future__ import annotations

import csv
import io
import json
import os
import re
from collections.abc import Callable, Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Final

from pii_guard.hookd.policy import structured_entity_type
from pii_guard.local_workflow import JOB_MODE, PRIVATE_MODE, WorkflowError

# Entity types a column can be mapped to, with the label the user sees.  The
# keys are the engine's own entity names, so a seeded value and a detected one
# end up under the same placeholder prefix.
COLUMN_TYPES: Final[dict[str, str]] = {
    "PERSON": "姓名",
    "ORG": "公司／組織",
    "TW_MOBILE": "手機",
    "TW_LANDLINE": "市話",
    "EMAIL_ADDRESS": "電子郵件",
    "TW_NATIONAL_ID": "身分證字號",
    "TW_BUSINESS_ID": "統一編號",
    "TW_ADDRESS": "地址",
    "TW_BANK_ACCOUNT": "銀行帳號",
    "TW_LICENSE_PLATE": "車牌",
    "ORDER_ID": "訂單／案件編號",
    "CUSTOM": "其他要遮的字",
    "SKIP": "不要遮",
}

# Friendlier spellings accepted on the command line, mapped to the real names.
TYPE_ALIASES: Final[dict[str, str]] = {
    "TW_ID": "TW_NATIONAL_ID",
    "TW_ID_NUMBER": "TW_NATIONAL_ID",
    "TW_PHONE": "TW_LANDLINE",
    "TW_PLATE": "TW_LICENSE_PLATE",
    "EMAIL": "EMAIL_ADDRESS",
    "ORGANIZATION": "ORG",
    "NONE": "SKIP",
    "IGNORE": "SKIP",
}

# Column-header keywords, longest first so "統一編號" wins over "編號".
HEADER_HINTS: Final[tuple[tuple[str, str], ...]] = (
    ("統一編號", "TW_BUSINESS_ID"),
    ("統編", "TW_BUSINESS_ID"),
    ("身分證", "TW_NATIONAL_ID"),
    ("身份證", "TW_NATIONAL_ID"),
    ("居留證", "TW_NATIONAL_ID"),
    ("聯絡人", "PERSON"),
    ("負責人", "PERSON"),
    ("客戶名稱", "PERSON"),
    ("姓名", "PERSON"),
    ("名字", "PERSON"),
    ("客戶", "PERSON"),
    ("contact", "PERSON"),
    ("name", "PERSON"),
    ("公司", "ORG"),
    ("廠商", "ORG"),
    ("單位", "ORG"),
    ("organization", "ORG"),
    ("organisation", "ORG"),
    ("company", "ORG"),
    ("手機", "TW_MOBILE"),
    ("行動電話", "TW_MOBILE"),
    ("行動", "TW_MOBILE"),
    ("mobile", "TW_MOBILE"),
    ("cell", "TW_MOBILE"),
    ("市話", "TW_LANDLINE"),
    ("電話", "TW_LANDLINE"),
    ("phone", "TW_LANDLINE"),
    ("tel", "TW_LANDLINE"),
    ("email", "EMAIL_ADDRESS"),
    ("e-mail", "EMAIL_ADDRESS"),
    ("信箱", "EMAIL_ADDRESS"),
    ("郵件", "EMAIL_ADDRESS"),
    ("地址", "TW_ADDRESS"),
    ("address", "TW_ADDRESS"),
    ("銀行帳號", "TW_BANK_ACCOUNT"),
    ("帳號", "TW_BANK_ACCOUNT"),
    ("account", "TW_BANK_ACCOUNT"),
    ("車牌", "TW_LICENSE_PLATE"),
    ("plate", "TW_LICENSE_PLATE"),
    ("訂單", "ORDER_ID"),
    ("單號", "ORDER_ID"),
    ("案號", "ORDER_ID"),
    ("案件", "ORDER_ID"),
    ("編號", "ORDER_ID"),
    ("order", "ORDER_ID"),
    ("no.", "ORDER_ID"),
    ("金額", "SKIP"),
    ("價格", "SKIP"),
    ("總價", "SKIP"),
    ("小計", "SKIP"),
    ("數量", "SKIP"),
    ("日期", "SKIP"),
    ("備註", "SKIP"),
    ("amount", "SKIP"),
    ("price", "SKIP"),
    ("total", "SKIP"),
    ("date", "SKIP"),
    ("note", "SKIP"),
    ("remark", "SKIP"),
)

# Short numbers and amounts collide with ordinary text everywhere, so a column
# that looks like money or a date is never masked by default.  The web page
# says why rather than silently deciding for the user.
NUMERIC_SKIP_REASON: Final[str] = "短數字容易誤遮，建議不遮"

# Types that only a model can find in running text.  A structured value such as
# a phone number never gets relabelled into one of these.
NER_ONLY_TYPES: Final[frozenset[str]] = frozenset({"PERSON", "ORG", "ORDER_ID", "CUSTOM"})

SOURCES_RELATIVE: Final[str] = ".pii-guard/sources.json"
TERMS_RELATIVE: Final[str] = ".pii-guard/terms.txt"
GUARD_DIRECTORY: Final[str] = ".pii-guard"
GITIGNORE_LINE: Final[str] = ".pii-guard/"
SOURCES_VERSION: Final[int] = 1

MAX_REFERENCE_TERMS: Final[int] = 50_000
MAX_TABLE_ROWS: Final[int] = 200_000
MAX_COLUMNS: Final[int] = 256
MAX_VALUE_LENGTH: Final[int] = 256
MAX_TABLE_BYTES: Final[int] = 64 * 1024 * 1024
SAMPLE_LIMIT: Final[int] = 3
# Shapes shorter than this match far too much ordinary text to be safe.
MIN_SHAPE_LENGTH: Final[int] = 5
SHAPE_AGREEMENT: Final[float] = 0.90
MAX_SHAPE_REGEX_LENGTH: Final[int] = 200

CSV_SUFFIXES: Final[frozenset[str]] = frozenset({".csv", ".tsv", ".txt"})
EXCEL_SUFFIXES: Final[frozenset[str]] = frozenset({".xlsx", ".xlsm"})
CSV_ENCODINGS: Final[tuple[str, ...]] = ("utf-8-sig", "utf-8", "cp950", "big5")

_CJK_PATTERN: Final[re.Pattern[str]] = re.compile(r"[㐀-䶿一-鿿豈-﫿]")
_ENTITY_NAME_PATTERN: Final[re.Pattern[str]] = re.compile(r"^[A-Z][A-Z0-9_]*$")


def normalize_type(value: str) -> str:
    """Return the canonical entity name for a user-supplied type."""

    name = (value or "").strip().upper().replace("-", "_")
    name = TYPE_ALIASES.get(name, name)
    if name in COLUMN_TYPES:
        return name
    if _ENTITY_NAME_PATTERN.fullmatch(name):
        # An entity name this build does not know is still usable: the
        # placeholder prefix is the only thing that depends on it.
        return name
    return "CUSTOM"


def type_label(entity_type: str) -> str:
    """The Chinese label for a type, falling back to the type itself."""

    return COLUMN_TYPES.get(entity_type, entity_type)


# ---------------------------------------------------------------------------
# Risk and shape rules
# ---------------------------------------------------------------------------


# Excel stores a phone number typed without quotes as a number, which loses the
# leading zero: 0912345678 comes back as 912345678 and would never match the
# text the guard actually sees.  Taiwan lists hit this constantly.
_LOST_ZERO_PATTERNS: Final[dict[str, re.Pattern[str]]] = {
    "TW_MOBILE": re.compile(r"9\d{8}"),
    "TW_LANDLINE": re.compile(r"[2-8]\d{7,8}"),
}
TW_BUSINESS_ID_LENGTH: Final[int] = 8


def normalize_value(entity_type: str, value: str) -> str:
    """Put back the leading zero a spreadsheet dropped, by column type.

    Only the types whose real values are known to start with a zero are
    touched, and only when what is left is exactly the shape that losing the
    zero would produce.  Everything else is returned unchanged.
    """

    text = (value or "").strip()
    if not text:
        return text
    pattern = _LOST_ZERO_PATTERNS.get(entity_type)
    if pattern is not None and pattern.fullmatch(text):
        return "0" + text
    if (
        entity_type == "TW_BUSINESS_ID"
        and text.isdigit()
        and len(text) < TW_BUSINESS_ID_LENGTH
    ):
        return text.zfill(TW_BUSINESS_ID_LENGTH)
    return text


def is_risky(value: str) -> bool:
    """Is this value too short or too generic to mask without asking?

    Masking "李" or "abc" everywhere would rewrite ordinary prose.  Risky
    values are reported and skipped unless the user asks for them back.
    """

    text = (value or "").strip()
    if not text:
        return True
    if text.isdigit():
        return len(text) <= 6
    if _CJK_PATTERN.search(text):
        return len(text) < 2
    return len(text) < 4


def _skeleton(value: str) -> str:
    """Collapse a value to its character classes: ``ORD-000123`` -> ``AAA-999999``."""

    out: list[str] = []
    for character in value:
        if character.isdigit():
            out.append("9")
        elif character.isascii() and character.isupper():
            out.append("A")
        elif character.isascii() and character.islower():
            out.append("a")
        else:
            out.append(character)
    return "".join(out)


def _skeleton_regex(skeleton: str) -> str | None:
    """Turn a skeleton into an anchored regex, or ``None`` when unusable."""

    parts: list[str] = []
    index = 0
    length = len(skeleton)
    while index < length:
        character = skeleton[index]
        run = 1
        while index + run < length and skeleton[index + run] == character:
            run += 1
        if character in {"9", "A", "a"}:
            body = {"9": r"\d", "A": "[A-Z]", "a": "[a-z]"}[character]
            parts.append(body if run == 1 else f"{body}{{{run}}}")
        else:
            escaped = re.escape(character)
            parts.append(escaped if run == 1 else f"(?:{escaped}){{{run}}}")
        index += run
    # A bare run of digits or letters would match inside longer tokens, so the
    # pattern only fires on a whole word.
    regex = r"(?<![A-Za-z0-9])" + "".join(parts) + r"(?![A-Za-z0-9])"
    if len(regex) > MAX_SHAPE_REGEX_LENGTH:
        return None
    try:
        re.compile(regex)
    except re.error:
        return None
    return regex


def infer_shape(values: Iterable[str]) -> str | None:
    """Infer one regex that covers a column, or ``None`` when it varies.

    A column of order numbers usually has exactly one shape.  When it does,
    numbers that are not in the list yet are masked too, which is the whole
    point of preferring a shape over a value list.
    """

    skeletons: dict[str, int] = {}
    total = 0
    for value in values:
        text = (value or "").strip()
        if not text or len(text) > MAX_VALUE_LENGTH:
            continue
        total += 1
        skeleton = _skeleton(text)
        skeletons[skeleton] = skeletons.get(skeleton, 0) + 1
    if total < 2 or not skeletons:
        return None
    dominant, count = max(skeletons.items(), key=lambda item: item[1])
    if len(dominant) < MIN_SHAPE_LENGTH:
        return None
    if count / total < SHAPE_AGREEMENT:
        return None
    # A shape made only of literal characters is just one repeated value.
    if not any(character in dominant for character in "9Aa"):
        return None
    return _skeleton_regex(dominant)


# ---------------------------------------------------------------------------
# Table inspection
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ColumnReport:
    """What one column of a table looks like; carries at most three values."""

    name: str
    index: int
    guessed_type: str
    non_empty: int
    risky: int
    samples: tuple[str, ...] = ()
    shape: str | None = None

    def describe(self, *, include_samples: bool = False) -> dict[str, Any]:
        """A JSON-safe summary; values are only included when asked for."""

        payload: dict[str, Any] = {
            "name": self.name,
            "index": self.index,
            "guessed_type": self.guessed_type,
            "label": type_label(self.guessed_type),
            "non_empty": self.non_empty,
            "risky": self.risky,
            "shape": self.shape,
        }
        if include_samples:
            payload["samples"] = list(self.samples)
        return payload


@dataclass(frozen=True)
class TableReport:
    """The column layout of one table, plus the sheets it could have used."""

    path: str
    sheet: str | None
    rows: int
    columns: tuple[ColumnReport, ...]
    sheets: tuple[str, ...] = ()

    def describe(self, *, include_samples: bool = False) -> dict[str, Any]:
        return {
            "path": self.path,
            "sheet": self.sheet,
            "sheets": list(self.sheets),
            "rows": self.rows,
            "columns": [
                column.describe(include_samples=include_samples) for column in self.columns
            ],
        }


def guess_from_header(header: str) -> str | None:
    """Map a column title to a type by keyword, or ``None``."""

    text = (header or "").strip().lower()
    if not text:
        return None
    for keyword, entity_type in HEADER_HINTS:
        if keyword in text:
            return entity_type
    return None


def _guess_from_values(values: Sequence[str]) -> str | None:
    """Name a column by the shape of the values it holds, or ``None``."""

    seen: dict[str, int] = {}
    counted = 0
    for value in values:
        text = (value or "").strip()
        if not text:
            continue
        counted += 1
        entity_type = structured_entity_type(text)
        if entity_type is not None:
            seen[entity_type] = seen.get(entity_type, 0) + 1
    if not counted or not seen:
        return None
    entity_type, count = max(seen.items(), key=lambda item: item[1])
    return entity_type if count / counted >= SHAPE_AGREEMENT else None


def _cell_text(value: object) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value.strip()
    if isinstance(value, bool):
        return ""
    if isinstance(value, float) and value.is_integer():
        return str(int(value))
    return str(value).strip()


def _read_excel_rows(
    path: Path, sheet: str | None, max_rows: int
) -> tuple[list[list[str]], str, tuple[str, ...]]:
    try:
        import openpyxl
    except ImportError as error:  # pragma: no cover - optional dependency
        raise WorkflowError(
            "OPENPYXL_MISSING",
            "Reading .xlsx needs openpyxl: uv sync --extra formats",
        ) from error
    try:
        workbook = openpyxl.load_workbook(path, read_only=True, data_only=True)
    except Exception as error:  # noqa: BLE001 - any parse failure is the same answer
        raise WorkflowError("TABLE_MALFORMED", "The table could not be read.") from error
    try:
        names = tuple(str(name) for name in workbook.sheetnames)
        if sheet is not None and sheet not in names:
            raise WorkflowError("SHEET_NOT_FOUND", "That sheet is not in this workbook.")
        selected = sheet or (names[0] if names else "")
        if not selected:
            raise WorkflowError("TABLE_EMPTY", "The table has no sheets.")
        worksheet = workbook[selected]
        rows: list[list[str]] = []
        for row in worksheet.iter_rows(values_only=True):
            rows.append([_cell_text(cell) for cell in row[:MAX_COLUMNS]])
            if len(rows) >= max_rows:
                break
        return rows, selected, names
    finally:
        workbook.close()


def _decode_csv(data: bytes) -> str:
    for encoding in CSV_ENCODINGS:
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise WorkflowError(
        "TABLE_NOT_DECODABLE",
        "The file is not UTF-8, CP950 or Big5 text.",
    )


def _read_csv_rows(path: Path, max_rows: int) -> list[list[str]]:
    try:
        size = path.stat().st_size
    except OSError as error:
        raise WorkflowError("TABLE_NOT_FOUND", "The table could not be opened.") from error
    if size > MAX_TABLE_BYTES:
        raise WorkflowError("TABLE_TOO_LARGE", "The table exceeds the safety size limit.")
    try:
        raw = path.read_bytes()
    except OSError as error:
        raise WorkflowError("TABLE_NOT_FOUND", "The table could not be opened.") from error
    delimiter = "\t" if path.suffix.lower() == ".tsv" else None
    return parse_csv_bytes(raw, max_rows=max_rows, delimiter=delimiter)


def parse_csv_bytes(
    data: bytes, *, max_rows: int = MAX_TABLE_ROWS, delimiter: str | None = None
) -> list[list[str]]:
    """Parse delimited text held in memory, sniffing the encoding first."""

    text = _decode_csv(data)
    if delimiter is None:
        head = text[:8192]
        delimiter = "\t" if head.count("\t") > head.count(",") else ","
    rows: list[list[str]] = []
    for row in csv.reader(io.StringIO(text, newline=""), delimiter=delimiter):
        rows.append([_cell_text(cell) for cell in row[:MAX_COLUMNS]])
        if len(rows) >= max_rows:
            break
    return rows


def build_report(
    rows: Sequence[Sequence[str]],
    *,
    path: str,
    sheet: str | None = None,
    sheets: tuple[str, ...] = (),
) -> TableReport:
    """Turn parsed rows into a column report, first row being the header."""

    if not rows:
        raise WorkflowError("TABLE_EMPTY", "The table has no rows.")
    header = list(rows[0])
    body = rows[1:]
    columns: list[ColumnReport] = []
    for index, raw_name in enumerate(header):
        name = raw_name.strip() or f"第 {index + 1} 欄"
        values = [row[index].strip() if index < len(row) else "" for row in body]
        present = [value for value in values if value]
        guessed = guess_from_header(raw_name)
        by_value = _guess_from_values(present)
        # The header names the intent; the values are the evidence.  A value
        # guess only overrides a header guess the values contradict.
        if by_value is not None and (guessed is None or guessed in NER_ONLY_TYPES):
            if guessed is None or by_value != guessed:
                guessed = by_value
        if guessed is None:
            guessed = "CUSTOM" if present else "SKIP"
        # The samples, the risky count and the shape all have to describe the
        # values the guard will actually look for, not the ones the spreadsheet
        # happened to store.
        present = [normalize_value(guessed, value) for value in present]
        shape = infer_shape(present) if guessed not in {"SKIP", "PERSON", "ORG"} else None
        columns.append(
            ColumnReport(
                name=name,
                index=index,
                guessed_type=guessed,
                non_empty=len(present),
                risky=sum(1 for value in present if is_risky(value)),
                samples=tuple(present[:SAMPLE_LIMIT]),
                shape=shape,
            )
        )
    return TableReport(
        path=path,
        sheet=sheet,
        rows=len(body),
        columns=tuple(columns),
        sheets=sheets,
    )


def read_rows(
    path: Path, *, sheet: str | None = None, max_rows: int = MAX_TABLE_ROWS
) -> tuple[list[list[str]], str | None, tuple[str, ...]]:
    """Read a table off disk, returning its rows, sheet name and sheet list."""

    suffix = path.suffix.lower()
    if suffix in EXCEL_SUFFIXES:
        rows, selected, names = _read_excel_rows(path, sheet, max_rows)
        return rows, selected, names
    if suffix in CSV_SUFFIXES:
        return _read_csv_rows(path, max_rows), None, ()
    raise WorkflowError(
        "TABLE_UNSUPPORTED",
        "Only .xlsx, .xlsm, .csv, .tsv and .txt tables are supported.",
    )


def inspect_table(
    path: str | Path, *, sheet: str | None = None, max_rows: int | None = None
) -> TableReport:
    """Describe the columns of a table without keeping any of its values."""

    resolved = Path(path).expanduser()
    if not resolved.is_file():
        raise WorkflowError("TABLE_NOT_FOUND", "That table does not exist.")
    rows, selected, sheets = read_rows(
        resolved, sheet=sheet, max_rows=max_rows or MAX_TABLE_ROWS
    )
    return build_report(rows, path=str(resolved), sheet=selected, sheets=sheets)


# ---------------------------------------------------------------------------
# Stored source descriptions
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReferenceSource:
    """One table this project wants masked, described without its values."""

    path: str
    sheet: str | None = None
    columns: dict[str, str] = field(default_factory=dict)
    patterns: tuple[tuple[str, str], ...] = ()

    def describe(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "sheet": self.sheet,
            "columns": dict(self.columns),
            "patterns": [{"type": name, "regex": regex} for name, regex in self.patterns],
        }

    @classmethod
    def from_mapping(cls, payload: object) -> ReferenceSource | None:
        """Build a source from stored JSON, or ``None`` when it is malformed."""

        if not isinstance(payload, Mapping):
            return None
        path = payload.get("path")
        if not isinstance(path, str) or not path.strip():
            return None
        sheet = payload.get("sheet")
        columns: dict[str, str] = {}
        raw_columns = payload.get("columns")
        if isinstance(raw_columns, Mapping):
            for name, entity_type in raw_columns.items():
                if isinstance(name, str) and isinstance(entity_type, str):
                    columns[name] = normalize_type(entity_type)
        patterns: list[tuple[str, str]] = []
        raw_patterns = payload.get("patterns")
        if isinstance(raw_patterns, list):
            for entry in raw_patterns:
                if not isinstance(entry, Mapping):
                    continue
                name = entry.get("type")
                regex = entry.get("regex")
                if not isinstance(name, str) or not isinstance(regex, str):
                    continue
                if len(regex) > MAX_SHAPE_REGEX_LENGTH:
                    continue
                try:
                    re.compile(regex)
                except re.error:
                    continue
                patterns.append((normalize_type(name), regex))
        return cls(
            path=path,
            sheet=sheet if isinstance(sheet, str) and sheet else None,
            columns=columns,
            patterns=tuple(patterns),
        )


def sources_path(project: str | Path) -> Path:
    """Where a project keeps its source descriptions."""

    return Path(project).expanduser() / SOURCES_RELATIVE


def terms_path(project: str | Path) -> Path:
    """Where ``--materialize`` writes a flat term list."""

    return Path(project).expanduser() / TERMS_RELATIVE


def ensure_gitignored(project: str | Path) -> bool:
    """Add ``.pii-guard/`` to the project's ``.gitignore``; report if changed.

    The directory holds a description of where personal data lives, and with
    ``--materialize`` the values themselves.  Neither belongs in a commit.
    """

    gitignore = Path(project).expanduser() / ".gitignore"
    try:
        existing = gitignore.read_text(encoding="utf-8") if gitignore.is_file() else ""
    except (OSError, UnicodeError):
        return False
    lines = [line.strip() for line in existing.splitlines()]
    if GITIGNORE_LINE in lines or GUARD_DIRECTORY in lines:
        return False
    prefix = "" if not existing or existing.endswith("\n") else "\n"
    try:
        with gitignore.open("a", encoding="utf-8") as handle:
            handle.write(f"{prefix}{GITIGNORE_LINE}\n")
    except OSError:
        return False
    return True


def _write_owner_only(path: Path, text: str) -> None:
    """Write a file only this user can read, replacing any earlier one."""

    path.parent.mkdir(parents=True, exist_ok=True, mode=JOB_MODE)
    try:
        os.chmod(path.parent, JOB_MODE)
    except OSError:
        pass
    temporary = path.with_name(path.name + ".tmp")
    descriptor = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, PRIVATE_MODE
    )
    with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
        handle.write(text)
    os.replace(temporary, path)
    os.chmod(path, PRIVATE_MODE)


def write_sources(project: str | Path, sources: Sequence[ReferenceSource]) -> Path:
    """Store the source descriptions for a project and return the file path."""

    target = sources_path(project)
    payload = {
        "version": SOURCES_VERSION,
        "sources": [source.describe() for source in sources],
    }
    _write_owner_only(target, json.dumps(payload, ensure_ascii=False, indent=2) + "\n")
    ensure_gitignored(project)
    return target


def load_sources_file(path: str | Path) -> list[ReferenceSource]:
    """Read one ``sources.json``; a missing or broken file means no sources."""

    resolved = Path(path).expanduser()
    try:
        payload = json.loads(resolved.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return []
    if not isinstance(payload, Mapping):
        return []
    raw = payload.get("sources")
    if not isinstance(raw, list):
        return []
    sources: list[ReferenceSource] = []
    for entry in raw:
        source = ReferenceSource.from_mapping(entry)
        if source is not None:
            sources.append(source)
    return sources


def load_sources(project: str | Path) -> list[ReferenceSource]:
    """Read a project's stored source descriptions."""

    return load_sources_file(sources_path(project))


def _installer_config_path() -> Path:
    """Where the installer keeps the list of projects the service should read."""

    from pii_guard.hookd import install as installer

    return installer.hookd_config_path()


def registered_source_files() -> tuple[str, ...]:
    """The ``sources.json`` paths the running service is meant to read.

    Read fresh every time.  A project registered after the service started has
    to become visible without a restart, which is the whole point of reload.
    """

    try:
        payload = json.loads(_installer_config_path().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return ()
    if not isinstance(payload, Mapping):
        return ()
    policy_block = payload.get("policy")
    if not isinstance(policy_block, Mapping):
        return ()
    raw = policy_block.get("reference_sources")
    if not isinstance(raw, list):
        return ()
    return tuple(item for item in raw if isinstance(item, str) and item.strip())


def _write_installer_reference_sources(files: Sequence[str]) -> None:
    """Rewrite only the reference list, leaving the rest of the config alone."""

    from pii_guard.hookd import install as installer

    path = _installer_config_path()
    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}
    policy_block = payload.get("policy")
    payload["policy"] = dict(policy_block) if isinstance(policy_block, Mapping) else {}
    payload["policy"]["reference_sources"] = list(files)
    installer._atomic_write(
        path, json.dumps(payload, ensure_ascii=False, indent=2) + "\n", mode=PRIVATE_MODE
    )


def register_project(project: str | Path) -> bool:
    """Tell the service to read this project's list; ``True`` when it changed.

    Writing ``sources.json`` is not enough on its own: the service only reads
    the descriptions the installer config names, so a project imported after
    the hooks were installed would be silently ignored.
    """

    descriptor = str(sources_path(project))
    existing = registered_source_files()
    if descriptor in existing:
        return False
    _write_installer_reference_sources([*existing, descriptor])
    return True


def unregister_project(project: str | Path) -> bool:
    """Stop the service reading this project's list; ``True`` when it changed."""

    descriptor = str(sources_path(project))
    existing = registered_source_files()
    if descriptor not in existing:
        return False
    _write_installer_reference_sources([item for item in existing if item != descriptor])
    return True


def source_fingerprint(sources: Sequence[ReferenceSource]) -> tuple[Any, ...]:
    """A cheap cache key: each source's path, size and modification time.

    Editing the spreadsheet has to be enough.  Asking the user to restart the
    service after every list change is how a list goes stale.
    """

    marks: list[Any] = []
    for source in sources:
        path = Path(source.path).expanduser()
        try:
            status = path.stat()
            marks.append((source.path, source.sheet, status.st_size, status.st_mtime_ns))
        except OSError:
            marks.append((source.path, source.sheet, -1, -1))
        marks.append(tuple(sorted(source.columns.items())))
        marks.append(source.patterns)
    return tuple(marks)


# ---------------------------------------------------------------------------
# Turning sources into terms
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class ReferenceLoad:
    """The outcome of reading every source: terms, patterns and counts."""

    terms: tuple[tuple[str, str], ...] = ()
    patterns: tuple[tuple[str, str], ...] = ()
    counts: dict[str, int] = field(default_factory=dict)
    risky_skipped: int = 0
    missing: tuple[str, ...] = ()
    truncated: bool = False

    def summary(self) -> dict[str, Any]:
        """Counts only; never a value."""

        return {
            "terms": len(self.terms),
            "patterns": [
                {"type": name, "regex": regex, "label": type_label(name)}
                for name, regex in self.patterns
            ],
            "counts": dict(self.counts),
            "labels": {name: type_label(name) for name in self.counts},
            "risky_skipped": self.risky_skipped,
            "missing": list(self.missing),
            "truncated": self.truncated,
        }


def load_reference_terms(
    sources: Sequence[ReferenceSource],
    *,
    include_risky: bool = False,
    max_terms: int = MAX_REFERENCE_TERMS,
) -> ReferenceLoad:
    """Read every source and return the seed terms its columns describe."""

    terms: list[tuple[str, str]] = []
    seen: set[str] = set()
    counts: dict[str, int] = {}
    patterns: list[tuple[str, str]] = []
    pattern_seen: set[tuple[str, str]] = set()
    missing: list[str] = []
    risky_skipped = 0
    truncated = False

    for source in sources:
        for name, regex in source.patterns:
            key = (name, regex)
            if key not in pattern_seen:
                pattern_seen.add(key)
                patterns.append(key)
        path = Path(source.path).expanduser()
        if not path.is_file():
            missing.append(source.path)
            continue
        try:
            rows, _, _ = read_rows(path, sheet=source.sheet)
        except WorkflowError:
            missing.append(source.path)
            continue
        if not rows:
            continue
        header = [str(cell).strip() for cell in rows[0]]
        wanted: list[tuple[int, str]] = []
        for index, title in enumerate(header):
            entity_type = source.columns.get(title)
            if entity_type is None or entity_type == "SKIP":
                continue
            wanted.append((index, entity_type))
        if not wanted:
            continue
        for row in rows[1:]:
            for index, entity_type in wanted:
                if index >= len(row):
                    continue
                value = normalize_value(entity_type, str(row[index]).strip())
                if not value or len(value) > MAX_VALUE_LENGTH:
                    continue
                if not include_risky and is_risky(value):
                    risky_skipped += 1
                    continue
                if value in seen:
                    continue
                if len(terms) >= max_terms:
                    truncated = True
                    break
                seen.add(value)
                terms.append((entity_type, value))
                counts[entity_type] = counts.get(entity_type, 0) + 1
            if truncated:
                break
        if truncated:
            break

    return ReferenceLoad(
        terms=tuple(terms),
        patterns=tuple(patterns),
        counts=counts,
        risky_skipped=risky_skipped,
        missing=tuple(missing),
        truncated=truncated,
    )


def materialize(
    sources: Sequence[ReferenceSource],
    target: str | Path,
    *,
    include_risky: bool = False,
) -> int:
    """Write a flat ``TYPE<TAB>value`` list, for setups that want one file.

    This is the only path that copies values out of the source table, so the
    file is written owner-only and the caller has to ask for it explicitly.
    """

    loaded = load_reference_terms(sources, include_risky=include_risky)
    lines = [f"{entity_type}\t{value}" for entity_type, value in loaded.terms]
    body = "\n".join(lines)
    _write_owner_only(Path(target).expanduser(), body + ("\n" if body else ""))
    return len(loaded.terms)


class ReferenceCache:
    """Reload the sources whenever one of the files behind them changes.

    *source_files* may be a fixed list or a callable.  The service passes a
    callable so that a project registered after it started is picked up on the
    next reload, rather than needing a restart.
    """

    def __init__(
        self,
        source_files: Sequence[str] | Callable[[], Sequence[str]] = registered_source_files,
    ) -> None:
        self._source_files = source_files
        self._fingerprint: tuple[Any, ...] | None = None
        self._loaded = ReferenceLoad()

    @property
    def source_files(self) -> tuple[str, ...]:
        if callable(self._source_files):
            try:
                return tuple(self._source_files())
            except Exception:  # noqa: BLE001 - an unreadable config means no lists
                return ()
        return tuple(self._source_files)

    def sources(self) -> list[ReferenceSource]:
        collected: list[ReferenceSource] = []
        for path in self.source_files:
            collected.extend(load_sources_file(path))
        return collected

    def load(self) -> ReferenceLoad:
        """Return the current terms, re-reading only when something changed."""

        sources = self.sources()
        # The list of descriptions is part of the key: registering a project
        # changes what should be loaded even when no table was touched.
        fingerprint = (self.source_files, source_fingerprint(sources))
        if fingerprint != self._fingerprint:
            self._loaded = load_reference_terms(sources)
            self._fingerprint = fingerprint
        return self._loaded

    def invalidate(self) -> None:
        """Forget the cached read, so the next load goes back to the files."""

        self._fingerprint = None
