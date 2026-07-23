"""Taiwan license plate, birth date, international mobile, bank account,
structured address, and secrets (verification code / password / crypto seed /
private key) recognizers.

Additional Taiwan PII types beyond the Phase 1 set.  All use lookarounds rather
than \\b boundaries (re.ASCII maps to regex.V1 in Presidio's internal regex module,
breaking boundary detection adjacent to Chinese characters).

Ambiguous numeric patterns (license plates, bank accounts, Western dates) require
a context keyword within ±50 characters to fire; self-contextualizing patterns
(Minguo dates with 民國 embedded, +886 prefix) do not.
"""

from __future__ import annotations

import re
from typing import ClassVar

from presidio_analyzer import LocalRecognizer, Pattern, PatternRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts

_FLAGS = re.DOTALL | re.MULTILINE
_CONTEXT_WINDOW = 50


def _has_context(text: str, start: int, end: int, keywords: list[str]) -> bool:
    """Return True if any keyword appears within ±CONTEXT_WINDOW chars of [start, end)."""
    ws = max(0, start - _CONTEXT_WINDOW)
    we = min(len(text), end + _CONTEXT_WINDOW)
    window = text[ws:we]
    return any(kw in window for kw in keywords)


# ── License Plate ──────────────────────────────────────────────────────────────

class TwLicensePlateRecognizer(LocalRecognizer):
    """Taiwan vehicle license plates (new and old formats) with context filter.

    New format: 2–3 uppercase letters + dash + 4 digits  (e.g. ABC-1234)
    Old format: 3–4 digits + dash + 2 uppercase letters  (e.g. 1234-AB)

    A context keyword is required within ±50 chars to suppress false positives
    from product codes, model numbers, etc.
    """

    SUPPORTED_ENTITY: ClassVar[str] = "TW_LICENSE_PLATE"
    # Compile with re.ASCII so [A-Z] / \d only match ASCII characters
    _PATTERNS: ClassVar[list[re.Pattern[str]]] = [
        re.compile(r"(?<![A-Za-z0-9])[A-Z]{2,3}-\d{4}(?![A-Za-z0-9])", re.ASCII),  # new
        re.compile(r"(?<!\d)\d{3,4}-[A-Z]{2}(?![A-Za-z0-9])", re.ASCII),            # old
    ]
    CONTEXT_KEYWORDS: ClassVar[list[str]] = [
        "車牌", "牌照", "車號", "車輛", "汽車", "機車", "行照", "號牌", "車籍", "車",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entities=[self.SUPPORTED_ENTITY],
            supported_language="zh",
            name="TwLicensePlateRecognizer",
        )

    def load(self) -> None:
        pass

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
    ) -> list[RecognizerResult]:
        if self.SUPPORTED_ENTITY not in entities:
            return []
        results: list[RecognizerResult] = []
        for pattern in self._PATTERNS:
            for match in pattern.finditer(text):
                if not _has_context(text, match.start(), match.end(), self.CONTEXT_KEYWORDS):
                    continue
                results.append(
                    RecognizerResult(
                        entity_type=self.SUPPORTED_ENTITY,
                        start=match.start(),
                        end=match.end(),
                        score=0.85,
                    )
                )
        return results


# ── Birth Date ─────────────────────────────────────────────────────────────────

class TwBirthDateRecognizer(LocalRecognizer):
    """Taiwan birth dates: Minguo calendar or Western ISO-style.

    Minguo pattern (e.g. 民國90年1月1日) embeds 民國 as a literal anchor so it
    is self-contextualizing — no external keyword needed (score = 0.9).

    Western pattern (e.g. 1990-01-01 / 1990/01/01 / 1990.01.01) is extremely
    common and would cause too many false positives without a hard context gate.
    A keyword within ±30 chars is required (score = 0.85 when matched).
    """

    SUPPORTED_ENTITY: ClassVar[str] = "TW_BIRTH_DATE"
    _MINGUO: ClassVar[re.Pattern[str]] = re.compile(
        r"民國\s?\d{2,3}\s?年\s?\d{1,2}\s?月\s?\d{1,2}\s?日",
        _FLAGS,
    )
    _WESTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"(?<!\d)\d{4}[-/.]\d{1,2}[-/.]\d{1,2}(?!\d)",
        _FLAGS,
    )
    CONTEXT_KEYWORDS: ClassVar[list[str]] = [
        "生日", "出生", "出生日期", "出生年月日", "出生日", "DOB", "birthday",
        "生日期", "出生年", "年齡",
    ]
    _WESTERN_WINDOW: ClassVar[int] = 30  # tighter window for Western dates

    def __init__(self) -> None:
        super().__init__(
            supported_entities=[self.SUPPORTED_ENTITY],
            supported_language="zh",
            name="TwBirthDateRecognizer",
        )

    def load(self) -> None:
        pass

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
    ) -> list[RecognizerResult]:
        if self.SUPPORTED_ENTITY not in entities:
            return []
        results: list[RecognizerResult] = []
        # Minguo: 民國 prefix is self-contextualizing
        for match in self._MINGUO.finditer(text):
            results.append(
                RecognizerResult(
                    entity_type=self.SUPPORTED_ENTITY,
                    start=match.start(),
                    end=match.end(),
                    score=0.9,
                )
            )
        # Western: requires context keyword within ±30 chars
        for match in self._WESTERN.finditer(text):
            if _has_context(text, match.start(), match.end(), self.CONTEXT_KEYWORDS):
                results.append(
                    RecognizerResult(
                        entity_type=self.SUPPORTED_ENTITY,
                        start=match.start(),
                        end=match.end(),
                        score=0.85,
                    )
                )
        return results


# ── International Mobile (+886) ────────────────────────────────────────────────

class TwIntlMobileRecognizer(PatternRecognizer):
    """Taiwan mobile in international dialling format: +886-9XX-XXX-XXX.

    Covers compact (+886912345678), dash-separated (+886-912-345-678), and
    space-separated (+886 912 345 678) variants.  The +886 prefix is a strong
    signal on its own (score = 0.9); context keywords further boost confidence.

    Uses the same entity type (TW_MOBILE) as TwMobileRecognizer so all mobile
    numbers collapse into a single placeholder series regardless of format.
    """

    SUPPORTED_ENTITY: ClassVar[str] = "TW_MOBILE"
    PATTERNS: ClassVar[list[Pattern]] = [
        Pattern(
            "TW_MOBILE_INTL",
            r"\+886[-\s]?9\d{2}[-\s]?\d{3}[-\s]?\d{3}",
            0.9,
        ),
    ]
    CONTEXT: ClassVar[list[str]] = [
        "手機", "電話", "mobile", "phone", "聯絡", "聯繫", "行動電話",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entity=self.SUPPORTED_ENTITY,
            patterns=self.PATTERNS,
            context=self.CONTEXT,
            supported_language="zh",
            global_regex_flags=_FLAGS,
        )


# ── Bank Account ───────────────────────────────────────────────────────────────

class TwBankAccountRecognizer(LocalRecognizer):
    """Taiwan bank account numbers (12–16 digits) with mandatory context filter.

    Raw 12–16 digit strings are extremely ambiguous (timestamps, order numbers,
    credit card PANs, etc.).  A context keyword is required within ±50 chars to
    avoid false positives.  Luhn-valid numbers are skipped because they are
    handled by TwCreditCardRecognizer.
    """

    SUPPORTED_ENTITY: ClassVar[str] = "TW_BANK_ACCOUNT"
    PATTERN: ClassVar[re.Pattern[str]] = re.compile(r"(?<!\d)\d{12,16}(?!\d)", re.ASCII)
    CONTEXT_KEYWORDS: ClassVar[list[str]] = [
        "帳號", "帳戶", "存摺", "銀行", "轉帳", "匯款", "戶號", "銀行帳戶",
        "銀行帳號", "帳", "存款", "金融帳號",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entities=[self.SUPPORTED_ENTITY],
            supported_language="zh",
            name="TwBankAccountRecognizer",
        )

    def load(self) -> None:
        pass

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
    ) -> list[RecognizerResult]:
        if self.SUPPORTED_ENTITY not in entities:
            return []
        results: list[RecognizerResult] = []
        for match in self.PATTERN.finditer(text):
            number = match.group()
            # Only exclude Luhn-valid numbers at credit card lengths (13-16 digits)
            if len(number) >= 13 and self._is_luhn_valid(number):
                continue
            if not _has_context(text, match.start(), match.end(), self.CONTEXT_KEYWORDS):
                continue
            results.append(
                RecognizerResult(
                    entity_type=self.SUPPORTED_ENTITY,
                    start=match.start(),
                    end=match.end(),
                    score=0.85,
                )
            )
        return results

    @staticmethod
    def _is_luhn_valid(number: str) -> bool:
        """Return True if *number* passes the Luhn checksum (likely a credit card)."""
        digits = [int(d) for d in number]
        checksum = 0
        for i, d in enumerate(reversed(digits)):
            if i % 2 == 1:
                d *= 2
                if d > 9:
                    d -= 9
            checksum += d
        return checksum % 10 == 0


# ── Structured Address (tiered priority-bitmap merge) ──────────────────────────
#
# Design adapted from funstory-ai/aifw's docs/zh_address_design.md: a Taiwan
# address is decomposed into ordered component tiers, from macro (county/city)
# down to micro (unit/room). Adjacent-tier tokens separated only by light
# punctuation merge into one span. A single isolated tier (e.g. just a city
# name) is not emitted — it isn't specific enough to count as an address on
# its own; at least two tiers must merge for a match.

class TwAddressRecognizer(LocalRecognizer):
    """Structured Taiwan address recognizer using a tiered merge algorithm.

    Tiers (macro=9 to micro=1): county/city, district, road(+section),
    lane/alley, house number, POI/complex, building block, floor, unit/room.
    Adjacent tiers separated by light punctuation (whitespace/comma, <=4 chars)
    merge into a single TW_ADDRESS span; a lone single-tier token is dropped.
    """

    SUPPORTED_ENTITY: ClassVar[str] = "TW_ADDRESS"

    # Suffix markers that terminate every tier. Excluding them from a lower-
    # priority tier's "name" prefix stops that tier's greedy match from
    # backtracking across an earlier tier's boundary (e.g. a road-name prefix
    # swallowing the preceding city+district text just to reach 路/街).
    _BOUNDARY: ClassVar[str] = "縣市鄉鎮區路街道號巷弄樓層室房棟幢座館段"
    _NAME: ClassVar[str] = rf"(?:(?![{_BOUNDARY}])[\u4e00-\u9fff0-9])"

    # Taiwan's 22 counties/cities are a small, fixed, enumerable set — matching
    # them by name (rather than a generic greedy character class) avoids
    # swallowing preceding prose (e.g. "地址在台北市" over-capturing "址在" as
    # part of the city name) since there's no ambiguity left to resolve.
    _CITY_COUNTY: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:台|臺)(?:北|中|南|東)市|新北市|桃園市|高雄市|基隆市|新竹市|嘉義市|"
        r"新竹縣|苗栗縣|彰化縣|南投縣|雲林縣|嘉義縣|屏東縣|宜蘭縣|花蓮縣|"
        r"(?:台|臺)東縣|澎湖縣|金門縣|連江縣"
    )

    # (tier, pattern) — higher tier number = more macro/coarse.
    _TIERS: ClassVar[list[tuple[int, re.Pattern[str]]]] = [
        (9, _CITY_COUNTY),
        # "市" deliberately excluded here — it would ambiguously re-match the
        # tier-9 city/county names themselves (both "台北市" and a county-
        # administered township-city like "斗六市" share the same "X市" shape).
        # Township-level 縣轄市 names are out of scope for this simplified
        # tier; only 鄉/鎮/區 are recognized at tier 8.
        (8, re.compile(rf"{_NAME}{{1,3}}(?:鄉|鎮|區)")),
        (7, re.compile(
            rf"{_NAME}{{1,6}}(?:路|街|道|大道)"
            r"(?:[一二三四五六七八九十]+段)?"
        )),
        (6, re.compile(r"\d+(?:巷|弄)")),
        (5, re.compile(r"\d+(?:之\d+)?號")),  # house number — privacy threshold
        (4, re.compile(rf"{_NAME}{{1,6}}(?:大樓|大廈|社區|中心|廣場|園區)")),
        (3, re.compile(r"[A-Za-z0-9]{0,2}(?:棟|幢|座|館)")),
        (2, re.compile(r"\d+(?:樓|層)|[Ff]\d+")),
        (1, re.compile(r"\d+(?:室|房)|第?[一二三四五六七八九十\d]+單元")),
    ]

    _MAX_GAP: ClassVar[int] = 4
    _LIGHT_SEP: ClassVar[re.Pattern[str]] = re.compile(r"^[\s,，、]*$")

    def __init__(self) -> None:
        super().__init__(
            supported_entities=[self.SUPPORTED_ENTITY],
            supported_language="zh",
            name="TwAddressRecognizer",
        )

    def load(self) -> None:
        pass

    def _tokens(self, text: str) -> list[tuple[int, int, int]]:
        """Return (start, end, tier) for every tier-token match, sorted by start."""
        tokens: list[tuple[int, int, int]] = []
        for tier, pattern in self._TIERS:
            for m in pattern.finditer(text):
                tokens.append((m.start(), m.end(), tier))
        tokens.sort(key=lambda t: (t[0], -t[1]))
        return tokens

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
    ) -> list[RecognizerResult]:
        if self.SUPPORTED_ENTITY not in entities:
            return []
        tokens = self._tokens(text)
        if not tokens:
            return []

        results: list[RecognizerResult] = []
        run_start, run_end, run_tier = tokens[0]
        run_tiers = {run_tier}

        def flush() -> None:
            if len(run_tiers) >= 2:
                results.append(
                    RecognizerResult(
                        entity_type=self.SUPPORTED_ENTITY,
                        start=run_start,
                        end=run_end,
                        score=0.85,
                    )
                )

        for start, end, tier in tokens[1:]:
            if start < run_end:
                continue  # nested/overlapping token inside current run, ignore
            gap = text[run_end:start]
            if tier < run_tier and len(gap) <= self._MAX_GAP and self._LIGHT_SEP.match(gap):
                run_end = end
                run_tier = tier
                run_tiers.add(tier)
            else:
                flush()
                run_start, run_end, run_tier = start, end, tier
                run_tiers = {tier}
        flush()
        return results


# ── Secrets: verification code, password, crypto seed, private key ─────────────

class TwVerificationCodeRecognizer(LocalRecognizer):
    """One-time verification codes (4-8 alphanumeric chars after a labelling keyword)."""

    SUPPORTED_ENTITY: ClassVar[str] = "TW_VERIFICATION_CODE"
    _PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:驗證碼|認證碼|動態密碼|一次性密碼|verification\s*code|otp|one[- ]?time\s*password)"
        r"\s*[:：]?\s*([A-Za-z0-9]{4,8})\b",
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        super().__init__(
            supported_entities=[self.SUPPORTED_ENTITY],
            supported_language="zh",
            name="TwVerificationCodeRecognizer",
        )

    def load(self) -> None:
        pass

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
    ) -> list[RecognizerResult]:
        if self.SUPPORTED_ENTITY not in entities:
            return []
        return [
            RecognizerResult(
                entity_type=self.SUPPORTED_ENTITY,
                start=m.start(1),
                end=m.end(1),
                score=0.8,
            )
            for m in self._PATTERN.finditer(text)
        ]


class TwPasswordRecognizer(LocalRecognizer):
    """Passwords following a 密碼/password label.

    The captured value is restricted to an ASCII password-shaped character
    class (letters/digits/common symbols), NOT a greedy \\S+ — Chinese text
    has no whitespace between the password and the next clause (e.g. a
    trailing full-width parenthesis), so a naive \\S+ capture would swallow
    the rest of the sentence. Stopping at the first CJK/full-width character
    keeps the span bounded to the password itself.
    """

    SUPPORTED_ENTITY: ClassVar[str] = "TW_PASSWORD"
    _PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:密碼|密码|password|pwd|pass)\s*(?:是|為|为)?\s*[:：]?\s*"
        r"([A-Za-z0-9!@#$%^&*_\-+=.]{4,32})",
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        super().__init__(
            supported_entities=[self.SUPPORTED_ENTITY],
            supported_language="zh",
            name="TwPasswordRecognizer",
        )

    def load(self) -> None:
        pass

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
    ) -> list[RecognizerResult]:
        if self.SUPPORTED_ENTITY not in entities:
            return []
        return [
            RecognizerResult(
                entity_type=self.SUPPORTED_ENTITY,
                start=m.start(1),
                end=m.end(1),
                score=0.75,
            )
            for m in self._PATTERN.finditer(text)
        ]


class TwCryptoSeedRecognizer(LocalRecognizer):
    """Crypto wallet seed phrases / mnemonics: 12-24 lowercase English words.

    Requires a labelling keyword (助記詞/seed phrase/mnemonic/...) within the
    shared ±50-char context window, since a bare run of English words alone is
    too ambiguous to flag as a secret.
    """

    SUPPORTED_ENTITY: ClassVar[str] = "TW_CRYPTO_SEED"
    _WORDS: ClassVar[re.Pattern[str]] = re.compile(
        r"(?:[a-z]{3,8}[ \t]+){11,23}[a-z]{3,8}", re.IGNORECASE
    )
    CONTEXT_KEYWORDS: ClassVar[list[str]] = [
        "助記詞", "助记词", "種子詞", "种子词", "seed phrase", "mnemonic", "recovery phrase",
    ]

    def __init__(self) -> None:
        super().__init__(
            supported_entities=[self.SUPPORTED_ENTITY],
            supported_language="zh",
            name="TwCryptoSeedRecognizer",
        )

    def load(self) -> None:
        pass

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
    ) -> list[RecognizerResult]:
        if self.SUPPORTED_ENTITY not in entities:
            return []
        results: list[RecognizerResult] = []
        for m in self._WORDS.finditer(text):
            if not _has_context(text, m.start(), m.end(), self.CONTEXT_KEYWORDS):
                continue
            results.append(
                RecognizerResult(
                    entity_type=self.SUPPORTED_ENTITY,
                    start=m.start(),
                    end=m.end(),
                    score=0.8,
                )
            )
        return results


class TwPrivateKeyRecognizer(LocalRecognizer):
    """PEM-format private key blocks. Self-contextualizing (BEGIN/END markers
    are unambiguous), so no separate keyword context filter is required.
    """

    SUPPORTED_ENTITY: ClassVar[str] = "TW_PRIVATE_KEY"
    _PATTERN: ClassVar[re.Pattern[str]] = re.compile(
        r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"
    )

    def __init__(self) -> None:
        super().__init__(
            supported_entities=[self.SUPPORTED_ENTITY],
            supported_language="zh",
            name="TwPrivateKeyRecognizer",
        )

    def load(self) -> None:
        pass

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
    ) -> list[RecognizerResult]:
        if self.SUPPORTED_ENTITY not in entities:
            return []
        return [
            RecognizerResult(
                entity_type=self.SUPPORTED_ENTITY,
                start=m.start(),
                end=m.end(),
                score=0.95,
            )
            for m in self._PATTERN.finditer(text)
        ]
