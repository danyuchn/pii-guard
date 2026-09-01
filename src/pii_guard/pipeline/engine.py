"""Core PII anonymization engine using Presidio + CKIP BERT."""

from __future__ import annotations

import json
import logging
import os
import stat
import warnings
from collections.abc import Iterable
from pathlib import Path
from typing import NoReturn, cast

from presidio_analyzer import AnalyzerEngine, RecognizerResult
from presidio_anonymizer import AnonymizerEngine
from presidio_anonymizer.entities import ConflictResolutionStrategy, OperatorConfig

from pii_guard._compat import is_reparse_point
from pii_guard.recognizers.tw_recognizers import TW_ENTITY_TYPES, get_all_tw_recognizers

logger = logging.getLogger(__name__)

# All entity types the engine handles.
# PERSON/ORG/LOCATION come from CKIP BERT NER; the rest from TW_ENTITY_TYPES.
SUPPORTED_ENTITIES: list[str] = [
    "PERSON",
    "ORG",
    "LOCATION",
    *TW_ENTITY_TYPES,
]

# CKIP NER label → Presidio entity type mapping
_CKIP_LABEL_MAP: dict[str, str] = {
    "PERSON": "PERSON",
    "PER": "PERSON",
    "ORG": "ORG",
    "LOC": "LOCATION",
    "GPE": "LOCATION",
    "FAC": "LOCATION",
}

MAX_ORG_ALLOWLIST_ENTRIES = 1_000
MAX_ORG_ALLOWLIST_CHARS = 512
MAX_ORG_ALLOWLIST_FILE_BYTES = 1_024_000
_ORG_ALLOWLIST_ERROR_CODE = "INVALID_ALLOW_ORG"
_ORG_ALLOWLIST_ERROR_MESSAGE = "Organization allowlist is invalid."


class OrgAllowlistError(ValueError):
    """A fixed, caller-safe organization allowlist validation error."""

    code = _ORG_ALLOWLIST_ERROR_CODE
    message = _ORG_ALLOWLIST_ERROR_MESSAGE

    def __init__(self) -> None:
        super().__init__(self.message)

    def __str__(self) -> str:
        return self.message


def _invalid_org_allowlist() -> NoReturn:
    raise OrgAllowlistError() from None


def validate_org_allowlist(values: Iterable[str] | None) -> tuple[str, ...]:
    """Validate one invocation's exact organization values."""

    if values is None:
        return ()
    if isinstance(values, str):
        values = (values,)

    validated: list[str] = []
    try:
        for value in values:
            if len(validated) >= MAX_ORG_ALLOWLIST_ENTRIES:
                _invalid_org_allowlist()
            if not isinstance(value, str):
                _invalid_org_allowlist()
            if not value.strip() or any(character in value for character in "\r\n\u2028\u2029"):
                _invalid_org_allowlist()
            if len(value) > MAX_ORG_ALLOWLIST_CHARS:
                _invalid_org_allowlist()
            validated.append(value)
    except OrgAllowlistError:
        raise
    except Exception:
        _invalid_org_allowlist()
    return tuple(validated)


def load_org_allowlist_file(path: Path) -> tuple[str, ...]:
    """Read and validate one newline-delimited organization allowlist."""

    # O_NOFOLLOW does not exist on Windows. Treating that as fatal made this
    # rule file unusable there, so reject links with the platform-neutral
    # reparse-point check and confirm the opened file is the one we checked.
    no_follow = getattr(os, "O_NOFOLLOW", 0)
    descriptor = -1
    try:
        path_status = path.lstat()
        if is_reparse_point(path_status) or not stat.S_ISREG(path_status.st_mode):
            _invalid_org_allowlist()
        descriptor = os.open(path, os.O_RDONLY | no_follow | getattr(os, "O_BINARY", 0))
        file_status = os.fstat(descriptor)
        if not stat.S_ISREG(file_status.st_mode):
            _invalid_org_allowlist()
        if file_status.st_dev != path_status.st_dev or file_status.st_ino != path_status.st_ino:
            _invalid_org_allowlist()
        if file_status.st_size > MAX_ORG_ALLOWLIST_FILE_BYTES:
            _invalid_org_allowlist()
        data = os.read(descriptor, MAX_ORG_ALLOWLIST_FILE_BYTES + 1)
        if len(data) > MAX_ORG_ALLOWLIST_FILE_BYTES:
            _invalid_org_allowlist()
        contents = data.decode("utf-8")
    except OrgAllowlistError:
        raise
    except (OSError, UnicodeError, TypeError, ValueError, OverflowError):
        _invalid_org_allowlist()
    finally:
        if descriptor >= 0:
            os.close(descriptor)

    values: list[str] = []
    for line in contents.split("\n"):
        if line.endswith("\r"):
            line = line[:-1]
        value = line.strip(" \t\v\f\r")
        if not value or value.startswith("#"):
            continue
        values.append(value)
    return validate_org_allowlist(values)


def _build_analyzer(
    ckip_model: str,
    *,
    english_ner: bool = True,
) -> AnalyzerEngine:
    """
    Build Presidio AnalyzerEngine backed by CKIP BERT (for PERSON/ORG/LOCATION)
    plus Taiwan-specific PatternRecognizers.

    Falls back gracefully if transformers/spaCy models are unavailable.
    Optionally registers an English NER recognizer.
    """
    nlp_engine = _create_nlp_engine(ckip_model)
    analyzer = AnalyzerEngine(
        nlp_engine=nlp_engine,
        supported_languages=["zh"],
    )

    # Remove Presidio built-in recognizers that conflict with our TW variants.
    # The built-in EmailRecognizer uses \b boundaries which produce wrong spans
    # in Chinese text (e.g. "信箱user@x.com" matched as full string instead of
    # just "user@x.com"), and its score=1.0 overrides our TwEmailRecognizer.
    _remove = {"EmailRecognizer", "CreditCardRecognizer"}
    filtered_recognizers = []
    for recognizer in analyzer.registry.recognizers:
        name = cast(str | None, getattr(recognizer, "name", None))
        if name not in _remove:
            filtered_recognizers.append(recognizer)
    analyzer.registry.recognizers = filtered_recognizers

    for recognizer in get_all_tw_recognizers():
        analyzer.registry.add_recognizer(recognizer)

    if english_ner:
        try:
            from pii_guard.recognizers.english_ner_recognizer import EnglishNerRecognizer

            analyzer.registry.add_recognizer(EnglishNerRecognizer())
            logger.info("EnglishNerRecognizer enabled (en_core_web_sm)")
        except Exception as exc:
            logger.warning("EnglishNerRecognizer unavailable (%s)", exc)

    return analyzer


def _create_nlp_engine(ckip_model: str):
    """Create NLP engine: TransformersNlpEngine (CKIP) → SpacyNlpEngine fallback."""
    try:
        from presidio_analyzer.nlp_engine import TransformersNlpEngine

        models = [
            {
                "lang_code": "zh",
                "model_name": {
                    "spacy": "zh_core_web_sm",
                    "transformers": ckip_model,
                },
            }
        ]

        # Presidio ≥ 2.2.34 exposes NerModelConfiguration for label mapping
        try:
            from presidio_analyzer.nlp_engine.transformers_nlp_engine import (
                NerModelConfiguration,
            )

            ner_config = NerModelConfiguration(
                model_to_presidio_entity_mapping=_CKIP_LABEL_MAP,
                aggregation_strategy="simple",
                default_score=0.85,
                low_score_entity_names=["MISC", "NORP", "WORK_OF_ART", "EVENT"],
            )
            engine = TransformersNlpEngine(models=models, ner_model_configuration=ner_config)
            logger.info("Using CKIP TransformersNlpEngine with NerModelConfiguration")
        except (ImportError, TypeError):
            engine = TransformersNlpEngine(models=models)
            logger.info("Using CKIP TransformersNlpEngine (no NerModelConfiguration)")

        return engine

    except (ImportError, OSError, ValueError) as exc:
        # ValueError covers "Can't find factory for 'hf_token_pipe'" when
        # spacy-transformers is not installed.
        logger.warning(
            "TransformersNlpEngine unavailable (%s). "
            "PERSON/ORG/LOCATION detection via CKIP will be disabled. "
            "Taiwan regex recognizers still active.",
            exc,
        )
        from presidio_analyzer.nlp_engine import SpacyNlpEngine

        return SpacyNlpEngine(models=[{"lang_code": "zh", "model_name": "zh_core_web_sm"}])


def _merge_adjacent_spans(results: list[RecognizerResult]) -> list[RecognizerResult]:
    """Merge adjacent or overlapping spans of the same entity type.

    CKIP sometimes splits a single entity into multiple tokens
    (e.g. "台北市信義區" → [4:9] + [9:10]).  This merges them back.
    """
    if not results:
        return results
    sorted_results = sorted(results, key=lambda r: (r.entity_type, r.start))
    merged: list[RecognizerResult] = []
    for r in sorted_results:
        if (
            merged
            and merged[-1].entity_type == r.entity_type
            and r.start <= merged[-1].end  # adjacent or overlapping
        ):
            prev = merged[-1]
            merged[-1] = RecognizerResult(
                entity_type=prev.entity_type,
                start=prev.start,
                end=max(prev.end, r.end),
                score=max(prev.score, r.score),
            )
        else:
            merged.append(r)
    return merged


def _filter_person_over_date(results: list[RecognizerResult]) -> list[RecognizerResult]:
    """Drop PERSON spans that fully overlap a TW_BIRTH_DATE span.

    CKIP sometimes tags Minguo dates (民國85年12月3日) as PERSON.
    """
    date_spans = {(r.start, r.end) for r in results if r.entity_type == "TW_BIRTH_DATE"}
    if not date_spans:
        return results
    return [
        r
        for r in results
        if not (
            r.entity_type == "PERSON"
            and any(ds <= r.start and r.end <= de for ds, de in date_spans)
        )
    ]


class PiiGuardEngine:
    """
    Orchestrates PII detection and reversible anonymization for Traditional Chinese text.

    Usage::

        engine = PiiGuardEngine()
        anonymized, mapping = engine.anonymize("張大明的身分證A123456789")
        # anonymized → "<PERSON_1>的身分證<TW_NATIONAL_ID_1>"
        # mapping    → {"<PERSON_1>": "張大明", "<TW_NATIONAL_ID_1>": "A123456789"}

        original = engine.deanonymize(anonymized, mapping)
        assert original == "張大明的身分證A123456789"
    """

    def __init__(
        self,
        ckip_model: str = "ckiplab/bert-base-chinese-ner",
        score_threshold: float = 0.5,
        english_ner: bool = True,
    ) -> None:
        self.score_threshold = score_threshold
        self._analyzer = _build_analyzer(
            ckip_model,
            english_ner=english_ner,
        )
        self._anonymizer = AnonymizerEngine()

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _raw_detect(self, text: str) -> list[RecognizerResult]:
        """Run analyzer + post-processing (merge spans, resolve conflicts)."""
        # Some NLP backends emit warning text containing the full input when
        # token offsets cannot be aligned.  Never let that dependency output
        # cross a caller's stderr/log boundary.
        with warnings.catch_warnings():
            warnings.simplefilter("ignore", UserWarning)
            results = self._analyzer.analyze(
                text=text,
                language="zh",
                entities=SUPPORTED_ENTITIES,
                score_threshold=self.score_threshold,
            )
        results = _merge_adjacent_spans(results)
        results = _filter_person_over_date(results)
        return results

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @staticmethod
    def _filter_allowed_orgs(
        text: str,
        results: list[RecognizerResult],
        allow_orgs: Iterable[str],
    ) -> list[RecognizerResult]:
        """Drop only exact ORG spans named by this invocation's allowlist."""

        allowed = frozenset(allow_orgs)
        if not allowed:
            return results
        return [
            result
            for result in results
            if not (
                result.entity_type == "ORG"
                and 0 <= result.start <= result.end <= len(text)
                and text[result.start : result.end] in allowed
            )
        ]

    def anonymize(
        self,
        text: str,
        allow_orgs: Iterable[str] | None = None,
    ) -> tuple[str, dict[str, str]]:
        """
        Anonymize PII in *text*.

        Returns
        -------
        anonymized_text : str
            Text with PII replaced by numbered placeholders, e.g. ``<PERSON_1>``.
        mapping : dict[str, str]
            ``{placeholder: original_value}`` — needed for :meth:`deanonymize`.
        allow_orgs : Iterable[str] | None
            Exact organization spans to leave visible for this invocation only.
        """
        # Shared mutable state for the operator lambdas (closure)
        entity_mapping: dict[str, str] = {}  # original_value → placeholder
        counters: dict[str, int] = {}  # entity_type → running count

        requested_allowlist = validate_org_allowlist(allow_orgs)

        def make_lambda(entity_type: str):
            def replace_fn(original: str) -> str:
                # Presidio's Custom.validate() always calls lambda("PII") to type-check
                # the return value. Skip this sentinel to avoid polluting entity_mapping.
                if original == "PII":
                    return "<VALIDATION>"
                if original not in entity_mapping:
                    counters[entity_type] = counters.get(entity_type, 0) + 1
                    placeholder = f"<{entity_type}_{counters[entity_type]}>"
                    entity_mapping[original] = placeholder
                return entity_mapping[original]

            return replace_fn

        operators = {
            et: OperatorConfig("custom", {"lambda": make_lambda(et)}) for et in SUPPORTED_ENTITIES
        }

        results = self._filter_allowed_orgs(
            text,
            self._raw_detect(text),
            requested_allowlist,
        )

        anonymized_result = self._anonymizer.anonymize(
            text=text,
            analyzer_results=results,  # type: ignore[arg-type]
            operators=operators,
            # Default MERGE_SIMILAR_OR_CONTAINED only merges same-type spans and
            # drops fully-contained ones; it leaves partially overlapping spans of
            # DIFFERENT entity types untouched, which double-writes placeholders
            # into the anonymized text and corrupts restore (e.g. "IL" duplicated
            # into "ILIL" when a LOCATION span and an ORG span partially overlap).
            # REMOVE_INTERSECTIONS additionally clips such partial overlaps by score.
            conflict_resolution=ConflictResolutionStrategy.REMOVE_INTERSECTIONS,
        )

        # Reverse: placeholder → original (for deanonymize)
        reverse_mapping: dict[str, str] = {v: k for k, v in entity_mapping.items()}
        return anonymized_result.text, reverse_mapping

    def detect(self, text: str) -> list[RecognizerResult]:
        """Return raw RecognizerResult list without anonymizing."""
        return self._raw_detect(text)

    @staticmethod
    def deanonymize(text: str, mapping: dict[str, str]) -> str:
        """
        Restore anonymized *text* using *mapping*.

        Parameters
        ----------
        text : str
            Text containing placeholders like ``<PERSON_1>``.
        mapping : dict[str, str]
            ``{placeholder: original_value}`` as returned by :meth:`anonymize`.
        """
        # Sort longest first to avoid <PERSON_1> matching inside <PERSON_10>
        for placeholder in sorted(mapping, key=len, reverse=True):
            text = text.replace(placeholder, mapping[placeholder])
        return text

    # ------------------------------------------------------------------
    # Mapping persistence
    # ------------------------------------------------------------------

    @staticmethod
    def save_mapping(mapping: dict[str, str], path: Path) -> None:
        """Serialise *mapping* to a JSON file at *path*."""
        path.write_text(json.dumps(mapping, ensure_ascii=False, indent=2), encoding="utf-8")

    @staticmethod
    def load_mapping(path: Path) -> dict[str, str]:
        """Load a mapping JSON file previously saved by :meth:`save_mapping`."""
        return json.loads(path.read_text(encoding="utf-8"))
