"""Ollama LLM fallback recognizer for PII detection."""

from __future__ import annotations

import json
import logging
import re
from typing import ClassVar

import httpx
from presidio_analyzer import LocalRecognizer, RecognizerResult
from presidio_analyzer.nlp_engine import NlpArtifacts

logger = logging.getLogger(__name__)

_PROMPT_TEMPLATE = """\
你是台灣個人資料（PII）偵測系統。分析以下文本，找出所有個人識別資訊並回傳 JSON。

可偵測的 PII 類型：
- PERSON（人名）
- ORG（組織名稱）
- LOCATION（地名、地址）
- TW_NATIONAL_ID（身分證字號，如 A123456789）
- TW_ARC（外籍居留證號）
- TW_PASSPORT（護照號碼）
- TW_MOBILE（手機號碼，如 0912345678）
- TW_LANDLINE（市話號碼）
- TW_BUSINESS_ID（統一編號，8 位數）
- EMAIL_ADDRESS（電子郵件）
- CREDIT_CARD（信用卡號）
- TW_LICENSE_PLATE（車牌號碼）
- TW_BIRTH_DATE（出生日期）
- TW_BANK_ACCOUNT（銀行帳號）

回傳格式（嚴格 JSON，不要加任何說明文字）：
{{"entities": [{{"type": "PERSON", "value": "張大明", "start": 0, "end": 3}}]}}

若無偵測到任何 PII，回傳：
{{"entities": []}}

文本：
{text}"""

VALID_ENTITY_TYPES: set[str] = {
    "PERSON", "ORG", "LOCATION",
    "TW_NATIONAL_ID", "TW_ARC", "TW_PASSPORT",
    "TW_MOBILE", "TW_LANDLINE", "TW_BUSINESS_ID",
    "EMAIL_ADDRESS", "CREDIT_CARD",
    "TW_LICENSE_PLATE", "TW_BIRTH_DATE", "TW_BANK_ACCOUNT",
}


class OllamaRecognizer(LocalRecognizer):
    """
    LLM-based PII recognizer using Ollama (Qwen2.5) as a fallback layer.

    Runs after deterministic recognizers (regex, CKIP BERT). Confidence is set
    lower (0.75) so Presidio's dedup favours deterministic results on overlap.
    Gracefully degrades to no-op when Ollama is unavailable.
    """

    DEFAULT_MODEL: ClassVar[str] = "qwen2.5:1.5b"
    DEFAULT_BASE_URL: ClassVar[str] = "http://localhost:11434"
    DEFAULT_CONFIDENCE: ClassVar[float] = 0.75
    DEFAULT_TIMEOUT: ClassVar[float] = 30.0

    def __init__(
        self,
        model: str = DEFAULT_MODEL,
        base_url: str = DEFAULT_BASE_URL,
        confidence: float = DEFAULT_CONFIDENCE,
        timeout: float = DEFAULT_TIMEOUT,
    ) -> None:
        super().__init__(
            supported_entities=sorted(VALID_ENTITY_TYPES),
            supported_language="zh",
            name="OllamaRecognizer",
        )
        self._model = model
        self._base_url = base_url.rstrip("/")
        self._confidence = confidence
        self._timeout = timeout
        self._available: bool | None = None  # lazy health check

    def load(self) -> None:
        pass

    # ------------------------------------------------------------------
    # Public API (Presidio interface)
    # ------------------------------------------------------------------

    def analyze(
        self,
        text: str,
        entities: list[str],
        nlp_artifacts: NlpArtifacts | None = None,
    ) -> list[RecognizerResult]:
        if not self._check_available():
            return []

        try:
            raw = self._call_ollama(text)
            parsed = self._parse_response(raw)
            return self._to_recognizer_results(parsed, text, entities)
        except Exception:
            logger.warning("OllamaRecognizer failed", exc_info=True)
            return []

    # ------------------------------------------------------------------
    # Internals
    # ------------------------------------------------------------------

    def _check_available(self) -> bool:
        """Check Ollama is running and the model is pulled. Result is cached."""
        if self._available is not None:
            return self._available

        try:
            resp = httpx.get(
                f"{self._base_url}/api/tags",
                timeout=5.0,
            )
            resp.raise_for_status()
            models = {m["name"] for m in resp.json().get("models", [])}
            # Ollama model names may or may not include :latest
            model_name = self._model
            self._available = (
                model_name in models
                or f"{model_name}:latest" in models
                or any(m.startswith(model_name.split(":")[0]) for m in models)
            )
            if not self._available:
                logger.warning(
                    "Ollama model '%s' not found. Available: %s",
                    self._model,
                    sorted(models),
                )
        except Exception:
            logger.warning("Ollama not reachable at %s", self._base_url)
            self._available = False

        return self._available

    def _call_ollama(self, text: str) -> str:
        """Call Ollama /api/generate and return raw response text."""
        resp = httpx.post(
            f"{self._base_url}/api/generate",
            json={
                "model": self._model,
                "prompt": _PROMPT_TEMPLATE.format(text=text),
                "stream": False,
                "format": "json",
                "options": {
                    "temperature": 0,
                    "num_predict": 1024,
                },
            },
            timeout=self._timeout,
        )
        resp.raise_for_status()
        return resp.json().get("response", "")

    def _parse_response(self, raw: str) -> list[dict]:
        """Parse LLM JSON response into a list of entity dicts."""
        # Strip markdown fencing if present
        cleaned = re.sub(r"^```(?:json)?\s*|\s*```$", "", raw.strip())
        data = json.loads(cleaned)
        entities = data.get("entities", [])
        if not isinstance(entities, list):
            return []
        return entities

    def _to_recognizer_results(
        self,
        entities: list[dict],
        text: str,
        requested_entities: list[str],
    ) -> list[RecognizerResult]:
        """Validate and convert parsed entities to RecognizerResult list."""
        results: list[RecognizerResult] = []
        for ent in entities:
            entity_type = ent.get("type", "")
            value = ent.get("value", "")
            start = ent.get("start")
            end = ent.get("end")

            # Filter: must be a known and requested entity type
            if entity_type not in VALID_ENTITY_TYPES:
                continue
            if entity_type not in requested_entities:
                continue
            if not value:
                continue

            # Validate or fix offsets
            resolved_start, resolved_end = self._resolve_offsets(text, value, start, end)
            if resolved_start is None or resolved_end is None:
                continue

            results.append(
                RecognizerResult(
                    entity_type=entity_type,
                    start=resolved_start,
                    end=resolved_end,
                    score=self._confidence,
                )
            )
        return results

    @staticmethod
    def _resolve_offsets(
        text: str,
        value: str,
        start: int | None,
        end: int | None,
    ) -> tuple[int | None, int | None]:
        """
        Verify LLM-provided offsets; fall back to text.find() if wrong.

        Returns (start, end) or (None, None) if value not found in text.
        """
        # Check if LLM offsets are valid
        if (
            isinstance(start, int)
            and isinstance(end, int)
            and 0 <= start < end <= len(text)
            and text[start:end] == value
        ):
            return start, end

        # Fallback: find value in text
        idx = text.find(value)
        if idx >= 0:
            return idx, idx + len(value)

        return None, None
