"""MCP Server exposing pii-guard tools via stdio transport.

Install into Claude Code:
    claude mcp add pii-guard -- uv run --project /path/to/pii-guard python -m pii_guard serve

Tools exposed:
    anonymize_text   – detect and replace PII, returns anonymized text + session_id
    restore_text     – restore using in-memory session
    save_mapping     – persist session mapping to a JSON file
    restore_from_file – restore using a saved mapping file
"""

from __future__ import annotations

import os
import uuid

from mcp.server.fastmcp import FastMCP

# Lazy-init: model loads on first tool call to avoid slow startup
_engine = None
_sessions: dict[str, dict[str, str]] = {}  # session_id → {placeholder: original}


def _get_engine():
    global _engine
    if _engine is None:
        from pii_guard.pipeline.engine import PiiGuardEngine

        model = os.environ.get("PII_GUARD_MODEL", "ckiplab/bert-base-chinese-ner")
        llm_fallback = os.environ.get("PII_GUARD_LLM_FALLBACK", "").lower() in (
            "1", "true", "yes",
        )
        _engine = PiiGuardEngine(ckip_model=model, llm_fallback=llm_fallback)
    return _engine


app = FastMCP(
    "pii-guard",
    instructions=(
        "繁體中文 PII 去識別化工具。\n"
        "流程：anonymize_text → 取得 session_id → restore_text 還原。\n"
        "或：anonymize_text → save_mapping 存檔 → restore_from_file 跨 session 還原。"
    ),
)


@app.tool()
def anonymize_text(text: str) -> dict:
    """
    去識別化文本。自動偵測台灣常見 PII（人名、身分證、手機、統編、Email 等）
    並替換為編號佔位符，例如 <PERSON_1>、<TW_NATIONAL_ID_1>。

    Returns:
        anonymized_text: 去識別化後的文本
        session_id: 用於 restore_text 的 session ID（本次 server 生命週期內有效）
        entity_count: 偵測到的 PII 實體數量
    """
    engine = _get_engine()
    anonymized, mapping = engine.anonymize(text)
    session_id = str(uuid.uuid4())
    _sessions[session_id] = mapping
    return {
        "anonymized_text": anonymized,
        "session_id": session_id,
        "entity_count": len(mapping),
    }


@app.tool()
def restore_text(anonymized_text: str, session_id: str) -> str:
    """
    還原去識別化文本。需提供 anonymize_text 回傳的 session_id。

    注意：session 僅在 MCP server 生命週期內有效（server 重啟後失效）。
    如需跨 session 還原，請先用 save_mapping 存檔，再用 restore_from_file。
    """
    mapping = _sessions.get(session_id)
    if mapping is None:
        raise ValueError(
            f"Session '{session_id}' not found. "
            "Did you call anonymize_text first, or has the server been restarted?"
        )
    from pii_guard.pipeline.engine import PiiGuardEngine

    return PiiGuardEngine.deanonymize(anonymized_text, mapping)


@app.tool()
def save_mapping(session_id: str, path: str) -> str:
    """
    將 session 的 mapping 序列化到指定 JSON 檔案路徑。
    可用於跨 session 或跨 server 重啟的還原。

    Returns:
        確認訊息，包含儲存路徑與 PII 數量
    """
    from pathlib import Path

    mapping = _sessions.get(session_id)
    if mapping is None:
        raise ValueError(f"Session '{session_id}' not found.")
    from pii_guard.pipeline.engine import PiiGuardEngine

    save_path = Path(path)
    PiiGuardEngine.save_mapping(mapping, save_path)
    return f"Mapping ({len(mapping)} entities) saved to {save_path.resolve()}"


@app.tool()
def restore_from_file(anonymized_text: str, mapping_path: str) -> str:
    """
    從 mapping JSON 檔案還原去識別化文本。適用於跨 session 的還原場景。

    Parameters:
        anonymized_text: 含佔位符的去識別化文本
        mapping_path: save_mapping 存檔的 JSON 路徑
    """
    from pathlib import Path

    from pii_guard.pipeline.engine import PiiGuardEngine

    mapping = PiiGuardEngine.load_mapping(Path(mapping_path))
    return PiiGuardEngine.deanonymize(anonymized_text, mapping)
