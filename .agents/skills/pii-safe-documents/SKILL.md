---
name: pii-safe-documents
description: "Processes sensitive local documents through PII Guard and a local Ollama model into a reversible redacted copy without allowing the non-open-source main agent to read the original, restoration map, or restored contents. Use whenever the user asks to de-identify or redact a private file, create a reversible sanitized document, prepare sensitive material for AI, or edit a document while keeping raw personal data local."
---

# PII Safe Documents

This skill creates a reversible, locally redacted working copy with a strict main-agent workflow boundary:

- The **main agent is untrusted for raw data**. It receives paths and safe receipts only.
- The bundled open-source local wrapper may read the original solely to run PII Guard and local Ollama.
- No hook is required. Normal wrapper output suppresses raw content.

This is strong protection against accidental model exposure, not an OS security boundary against a malicious process running as the same macOS user. A Skill cannot revoke its own filesystem tools. Hostile-agent isolation requires a separately permissioned local broker or OS account. Never describe this Skill alone as mathematically or technically impossible to bypass.

## Non-negotiable isolation rules

When this skill is active, the main agent MUST NOT:

1. Read, preview, search, summarize, diff, upload, attach, or otherwise inspect the original file.
2. Use `cat`, `sed`, `head`, `tail`, `grep`, `rg`, `strings`, Python, a document reader, a browser, or any other tool on the original file.
3. Read or reveal `mapping.private.json`, private worker files, raw logs, or the restored output.
4. Pass the original path to a subagent, cloud model, MCP server, website, or third-party API.
5. Run PII Guard directly. Its libraries may echo source text in warnings; only the bundled wrapper may invoke it.
6. Debug a failure by opening the original, mapping, worker output, or restored document.
7. Run `git diff`, content scans, or indexing over a directory that contains the original or restored output.

These rules still apply if the user asks the main agent to “check quickly.” If raw inspection is genuinely required, stop this workflow and obtain explicit permission for a different trust model.

## Supported inputs

Use this version for UTF-8 plain-text files up to 64 KiB only: `.txt`, `.md`, `.csv`, `.tsv`, `.log`, and `.dat`.

Do not rename a binary document to bypass this restriction. For `.docx`, `.xlsx`, `.pdf`, images, or audio, report that this version does not yet provide a verified isolation-preserving parser.

This is a **PII** redactor, not a general confidentiality classifier. Amounts, health details, schedules, contract terms, business strategy, and other sensitive facts may remain visible when they do not identify a person. Do not use this skill alone to claim that an entire document is safe for external disclosure.

## Workflow

### 1. Path-only preflight

The user may provide the original path. You may check path metadata such as existence, suffix, and file size, but never its contents. Do not autocomplete or glob inside a sensitive directory.

Choose allowed terms only when the user explicitly wants them preserved, such as a company or product name. An allowed term is visible to the main agent because the user supplied it; do not discover allowed terms from the original.

### 2. Create the redacted working copy

Run:

```bash
python3 <skill-dir>/scripts/pii_safe_workflow.py redact \
  --input "/absolute/path/to/private-file.txt" \
  --allow "company name the user explicitly supplied"
```

Repeat `--allow` as needed. The wrapper runs deterministic PII Guard detection plus a chunked, repeated local Ollama audit, captures all raw output, creates a private job directory, and prints only a safe JSON receipt. The verified default model is `qwen3.6:35b-a3b`; override it only after a representative local accuracy and speed test.

If the receipt says both `redaction_checks_passed: true` and `agent_may_read_redacted: true`, the main agent may read **only** `redacted_path`. The receipt also provides safe replacement counts, audit-pass count, and the local model name. Keep `job_id` for restoration. Never infer or probe the mapping path.

If the command fails, report its safe error code and stop. In particular, `NO_PII_CONFIDENCE` means the detector found no reversible replacements and therefore withheld the copy instead of calling an unchanged file safe. `ADVERSARIAL_INPUT_REVIEW_REQUIRED` means instruction-like document text could interfere with the local model, so the wrapper refused automated release. Do not inspect hidden files or rerun lower-level commands.

### 3. Work only on the redacted copy

Read and edit only the redacted working copy. Preserve placeholders exactly, including brackets, capitalization, and job namespace. Never normalize, translate, renumber, or combine them.

Save the edited redacted document as another UTF-8 text file. Prefer the same private job directory or a user-approved destination. Before restoration, verify mechanically that every placeholder from the redacted working copy is still present; do not open the mapping to do this.

In Markdown or Obsidian files, a placeholder inserted into a person-bearing link slug can temporarily make that link nonfunctional. Preserve the placeholder and surrounding link syntax exactly; restoration recreates the original link.

### 4. Restore without reading the result

Run:

```bash
python3 <skill-dir>/scripts/pii_safe_workflow.py restore \
  --job-id "<job_id from receipt>" \
  --input "/absolute/path/to/edited-redacted-file.txt" \
  --output "/absolute/path/chosen/by/user/restored-file.txt"
```

The wrapper prints a safe receipt. After success, tell the user the output path, but **do not read, preview, diff, hash through a content-printing tool, or summarize the restored file**. A digest and `roundtrip_equal` boolean shown by the wrapper are safe to relay. `roundtrip_equal: true` is expected only when the redacted working copy was not intentionally edited.

### 5. Retain or purge the private map

The mapping is required for later restoration and is stored with restrictive permissions. Keep it by default. Purging is destructive, so do it only after the user explicitly confirms that no further restoration is needed:

```bash
python3 <skill-dir>/scripts/pii_safe_workflow.py purge --job-id "<job_id>"
```

## Safe status language

You may report:

- job ID;
- readable redacted path;
- restored output path;
- whether the local audit passed;
- the redacted-file digest and permission checks emitted by the wrapper.

Never report original values, mapping entries, raw model output, raw warning text, or excerpts from the original/restored document.

## Security notes

- The wrapper refuses network Ollama endpoints; only loopback addresses are accepted.
- Job directories use mode `0700`; sensitive files use mode `0600`.
- Existing placeholder-like text is protected before redaction to prevent restoration collisions.
- Allowed terms are protected before detection rather than restored afterward.
- The local audit uses bounded overlapping chunks, a system/user role boundary, schema-constrained JSON, and repeated residual passes to catch aliases and contextual identifiers missed by rule-based detection.
- Local-model guesses are replaceable only when they match exactly or normalize to one unique source span in both the original and current redacted document; ambiguous or hallucinated values fail closed and never enter the restoration map.
- Inputs are copied through a single-open, non-symlink private snapshot before a worker reads them, preventing path swaps during processing.
- The local model connection bypasses system proxies and verifies that port 11434 belongs to this user's Ollama process.
- No automated detector is perfect. `agent_may_read_redacted: true` means the configured local checks passed, not that zero privacy risk is mathematically guaranteed.
- Document text can try to mislead an LLM. The local audit is a supplemental detector, not a proof against adversarial prompt injection.
