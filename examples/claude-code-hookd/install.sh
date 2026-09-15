#!/usr/bin/env bash
# Install the pii-guard hook client and print the settings block to merge.
#
# This script never edits your Claude Code settings for you.  It copies the
# client to a stable location and prints the exact JSON with the real path
# filled in, so you can see what you are adding before you add it.
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
target_dir="${PII_GUARD_HOOK_DIR:-$HOME/.claude/hooks/pii-guard}"
target="$target_dir/pii_guard_hook_client.py"

mkdir -p "$target_dir"
chmod 700 "$target_dir"
install -m 700 "$here/pii_guard_hook_client.py" "$target"

echo "Installed: $target"
echo

if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)'; then
  echo "WARNING: python3 is older than 3.8; the hook client may not run." >&2
fi

echo "Merge this into ~/.claude/settings.json (or your project .claude/settings.json):"
echo
python3 - "$here/settings.json" "$target" <<'PY'
import json
import sys

with open(sys.argv[1], encoding="utf-8") as handle:
    text = handle.read()
# json.dumps escapes the path exactly the way the settings file needs it.
block = json.loads(text.replace("__HOOKD_CLIENT__", json.dumps(sys.argv[2])[1:-1]))
print(json.dumps(block, indent=2, ensure_ascii=False))
PY

echo
echo "Then start the service:"
echo "  uv run pii-guard-hookd serve            # regex engine, fast start"
echo "  uv run pii-guard-hookd serve --engine full   # adds Chinese name detection"
echo "  uv run pii-guard-hookd status"
