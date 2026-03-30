#!/bin/bash
# PreToolUse[Read]: Anonymize PII in protected files before Claude reads them
# Config: ~/.config/pii-guard/hook-config.json

INPUT=$(cat)
FILE_PATH=$(echo "$INPUT" | jq -r '.tool_input.file_path // ""')

# Quick exit if no file path or file doesn't exist
[ -z "$FILE_PATH" ] && exit 0
[ ! -f "$FILE_PATH" ] && exit 0

# Load config
CONFIG_FILE="$HOME/.config/pii-guard/hook-config.json"
if [ -f "$CONFIG_FILE" ]; then
  ENABLED=$(jq -r '.enabled // true' "$CONFIG_FILE")
  [ "$ENABLED" = "false" ] && exit 0
  PROJECT_PATH=$(jq -r '.project_path // ""' "$CONFIG_FILE")
else
  exit 0
fi

# Skip source code, config, and binary-adjacent files by extension
EXT="${FILE_PATH##*.}"
case ".$EXT" in
  .py|.js|.ts|.jsx|.tsx|.json|.yaml|.yml|.toml|.md|.sh|.css|.html|.xml|.sql|.go|.rs|.java|.rb|.swift|.kt|.c|.h|.cpp|.hpp|.lock|.gitignore|.env|.ini|.cfg|.conf|.ipynb|.whl|.tar|.gz|.zip|.png|.jpg|.jpeg|.gif|.svg|.ico|.woff|.woff2|.ttf|.eot|.pdf|.mp3|.mp4|.wav|.avi)
    exit 0
    ;;
esac

# Skip binary files (quick heuristic via file command)
file "$FILE_PATH" 2>/dev/null | grep -q "text" || exit 0

# Check protected_paths — if list is non-empty, file must be under one of them
PROTECTED_PATHS=$(jq -r '.protected_paths // [] | .[]' "$CONFIG_FILE" 2>/dev/null)
if [ -n "$PROTECTED_PATHS" ]; then
  MATCH=false
  while IFS= read -r dir; do
    [ -z "$dir" ] && continue
    case "$FILE_PATH" in "$dir"*) MATCH=true; break ;; esac
  done <<< "$PROTECTED_PATHS"
  [ "$MATCH" = "false" ] && exit 0
fi

# Check protected_extensions — file extension must be in the list
PROTECTED_EXT=$(jq -r '.protected_extensions // [] | .[]' "$CONFIG_FILE" 2>/dev/null)
if [ -n "$PROTECTED_EXT" ]; then
  EXT_MATCH=false
  while IFS= read -r pext; do
    [ -z "$pext" ] && continue
    [ ".$EXT" = "$pext" ] && EXT_MATCH=true && break
  done <<< "$PROTECTED_EXT"
  [ "$EXT_MATCH" = "false" ] && exit 0
fi

# Delegate to Python anonymizer
echo "$INPUT" | uv run --project "$PROJECT_PATH" python -m pii_guard.hook_anonymize
