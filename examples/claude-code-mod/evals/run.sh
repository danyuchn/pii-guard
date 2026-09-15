#!/usr/bin/env bash
# Runs the Mod's eval suite against a throwaway guard service.
#
# An eval run gets a throwaway home directory and inherits only EVAL_ prefixed
# variables from the surrounding shell, so the Mod cannot find a service at the
# usual path. This script starts one under a temporary home and hands the Mod
# that path as EVAL_PII_GUARD_HOOKD_HOME. Nothing here touches a real
# installation: no settings are written and the service is stopped on the way
# out, whichever way the script ends.
#
#   ./run.sh                       # full engine, 1 run per arm, haiku
#   ENGINE=regex RUNS=3 ./run.sh   # faster engine, more runs
#
set -euo pipefail

MOD_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REPO_ROOT="$(cd "$MOD_DIR/../.." && pwd)"
ENGINE="${ENGINE:-full}"
RUNS="${RUNS:-1}"
MODEL="${MODEL:-haiku}"

GUARD_HOME="$(mktemp -d "${TMPDIR:-/tmp}/pii-guard-evals.XXXXXX")"

cleanup() {
    PII_GUARD_HOOKD_HOME="$GUARD_HOME" \
        uv run --project "$REPO_ROOT" pii-guard-hookd stop >/dev/null 2>&1 || true
    rm -rf "$GUARD_HOME"
}
trap cleanup EXIT INT TERM

echo "Starting the guard (engine: $ENGINE, home: $GUARD_HOME)..."
if ! PII_GUARD_HOOKD_HOME="$GUARD_HOME" \
    uv run --project "$REPO_ROOT" pii-guard-hookd serve --engine "$ENGINE"; then
    echo "The guard did not start; the suite would only measure a dead service." >&2
    exit 1
fi

# The plugin's hooks run outside the agent's sandbox, so they can reach the
# service on loopback and read its state file under this path.
export EVAL_PII_GUARD_HOOKD_HOME="$GUARD_HOME"
export CLAUDE_CODE_ENABLE_FUNCTION_HOOKS=1

set +e
claude plugin eval "$MOD_DIR" \
    --scaffold \
    --allow-tools Write \
    --trust-plugin \
    --no-publish \
    --runs "$RUNS" \
    --model "$MODEL" \
    "$@"
STATUS=$?
set -e

LATEST="$(ls -dt "$MOD_DIR"/evals/results/*/ 2>/dev/null | head -1 || true)"
if [ -n "$LATEST" ]; then
    echo
    echo "Report: ${LATEST}report.html"
    echo "Result: ${LATEST}aggregate-result.json"
fi
exit "$STATUS"
