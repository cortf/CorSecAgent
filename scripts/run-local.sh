#!/usr/bin/env bash
#
# Run the full CorSec pipeline against the local sandbox.
#
#   ./scripts/run-local.sh              # replay recorded advisories (deterministic, no token)
#   ./scripts/run-local.sh --live       # query the real GitHub Advisory API
#   ./scripts/run-local.sh --no-reset   # keep the sandbox as the last run left it
#
# Always DRY RUN: the orchestrator is invoked with --dry-run, so nothing is
# pushed and no PR is opened. The Patcher still creates a local branch and runs
# npm install inside the sandbox — that is why we reset it by default.
#
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SANDBOX="$REPO_ROOT/sandbox/vulnerable-app"
OUTPUT_DIR="$REPO_ROOT/.corsec-local"
ADVISORIES="$REPO_ROOT/fixtures/recorded-advisories.json"

LIVE=0
RESET=1
for arg in "$@"; do
  case "$arg" in
    --live)     LIVE=1 ;;
    --no-reset) RESET=0 ;;
    *) echo "Unknown flag: $arg" >&2; exit 2 ;;
  esac
done

# checkov installs to a user-local bin that is often not on PATH.
export PATH="$HOME/.local/bin:$HOME/Library/Python/3.12/bin:$PATH"

echo "==> Preflight"
for bin in node npm git; do
  command -v "$bin" >/dev/null || { echo "    MISSING (required): $bin" >&2; exit 1; }
done
# Scanners are optional: Cort degrades to an empty report per scanner if absent.
for bin in checkov tfsec; do
  if command -v "$bin" >/dev/null; then
    echo "    ok       $bin"
  else
    echo "    absent   $bin (Cort will degrade — that stage's findings will be empty)"
  fi
done
if [ -n "${ANTHROPIC_API_KEY:-}" ]; then
  echo "    ok       ANTHROPIC_API_KEY (Reporter can use LLM mode)"
else
  echo "    absent   ANTHROPIC_API_KEY (Reporter fails if it picks LLM mode)"
fi

if [ "$RESET" -eq 1 ]; then
  "$REPO_ROOT/scripts/setup-sandbox.sh"
else
  echo "==> Skipping sandbox reset (--no-reset)"
  [ -d "$SANDBOX" ] || { echo "    Sandbox missing. Run scripts/setup-sandbox.sh first." >&2; exit 1; }
fi

rm -rf "$OUTPUT_DIR"
mkdir -p "$OUTPUT_DIR"

# Advisory source: replay by default, live only on request.
ADVISORY_ARGS=()
if [ "$LIVE" -eq 1 ]; then
  if [ -z "${GITHUB_TOKEN:-}" ]; then
    if command -v gh >/dev/null && gh auth token >/dev/null 2>&1; then
      GITHUB_TOKEN="$(gh auth token)"
      export GITHUB_TOKEN
      echo "==> Using GITHUB_TOKEN from 'gh auth token'"
    else
      echo "GITHUB_TOKEN is not set and 'gh auth token' failed." >&2
      exit 1
    fi
  fi
  # 30 days: the API returns the 100 most recent advisories regardless, so a
  # wider window than this buys nothing. A 24h window is usually empty.
  SINCE="$(node -e "console.log(new Date(Date.now()-30*864e5).toISOString())")"
  ADVISORY_ARGS=(--since "$SINCE")
  echo "==> Advisory source: LIVE GitHub API (since $SINCE)"
else
  [ -f "$ADVISORIES" ] || {
    echo "Recorded advisories not found at $ADVISORIES" >&2
    echo "Record them once with:" >&2
    echo "  GITHUB_TOKEN=\$(gh auth token) npx tsx scripts/record-advisories.ts --output $ADVISORIES" >&2
    exit 1
  }
  ADVISORY_ARGS=(--advisories-file "$ADVISORIES")
  echo "==> Advisory source: recorded replay ($ADVISORIES)"
fi

echo "==> Running orchestrator (dry run)"
set +e
npx tsx "$REPO_ROOT/src/orchestrate.ts" \
  --working-dir "$SANDBOX" \
  --output-dir "$OUTPUT_DIR" \
  --terraform-dir "$SANDBOX/terraform" \
  --test-command "npm test" \
  --dry-run \
  "${ADVISORY_ARGS[@]}"
EXIT_CODE=$?
set -e

echo ""
echo "==> Exit code: $EXIT_CODE"
echo "==> Artifacts in $OUTPUT_DIR:"
for f in hunter-matches.json cort-report.json patch-session.json pr-description.md orchestration-summary.json; do
  if [ -f "$OUTPUT_DIR/$f" ]; then
    printf '    %-28s %s bytes\n' "$f" "$(wc -c < "$OUTPUT_DIR/$f" | tr -d ' ')"
  else
    printf '    %-28s (not produced)\n' "$f"
  fi
done

if [ -f "$OUTPUT_DIR/pr-description.md" ]; then
  echo ""
  echo "===================== pr-description.md ====================="
  cat "$OUTPUT_DIR/pr-description.md"
  echo ""
  echo "============================================================="
fi

exit "$EXIT_CODE"
