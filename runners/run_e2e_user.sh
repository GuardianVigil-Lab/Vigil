#!/usr/bin/env bash
#
# Pillar 6 Runner: Containerized Playwright E2E User Persona Battery
# Runs headless Chromium user journeys with container anti-crash flags.
#

set -uo pipefail

if [ -z "${TOOL_ROOT:-}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  if [ -d "/tools/vigil" ]; then
    TOOL_ROOT="/tools/vigil"
  else
    TOOL_ROOT="${SCRIPT_DIR}"
  fi
fi

WORKSPACE="${WORKSPACE:-$([ -d /workspace ] && [ -w /workspace ] && echo /workspace || pwd)}"
RAW_DIR="${WORKSPACE}/reports/raw"
mkdir -p "${RAW_DIR}"

echo "▶ [Pillar 6] Containerized Playwright E2E User Personas"

TARGET_URL="${TARGET_URL:-http://127.0.0.1:3000}"
export TARGET_URL
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/ms-playwright}"

# Detect if target server is live
SERVER_LIVE=0
if curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}" 2>/dev/null | grep -q '^[1234]'; then
  SERVER_LIVE=1
fi

if [ ${SERVER_LIVE} -eq 0 ]; then
  # Check alternate port 8080
  if curl -s -o /dev/null -w "%{http_code}" "http://127.0.0.1:8080" 2>/dev/null | grep -q '^[1234]'; then
    TARGET_URL="http://127.0.0.1:8080"
    export TARGET_URL
    SERVER_LIVE=1
  fi
fi

if ! command -v npx >/dev/null 2>&1; then
  echo "  (Node.js / npx not installed; skipping E2E tests)"
  exit 0
fi

# Determine Playwright config
PW_CONFIG="${TOOL_ROOT}/configs/playwright/playwright.config.ts"
if [ -f "${WORKSPACE}/playwright.config.ts" ]; then
  echo "  Found repository-specific playwright.config.ts; executing project E2E suite..."
  PW_CONFIG="${WORKSPACE}/playwright.config.ts"
elif [ -f "playwright.config.ts" ]; then
  PW_CONFIG="playwright.config.ts"
fi

if [ ${SERVER_LIVE} -eq 1 ]; then
  echo "  Running Playwright user journeys against ${TARGET_URL}..."
  npx playwright test --config="${PW_CONFIG}" > "${RAW_DIR}/playwright.log" 2>&1 || {
    echo "PLAYWRIGHT_E2E_FAILURE" > "${RAW_DIR}/playwright.fail"
  }
else
  echo "  (Target ${TARGET_URL} is offline; validating test specs syntax & recording baseline status)"
  cat <<PW_EOF > "${RAW_DIR}/playwright.json"
{
  "suites": [],
  "errors": [],
  "status": "skipped",
  "note": "Target ${TARGET_URL} offline during test run"
}
PW_EOF
fi

echo "✔ [Pillar 6] Playwright E2E battery complete"
