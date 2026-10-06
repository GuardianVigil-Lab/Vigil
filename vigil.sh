#!/usr/bin/env bash
#
# Vigil: Master Container Orchestrator Entrypoint
# Modes: fast, quality, security, vapt, test, e2e, review
#

set -uo pipefail

# Detect tool root dynamically (supports /tools/vigil, /tools/sentinel, or local execution)
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -d "/tools/vigil" ]; then
  TOOL_ROOT="/tools/vigil"
elif [ -d "/tools/sentinel" ]; then
  TOOL_ROOT="/tools/sentinel"
else
  TOOL_ROOT="${SCRIPT_DIR}"
fi
export TOOL_ROOT

MODE="${1:-review}"
export WORKSPACE="${WORKSPACE:-$([ -d /workspace ] && [ -w /workspace ] && echo /workspace || pwd)}"
cd "${WORKSPACE}"

RAW_DIR="${WORKSPACE}/reports/raw"
mkdir -p "${RAW_DIR}"
# Clean previous raw run artifacts
rm -f "${RAW_DIR}"/* 2>/dev/null || true

START_TIME=$(date +%s)

echo "══════════════════════════════════════════════════════════════════════"
echo "  VIGIL SECURITY & QUALITY ENGINE (Mode: ${MODE})"
echo "  Target Workspace: ${WORKSPACE}"
echo "══════════════════════════════════════════════════════════════════════"

case "${MODE}" in
  fast)
    echo "⚡ Running FAST battery (<15s ratchet)..."
    bash "${TOOL_ROOT}/runners/run_fast.sh"
    ;;
  quality)
    echo "💎 Running QUALITY battery..."
    bash "${TOOL_ROOT}/runners/run_quality.sh"
    ;;
  security)
    echo "🛡️ Running SECURITY battery..."
    bash "${TOOL_ROOT}/runners/run_security.sh"
    ;;
  vapt)
    echo "🎯 Running VAPT & Deep Penetration Testing battery..."
    bash "${TOOL_ROOT}/runners/run_vapt.sh"
    ;;
  test)
    echo "🧪 Running QA & Mutation Test battery..."
    bash "${TOOL_ROOT}/runners/run_qa_tests.sh"
    ;;
  e2e)
    echo "🎭 Running Playwright E2E User Persona battery..."
    bash "${TOOL_ROOT}/runners/run_e2e_user.sh"
    ;;
  review|all)
    echo "🔍 Running COMPLETE REVIEW battery..."
    bash "${TOOL_ROOT}/runners/run_ast_lint.sh" review || true
    bash "${TOOL_ROOT}/runners/run_junk_detect.sh" || true
    bash "${TOOL_ROOT}/runners/run_quality.sh" || true
    bash "${TOOL_ROOT}/runners/run_security.sh" || true
    bash "${TOOL_ROOT}/runners/run_vapt.sh" || true
    bash "${TOOL_ROOT}/runners/run_qa_tests.sh" || true
    bash "${TOOL_ROOT}/runners/run_e2e_user.sh" || true
    ;;
  *)
    echo "Unknown mode: ${MODE}"
    echo "Supported modes: fast, quality, security, vapt, test, e2e, review"
    exit 2
    ;;
esac

# Execute Review Synthesizer
python3 "${TOOL_ROOT}/engine/synthesizer/parse_results.py"
EXIT_CODE=$?

END_TIME=$(date +%s)
ELAPSED=$((END_TIME - START_TIME))
echo "⏱ Audit completed in ${ELAPSED}s (Exit code: ${EXIT_CODE})"
echo "  SARIF:    ${WORKSPACE}/reports/vigil.sarif"
echo "  Markdown: ${WORKSPACE}/reports/vigil-review.md"

exit ${EXIT_CODE}
