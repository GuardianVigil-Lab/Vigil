#!/usr/bin/env bash
#
# Sentinel Complete Audit Battery Orchestrator
# Executes all 6 pillars and triggers the synthesizer.
#

set -uo pipefail

if [ -z "${TOOL_ROOT:-}" ]; then
  SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  if [ -d "/tools/vigil" ]; then
    TOOL_ROOT="/tools/vigil"
  elif [ -d "/tools/sentinel" ]; then
    TOOL_ROOT="/tools/sentinel"
  else
    TOOL_ROOT="${SCRIPT_DIR}"
  fi
fi

echo "======================================================================"
echo "  VIGIL COMPLETE AUDIT BATTERY"
echo "======================================================================"

bash "${TOOL_ROOT}/runners/run_ast_lint.sh" review || true
bash "${TOOL_ROOT}/runners/run_junk_detect.sh" || true
bash "${TOOL_ROOT}/runners/run_quality.sh" || true
bash "${TOOL_ROOT}/runners/run_security.sh" || true
bash "${TOOL_ROOT}/runners/run_vapt.sh" || true
bash "${TOOL_ROOT}/runners/run_qa_tests.sh" || true
bash "${TOOL_ROOT}/runners/run_e2e_user.sh" || true

echo "✔ All batteries completed. Ready for review synthesis."
