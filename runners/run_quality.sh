#!/usr/bin/env bash
#
# Sentinel Quality Battery: Code Quality, Complexity, Duplication & Dead Code
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

WORKSPACE="${WORKSPACE:-$([ -d /workspace ] && [ -w /workspace ] && echo /workspace || pwd)}"
RAW_DIR="${WORKSPACE}/reports/raw"
mkdir -p "${RAW_DIR}"

echo "▶ [Quality Battery] Code Quality, Complexity, Duplication & Dead Code"

# 1. AST Linting (Quality Mode: golangci-lint, nilaway, squawk, ruff, phpstan)
if [ -f "${TOOL_ROOT}/runners/run_ast_lint.sh" ]; then
  bash "${TOOL_ROOT}/runners/run_ast_lint.sh" quality
fi

# 2. Dead Code & Junk Pruning (knip, deadcode, vulture)
if [ -f "${TOOL_ROOT}/runners/run_junk_detect.sh" ]; then
  bash "${TOOL_ROOT}/runners/run_junk_detect.sh"
fi

# 3. Duplicate Code Detection (jscpd)
if command -v jscpd >/dev/null 2>&1; then
  echo "  Running jscpd copy-paste duplication detector..."
  mkdir -p "${RAW_DIR}/jscpd"
  JSCPD_CONF="${TOOL_ROOT}/configs/jscpd/.jscpd.json"
  [ -f ".jscpd.json" ] && JSCPD_CONF=".jscpd.json"
  jscpd --config "${JSCPD_CONF}" . > "${RAW_DIR}/jscpd.log" 2>&1 || true
fi

# 4. Semantic Code Review & PR-Agent Suggestions
if [ -f "${TOOL_ROOT}/engine/code_review/pr_reviewer.py" ]; then
  echo "  Running semantic PR reviewer (CodeRabbit alternative)..."
  python3 "${TOOL_ROOT}/engine/code_review/pr_reviewer.py" --output-json="${RAW_DIR}/pr_review.json" --output-md="${RAW_DIR}/pr_review.md" || true
fi

# 5. Inline GitHub Annotations (reviewdog)
if [ -f "${TOOL_ROOT}/engine/code_review/reviewdog_wrapper.sh" ]; then
  bash "${TOOL_ROOT}/engine/code_review/reviewdog_wrapper.sh" || true
fi

echo "✔ [Quality Battery] Code quality analysis complete"
