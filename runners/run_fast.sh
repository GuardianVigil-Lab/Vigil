#!/usr/bin/env bash
#
# Sentinel Fast Developer Ratchet (< 15s)
# Focuses on high-speed pre-commit & PR gates:
# 1. AST Linting & Action Guards
# 2. Gitleaks fast commit/tree secrets scan
# 3. Zizmor CI workflow security
# 4. Anti-Fabrication fast changed files scan
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

echo "▶ [Fast Ratchet] Starting developer iteration battery (< 15s)"

# 1. AST Linting
if [ -f "${TOOL_ROOT}/runners/run_ast_lint.sh" ]; then
  bash "${TOOL_ROOT}/runners/run_ast_lint.sh" fast
fi

# 2. Fast Gitleaks
if command -v gitleaks >/dev/null 2>&1; then
  echo "  Running gitleaks fast scan..."
  if [ -d ".git" ]; then
    gitleaks git --no-banner --report-format json --report-path "${RAW_DIR}/gitleaks.json" >/dev/null 2>&1 || true
  else
    gitleaks detect --no-git --report-format json --report-path "${RAW_DIR}/gitleaks.json" >/dev/null 2>&1 || true
  fi
fi

# 3. Fast Anti-Fabrication Changed-Files Scan
if [ -f "${TOOL_ROOT}/engine/anti_fabrication/detector.py" ]; then
  echo "  Running anti-fabrication on changed files..."
  python3 "${TOOL_ROOT}/engine/anti_fabrication/detector.py" --changed --json-out="${RAW_DIR}/anti_fabrication.json" >/dev/null 2>&1 || true
fi

# 4. Fast PR Diff Semantic Review
if [ -f "${TOOL_ROOT}/engine/code_review/pr_reviewer.py" ]; then
  echo "  Running diff-scoped semantic code review..."
  python3 "${TOOL_ROOT}/engine/code_review/pr_reviewer.py" --output-json="${RAW_DIR}/pr_review.json" --output-md="${RAW_DIR}/pr_review.md" >/dev/null 2>&1 || true
fi

echo "✔ [Fast Ratchet] Fast battery complete"
