#!/usr/bin/env bash
#
# Pillar 2 Runner: Junk Code & Asset Pruning
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

echo "▶ [Pillar 2] Junk Code & Dead Asset Pruning"

# 1. Knip Next.js / TypeScript dead code analysis
if command -v knip >/dev/null 2>&1 && [ -f "package.json" ]; then
  echo "  Running knip dead-code detector..."
  KNIP_CONF="${TOOL_ROOT}/configs/knip.jsonc"
  [ -f "knip.jsonc" ] && KNIP_CONF="knip.jsonc"
  knip --config "${KNIP_CONF}" --reporter json > "${RAW_DIR}/knip.json" 2>/dev/null || true
fi

# 2. Go deadcode analysis
GO_MODULES=$(find . -name "go.mod" -not -path "*/node_modules/*" -not -path "*/vendor/*" -exec dirname {} \; 2>/dev/null | sort)
if command -v deadcode >/dev/null 2>&1 && [ -n "${GO_MODULES}" ]; then
  echo "  Running Go deadcode analysis..."
  for mod in ${GO_MODULES}; do
    (
      cd "${mod}"
      deadcode -test ./... >> "${RAW_DIR}/deadcode.log" 2>&1 || true
    )
  done
fi

# 3. Python vulture dead code analysis
if command -v vulture >/dev/null 2>&1; then
  PY_FILES=$(find . -maxdepth 3 -name "*.py" -not -path "*/.venv/*" -not -path "*/node_modules/*" 2>/dev/null | head -n 1)
  if [ -n "${PY_FILES}" ]; then
    echo "  Running vulture dead-code detector..."
    vulture --min-confidence 80 --exclude ".venv,node_modules,vendor,testdata" . > "${RAW_DIR}/vulture.log" 2>&1 || true
  fi
fi

echo "✔ [Pillar 2] Junk Code analysis complete"
