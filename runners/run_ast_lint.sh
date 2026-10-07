#!/usr/bin/env bash
#
# Pillar 1 Runner: AST Linting & Code Review
# Modes: fast, quality, review
#

set -uo pipefail
MODE="${1:-${MODE:-fast}}"
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

echo "▶ [Pillar 1] AST Linting & Code Review (Mode: ${MODE})"

# 1. ast-grep (sg)
SG_BIN=""
if command -v ast-grep >/dev/null 2>&1 && ast-grep --version 2>&1 | grep -q "ast-grep"; then
  SG_BIN="ast-grep"
elif command -v sg >/dev/null 2>&1 && sg --version 2>&1 | grep -q "ast-grep"; then
  SG_BIN="sg"
fi

if [ -n "${SG_BIN}" ]; then
  echo "  Running ast-grep scan..."

  ACTIVE_RULES=()
  # Go egress rule: if Go code exists
  if [ -f "go.mod" ] || [ -d "backend" ] || [ -n "$(find . -maxdepth 3 -name "*.go" -not -path "*/vendor/*" 2>/dev/null | head -n 1)" ]; then
    [ -f "${TOOL_ROOT}/configs/ast-grep/rules/go-egress.yml" ] && ACTIVE_RULES+=("${TOOL_ROOT}/configs/ast-grep/rules/go-egress.yml")
  fi

  # TypeScript / Next.js server action guard and pool isolation rules: if JS/TS code exists
  if [ -f "package.json" ] || [ -d "src" ] || [ -d "app" ]; then
    [ -f "${TOOL_ROOT}/configs/ast-grep/rules/action-authorization-guard.yml" ] && ACTIVE_RULES+=("${TOOL_ROOT}/configs/ast-grep/rules/action-authorization-guard.yml")
    [ -f "${TOOL_ROOT}/configs/ast-grep/rules/db-pool-isolation.yml" ] && ACTIVE_RULES+=("${TOOL_ROOT}/configs/ast-grep/rules/db-pool-isolation.yml")
  fi

  # Project-specific custom AST rules (.vigil/rules/*.yml)
  for rdir in .vigil/rules; do
    if [ -d "${rdir}" ]; then
      for custom_rule in "${rdir}"/*.yml "${rdir}"/*.yaml; do
        if [ -f "${custom_rule}" ]; then
          ACTIVE_RULES+=("${custom_rule}")
        fi
      done
    fi
  done

  if [ ${#ACTIVE_RULES[@]} -gt 0 ]; then
    python3 -c "
import subprocess, json, sys
active_rules = sys.argv[1:]
all_matches = []
for r in active_rules:
    res = subprocess.run(['${SG_BIN}', 'scan', '-r', r, '--json'], capture_output=True, text=True)
    if res.stdout:
        try:
            items = json.loads(res.stdout)
            if isinstance(items, list):
                all_matches.extend(items)
        except Exception:
            pass
with open('${RAW_DIR}/ast_grep.json', 'w') as f:
    json.dump(all_matches, f, indent=2)
" "${ACTIVE_RULES[@]}" 2>/dev/null || echo "[]" > "${RAW_DIR}/ast_grep.json"
  else
    echo "[]" > "${RAW_DIR}/ast_grep.json"
  fi
fi

# 2. Hadolint Dockerfile analysis
if command -v hadolint >/dev/null 2>&1; then
  echo "  Running hadolint..."
  DOCKERFILES=$(find . -maxdepth 3 -name "Dockerfile*" -not -path "*/node_modules/*" -not -path "*/.git/*" 2>/dev/null)
  if [ -n "${DOCKERFILES}" ]; then
    hadolint -c "${TOOL_ROOT}/configs/.hadolint.yaml" -f json ${DOCKERFILES} > "${RAW_DIR}/hadolint.json" 2>/dev/null || true
  fi
fi

# 3. Zizmor CI workflow auditing
if command -v zizmor >/dev/null 2>&1 && [ -d ".github/workflows" ]; then
  echo "  Running zizmor on GitHub Actions workflows..."
  zizmor --format json .github/workflows/ > "${RAW_DIR}/zizmor.json" 2>/dev/null || true
fi

# 4. Dependency-Cruiser boundary checks
if [ -d "src" ] && command -v depcruise >/dev/null 2>&1; then
  echo "  Running dependency-cruiser..."
  TS_CONFIG_ARG=""
  [ -f "tsconfig.json" ] && TS_CONFIG_ARG="--ts-config tsconfig.json"
  NODE_PATH="${WORKSPACE}/node_modules:/usr/local/lib/node_modules" depcruise \
    --config "${TOOL_ROOT}/configs/.dependency-cruiser.js" \
    ${TS_CONFIG_ARG} \
    --output-type json \
    --output-to "${RAW_DIR}/dep_cruiser.json" \
    src 2>/dev/null || true
fi

# 5. Oxlint JavaScript/TypeScript linter
if command -v oxlint >/dev/null 2>&1 && [ -f "package.json" ]; then
  echo "  Running oxlint..."
  oxlint -f json > "${RAW_DIR}/oxlint.json" 2>/dev/null || true
fi

# 6. Custom repository audit hooks and scripts
for hdir in .vigil/hooks; do
  if [ -d "${hdir}" ]; then
    for hook in "${hdir}"/*.sh "${hdir}"/*.py; do
      if [ -f "${hook}" ]; then
        hook_name=$(basename "${hook}")
        echo "  Running custom audit hook ${hook_name}..."
        if [[ "${hook}" == *.py ]]; then
          python3 "${hook}" > "${RAW_DIR}/hook_${hook_name}.log" 2>&1 || echo "HOOK_FAILURE" > "${RAW_DIR}/hook_${hook_name}.fail"
        else
          bash "${hook}" > "${RAW_DIR}/hook_${hook_name}.log" 2>&1 || echo "HOOK_FAILURE" > "${RAW_DIR}/hook_${hook_name}.fail"
        fi
      fi
    done
  fi
done

for script_name in check-action-guards.py check-build-contexts.py check-service-boundary.py check-dockerfiles-nonroot.py check-tenant-scoping.py check-migrations.py; do
  if [ -f "scripts/${script_name}" ]; then
    echo "  Running scripts/${script_name}..."
    python3 "scripts/${script_name}" > "${RAW_DIR}/${script_name}.log" 2>&1 || echo "SCRIPT_FAILURE" > "${RAW_DIR}/${script_name}.fail"
  fi
done

# Quality & Review Mode battery
if [ "${MODE:-}" = "quality" ] || [ "${MODE:-}" = "review" ]; then
  # 7. GolangCI-Lint
  GO_MODULES=$(find . -name "go.mod" -not -path "*/node_modules/*" -not -path "*/vendor/*" -exec dirname {} \; 2>/dev/null | sort)
  if command -v golangci-lint >/dev/null 2>&1 && [ -n "${GO_MODULES}" ]; then
    echo "  Running golangci-lint on Go modules..."
    for mod in ${GO_MODULES}; do
      mod_name=$(echo "${mod}" | sed 's|^\./||; s|/|_|g')
      (
        cd "${mod}"
        golangci-lint run --config "${TOOL_ROOT}/configs/.golangci.yml" --out-format json > "${RAW_DIR}/golangci_${mod_name}.json" 2>/dev/null || true
      )
    done
  fi

  # 8. NilAway nil-safety analysis
  if command -v nilaway >/dev/null 2>&1 && [ -n "${GO_MODULES}" ]; then
    echo "  Running nilaway on Go modules..."
    for mod in ${GO_MODULES}; do
      (
        cd "${mod}"
        nilaway ./... >> "${RAW_DIR}/nilaway.log" 2>&1 || true
      )
    done
  fi

  # 9. Squawk PostgreSQL migration checks
  if command -v squawk >/dev/null 2>&1 && [ -d "database/migrations" ]; then
    echo "  Running squawk migration linter..."
    MIGRATIONS=$(find database/migrations -maxdepth 1 -name "*.sql" 2>/dev/null)
    if [ -n "${MIGRATIONS}" ]; then
      squawk --config "${TOOL_ROOT}/configs/.squawk.toml" --reporter json ${MIGRATIONS} > "${RAW_DIR}/squawk.json" 2>/dev/null || true
    fi
  fi

  # 10. Ruff Python linter
  if command -v ruff >/dev/null 2>&1; then
    PY_FILES=$(find . -maxdepth 3 -name "*.py" -not -path "*/.venv/*" -not -path "*/node_modules/*" 2>/dev/null | head -n 1)
    if [ -n "${PY_FILES}" ]; then
      echo "  Running ruff..."
      ruff check --config "${TOOL_ROOT}/configs/ruff.toml" --output-format json -o "${RAW_DIR}/ruff.json" . 2>/dev/null || true
    fi
  fi

  # 11. PHPStan analysis (Website repository)
  if command -v phpstan >/dev/null 2>&1; then
    PHP_FILES=$(find . -maxdepth 3 -name "*.php" -not -path "*/vendor/*" 2>/dev/null | head -n 1)
    if [ -n "${PHP_FILES}" ]; then
      echo "  Running phpstan..."
      phpstan analyse -c "${TOOL_ROOT}/configs/phpstan.neon" --error-format=json > "${RAW_DIR}/phpstan.json" 2>/dev/null || true
    fi
  fi
fi

echo "✔ [Pillar 1] AST Linting complete"
