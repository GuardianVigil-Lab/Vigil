#!/usr/bin/env bash
#
# Pillar 5 Runner: QA Invariants, Mutation Testing & DB Verification
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

echo "▶ [Pillar 5] QA Invariants, Unit Tests, Mutation Testing & DB Verification"

# 1. Vitest Unit Suite
if [ -f "vitest.config.mts" ] || [ -f "vitest.config.ts" ]; then
  echo "  Running Vitest unit test suite..."
  npx vitest run --reporter=json --outputFile="${RAW_DIR}/vitest.json" > "${RAW_DIR}/vitest.log" 2>&1 || echo "VITEST_FAILURE" > "${RAW_DIR}/vitest.fail"
fi

# 2. Stryker Mutation Testing (Broken Functionality & Test Efficacy Verification)
if [ "${ENABLE_MUTATION_TESTING:-0}" = "1" ] || [ -f "stryker.config.json" ] || [ -f "stryker.config.mjs" ]; then
  if command -v stryker >/dev/null 2>&1 || command -v npx >/dev/null 2>&1; then
    echo "  Running Stryker mutation testing on TypeScript tests..."
    npx stryker run > "${RAW_DIR}/stryker_mutation.log" 2>&1 || echo "STRYKER_MUTATION_FAILURE" > "${RAW_DIR}/stryker_mutation.fail"
  fi
fi

# 3. Go Unit & Race Suite
GO_MODULES=$(find . -name "go.mod" -not -path "*/node_modules/*" -not -path "*/vendor/*" -exec dirname {} \; 2>/dev/null | sort)
if [ -n "${GO_MODULES}" ]; then
  echo "  Running Go unit tests with race detector..."
  GO_FAILED=0
  for mod in ${GO_MODULES}; do
    printf '  Testing %-22s ' "${mod}..."
    if ( cd "${mod}" && go test -race ./... >> "${RAW_DIR}/go_tests.log" 2>&1 ); then
      echo "ok"
    else
      echo "FAILED"
      GO_FAILED=1
    fi
  done
  if [ ${GO_FAILED} -ne 0 ]; then
    echo "GO_TEST_FAILURE" > "${RAW_DIR}/go_tests.fail"
  fi

  # 4. Go Mutation Testing (go-mutesting)
  if [ "${ENABLE_MUTATION_TESTING:-0}" = "1" ] && command -v go-mutesting >/dev/null 2>&1; then
    echo "  Running go-mutesting on Go modules..."
    for mod in ${GO_MODULES}; do
      ( cd "${mod}" && go-mutesting ./... >> "${RAW_DIR}/go_mutesting.log" 2>&1 || true )
    done
  fi
fi

# 5. PHP Test Suite
if [ -f "scripts/php-tests.sh" ]; then
  echo "  Running PHP test suite..."
  bash scripts/php-tests.sh > "${RAW_DIR}/php_tests.log" 2>&1 || echo "PHP_TEST_FAILURE" > "${RAW_DIR}/php_tests.fail"
elif [ -f "vendor/bin/phpunit" ]; then
  echo "  Running PHPUnit..."
  php vendor/bin/phpunit > "${RAW_DIR}/php_tests.log" 2>&1 || echo "PHP_TEST_FAILURE" > "${RAW_DIR}/php_tests.fail"
fi

# 6. PostgreSQL Migration Static Verification
if [ -f "scripts/check-migrations.py" ]; then
  echo "  Running check-migrations.py..."
  python3 scripts/check-migrations.py > "${RAW_DIR}/migrations_gate.log" 2>&1 || echo "MIGRATION_FAILURE" > "${RAW_DIR}/migrations_gate.fail"
fi

echo "✔ [Pillar 5] QA tests complete"
