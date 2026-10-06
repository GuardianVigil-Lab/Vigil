#!/usr/bin/env bash
#
# Pillar 4 Runner: Deep VAPT, Strix Autonomous Red Teaming & Infrastructure Auditing
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

echo "▶ [Pillar 4] Deep VAPT, Strix Red Teaming & Infra Auditing"

# 1. Schemathesis OpenAPI fuzzing / validation
OPENAPI_SPEC=$(find . -maxdepth 4 -name "openapi.y*ml" -o -name "swagger.y*ml" 2>/dev/null | head -n 1)
if command -v schemathesis >/dev/null 2>&1 && [ -n "${OPENAPI_SPEC}" ]; then
  echo "  Running schemathesis schema conformance on ${OPENAPI_SPEC}..."
  schemathesis run "${OPENAPI_SPEC}" --dry-run --show-errors-trace --junit-xml "${RAW_DIR}/schemathesis.xml" >/dev/null 2>&1 || true
fi

# 2. Nuclei dynamic DAST checks (if target server active)
if command -v nuclei >/dev/null 2>&1; then
  echo "  Validating nuclei templates & running target audit..."
  NUCLEI_TARGET=""
  if [ -n "${TARGET_URL:-}" ] && curl -s -o /dev/null -w "%{http_code}" "${TARGET_URL}" 2>/dev/null | grep -q '^[1234]'; then
    NUCLEI_TARGET="${TARGET_URL}"
  elif curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:3000 2>/dev/null | grep -q '^[23]'; then
    NUCLEI_TARGET="http://127.0.0.1:3000"
  elif curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8080 2>/dev/null | grep -q '^[23]'; then
    NUCLEI_TARGET="http://127.0.0.1:8080"
  elif curl -s -o /dev/null -w "%{http_code}" http://127.0.0.1:8082 2>/dev/null | grep -q '^[23]'; then
    NUCLEI_TARGET="http://127.0.0.1:8082"
  fi

  if [ -n "${NUCLEI_TARGET}" ]; then
    nuclei -u "${NUCLEI_TARGET}" -duc -silent -jsonl -o "${RAW_DIR}/nuclei.jsonl" 2>/dev/null || true
  else
    echo "  (No live target HTTP server detected; skipping active nuclei probes)"
  fi
fi

# 3. Strix Autonomous Penetration Testing
if [ -f "${TOOL_ROOT}/engine/vapt/strix_orchestrator.py" ]; then
  echo "  Running Strix autonomous AI red team orchestrator..."
  SPEC_ARG=""
  [ -n "${OPENAPI_SPEC}" ] && SPEC_ARG="--openapi=${OPENAPI_SPEC}"
  python3 "${TOOL_ROOT}/engine/vapt/strix_orchestrator.py" ${SPEC_ARG} --output-dir="${RAW_DIR}" > "${RAW_DIR}/strix.log" 2>&1 || true
fi

# 4. Automated BOLA / IDOR Cross-Tenant Matrix Probe
if [ -f "${TOOL_ROOT}/engine/vapt/bola_matrix.py" ]; then
  echo "  Running BOLA / IDOR cross-tenant matrix probe..."
  python3 "${TOOL_ROOT}/engine/vapt/bola_matrix.py" --workspace="${WORKSPACE}" --output="${RAW_DIR}/bola_matrix.json" > "${RAW_DIR}/bola_matrix.log" 2>&1 || true
fi

# 5. Infrastructure & Transport Security Audit (Nmap, testssl.sh, Nikto)
if [ -f "${TOOL_ROOT}/engine/vapt/infra_scanner.sh" ]; then
  echo "  Running infrastructure & transport security audit..."
  bash "${TOOL_ROOT}/engine/vapt/infra_scanner.sh" > "${RAW_DIR}/infra_scanner.log" 2>&1 || true
fi

# 6. Dynamic Billing / Tenant Switching Checks
if [ -f "scripts/billing-lifecycle-test.sh" ]; then
  if command -v stripe >/dev/null 2>&1 && [ -n "${STRIPE_SECRET_KEY:-}" ]; then
    echo "  Running billing lifecycle boundary probe..."
    bash scripts/billing-lifecycle-test.sh > "${RAW_DIR}/billing_boundary.log" 2>&1 || echo "BILLING_BOUNDARY_FAILURE" > "${RAW_DIR}/billing_boundary.fail"
  fi
fi

echo "✔ [Pillar 4] VAPT checks complete"
