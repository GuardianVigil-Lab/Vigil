#!/usr/bin/env bash
#
# Pillar 3 Runner: Deep SAST, SCA, Secrets & Anti-Fabrication Hardening
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

echo "▶ [Pillar 3] Deep SAST, SCA, Secrets & Anti-Fabrication Hardening"

git config --global --add safe.directory '*' 2>/dev/null || true

# 1. Anti-Fabrication & Fake Functionality Engine
if [ -f "${TOOL_ROOT}/engine/anti_fabrication/detector.py" ]; then
  echo "  Running anti-fabrication & fake functionality detector (18 rules)..."
  python3 "${TOOL_ROOT}/engine/anti_fabrication/detector.py" --json-out="${RAW_DIR}/anti_fabrication.json" > "${RAW_DIR}/anti_fabrication.log" 2>&1 || true
fi

# 2. Gitleaks Secrets Scanning
if command -v gitleaks >/dev/null 2>&1; then
  echo "  Running gitleaks secrets detection..."
  if [ -d ".git" ]; then
    gitleaks git --no-banner --report-format json --report-path "${RAW_DIR}/gitleaks.json" >/dev/null 2>&1 || true
  else
    gitleaks detect --no-git --report-format json --report-path "${RAW_DIR}/gitleaks.json" >/dev/null 2>&1 || true
  fi
fi

# 3. TruffleHog Verification
if command -v trufflehog >/dev/null 2>&1; then
  echo "  Running trufflehog credential scanner..."
  trufflehog filesystem --json . --exclude-paths=.git,node_modules,.venv,testdata,reports > "${RAW_DIR}/trufflehog.json" 2>/dev/null || true
fi

# 4. Trivy Vulnerability & IaC Scanning
if command -v trivy >/dev/null 2>&1; then
  echo "  Running trivy filesystem and configuration scan..."
  trivy fs --skip-dirs reports --format json -o "${RAW_DIR}/trivy.json" --scanners vuln,secret,config . >/dev/null 2>&1 || true
fi

# 5. Syft SBOM Generation & Grype Vulnerability Matching
if command -v syft >/dev/null 2>&1; then
  echo "  Generating CycloneDX/SPDX SBOM via syft..."
  syft dir:. --exclude "reports/**" -o json > "${RAW_DIR}/syft.json" 2>/dev/null || true

  if command -v grype >/dev/null 2>&1 && [ -s "${RAW_DIR}/syft.json" ]; then
    echo "  Running grype against generated SBOM..."
    grype "${RAW_DIR}/syft.json" -o json > "${RAW_DIR}/grype.json" 2>/dev/null || true
  fi
fi

# 6. Go Security: govulncheck & gosec
GO_MODULES=$(find . -name "go.mod" -not -path "*/node_modules/*" -not -path "*/vendor/*" -exec dirname {} \; 2>/dev/null | sort)
if [ -n "${GO_MODULES}" ]; then
  if command -v govulncheck >/dev/null 2>&1; then
    echo "  Running govulncheck on Go call graphs..."
    for mod in ${GO_MODULES}; do
      mod_name=$(echo "${mod}" | sed 's|^\./||; s|/|_|g')
      (
        cd "${mod}"
        govulncheck -json ./... > "${RAW_DIR}/govulncheck_${mod_name}.json" 2>/dev/null || true
      )
    done
  fi

  if command -v gosec >/dev/null 2>&1; then
    echo "  Running gosec AST SAST scanner..."
    for mod in ${GO_MODULES}; do
      mod_name=$(echo "${mod}" | sed 's|^\./||; s|/|_|g')
      (
        cd "${mod}"
        gosec -fmt=json -out="${RAW_DIR}/gosec_${mod_name}.json" ./... >/dev/null 2>&1 || true
      )
    done
  fi
fi

# 7. Semgrep SAST
if command -v semgrep >/dev/null 2>&1; then
  echo "  Running semgrep SAST rules..."
  semgrep scan --config auto --json --output "${RAW_DIR}/semgrep.json" --exclude "reports" --quiet . >/dev/null 2>&1 || true
fi

# 8. Multi-Tenant Scoping Gate
if [ -f "scripts/check-tenant-scoping.py" ]; then
  echo "  Running check-tenant-scoping.py..."
  python3 scripts/check-tenant-scoping.py > "${RAW_DIR}/tenant_scoping.log" 2>&1 || echo "TENANT_SCOPING_FAILURE" > "${RAW_DIR}/tenant_scoping.fail"
fi

echo "✔ [Pillar 3] Security scanning complete"
