#!/usr/bin/env bash
#
# Vigil Infrastructure & Transport Security Auditor (Nessus-Equivalent)
# Orchestrates nmap (service & NSE vuln scan), testssl.sh (ciphers & TLS), and nikto (web server).
#

set -uo pipefail

TARGET_TLS="${TARGET_TLS:-0}"
if [ -n "${TARGET_URL:-}" ]; then
  PARSED=$(python3 -c "
import urllib.parse, sys
u = urllib.parse.urlparse(sys.argv[1])
scheme = u.scheme or 'http'
host = u.hostname or '127.0.0.1'
port = u.port or (443 if scheme == 'https' else 80)
tls = '1' if scheme == 'https' else '0'
print(f'{host} {port} {tls}')
" "${TARGET_URL}" 2>/dev/null || echo "")
  if [ -n "${PARSED}" ]; then
    read -r TH TP TT <<< "${PARSED}"
    TARGET_HOST="${TH}"
    TARGET_PORT="${TP}"
    TARGET_TLS="${TT}"
  fi
fi

TARGET_HOST="${TARGET_HOST:-127.0.0.1}"
TARGET_PORT="${TARGET_PORT:-3000}"
RAW_DIR="/workspace/reports/raw"
mkdir -p "${RAW_DIR}"

echo "▶ [Infra Scanner] Infrastructure & Transport Auditing (Host: ${TARGET_HOST}:${TARGET_PORT})"

# Detect if target port is open
PORT_OPEN=0
if command -v nc >/dev/null 2>&1; then
  nc -z -w 2 "${TARGET_HOST}" "${TARGET_PORT}" 2>/dev/null && PORT_OPEN=1 || true
elif (echo > /dev/tcp/"${TARGET_HOST}"/"${TARGET_PORT}") >/dev/null 2>&1; then
  PORT_OPEN=1
fi

# 1. Nmap Service & Vulnerability Scan
if command -v nmap >/dev/null 2>&1; then
  echo "  Running nmap service discovery and NSE vulnerability scripts..."
  if [ ${PORT_OPEN} -eq 1 ]; then
    nmap -sV --script "banner,vulners" -p "${TARGET_PORT}" -oX "${RAW_DIR}/nmap.xml" "${TARGET_HOST}" >/dev/null 2>&1 || true
  else
    echo "  (Port ${TARGET_PORT} not open on ${TARGET_HOST}; running local network surface audit)"
    nmap -sV -F -oX "${RAW_DIR}/nmap.xml" "${TARGET_HOST}" >/dev/null 2>&1 || true
  fi
else
  echo "  (nmap not available in environment; skipping network port audit)"
fi

# 2. testssl.sh Cipher Suite & TLS Audit
TESTSSL_BIN="$(command -v testssl.sh || command -v testssl || echo "/usr/local/bin/testssl.sh")"
if [ -x "${TESTSSL_BIN}" ]; then
  # Only run if TLS port (443, 8443) or explicit HTTPS target
  if [ "${TARGET_PORT}" = "443" ] || [ "${TARGET_PORT}" = "8443" ] || [ "${TARGET_TLS:-0}" = "1" ]; then
    echo "  Running testssl.sh TLS/SSL protocol and cipher suite audit..."
    "${TESTSSL_BIN}" --quiet --jsonfile-pretty "${RAW_DIR}/testssl.json" "${TARGET_HOST}:${TARGET_PORT}" >/dev/null 2>&1 || true
  else
    echo "  (Target ${TARGET_HOST}:${TARGET_PORT} is plain HTTP; recording TLS enforcement advisory)"
    cat <<TESTSSL_EOF > "${RAW_DIR}/testssl.json"
[
  {
    "id": "TLS-ENFORCEMENT-MISSING",
    "severity": "MEDIUM",
    "finding": "Target service exposed on unencrypted plain HTTP transport",
    "target": "${TARGET_HOST}:${TARGET_PORT}"
  }
]
TESTSSL_EOF
  fi
fi

# 3. Nikto Web Server Security Audit
NIKTO_BIN="$(command -v nikto || command -v nikto.pl || echo "/usr/local/bin/nikto")"
if [ -x "${NIKTO_BIN}" ]; then
  if [ ${PORT_OPEN} -eq 1 ]; then
    echo "  Running nikto web server misconfiguration audit..."
    perl "${NIKTO_BIN}" -host "${TARGET_HOST}" -port "${TARGET_PORT}" -Format json -output "${RAW_DIR}/nikto.json" -Tuning 123b >/dev/null 2>&1 || true
  else
    echo "  (Target server offline; skipping active nikto HTTP checks)"
  fi
fi

echo "✔ [Infra Scanner] Infrastructure audit complete"
