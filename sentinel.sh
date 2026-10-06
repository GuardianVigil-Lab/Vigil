#!/usr/bin/env bash
#
# Sentinel: Compatibility wrapper forwarding to Vigil orchestrator
#

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -f "${SCRIPT_DIR}/vigil.sh" ]; then
  exec "${SCRIPT_DIR}/vigil.sh" "$@"
elif [ -f "/tools/vigil/vigil.sh" ]; then
  exec "/tools/vigil/vigil.sh" "$@"
elif [ -f "/tools/sentinel/vigil.sh" ]; then
  exec "/tools/sentinel/vigil.sh" "$@"
else
  echo "[ERROR] Cannot find vigil.sh orchestrator" >&2
  exit 1
fi
