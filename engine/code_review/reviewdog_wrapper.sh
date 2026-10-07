#!/usr/bin/env bash
#
# Vigil Reviewdog Integration Wrapper
# Translates Vigil PR Review & Anti-Fabrication JSON findings into RDJSON format
# and posts inline GitHub Pull Request review annotations without failing on pre-existing code.
#

set -uo pipefail

WORKSPACE="${WORKSPACE:-$([ -d /workspace ] && [ -w /workspace ] && echo /workspace || pwd)}"
RAW_DIR="${WORKSPACE}/reports/raw"
PR_JSON="${RAW_DIR}/pr_review.json"
RDJSON_FILE="${RAW_DIR}/reviewdog.json"

if [ ! -f "${PR_JSON}" ]; then
  echo "  (No PR review findings at ${PR_JSON}; skipping reviewdog annotation)"
  exit 0
fi

# Convert Vigil JSON to Reviewdog Diagnostic Format (RDJSON)
python3 -c "
import json, sys

with open('${PR_JSON}', 'r') as f:
    items = json.load(f)

diagnostics = []
for it in items:
    sev = 'ERROR' if it.get('severity') in ('P0', 'P1') else 'WARNING'
    diag = {
        'message': f\"[{it.get('severity')}] {it.get('title')}: {it.get('message')}\",
        'location': {
            'path': it.get('file', 'unknown'),
            'range': {
                'start': {'line': int(it.get('line', 1)), 'column': 1}
            }
        },
        'severity': sev,
        'code': {'value': it.get('title', 'VigilReview')}
    }
    if it.get('suggestion'):
        diag['suggestions'] = [{
            'range': {'start': {'line': int(it.get('line', 1)), 'column': 1}},
            'text': it.get('suggestion')
        }]
    diagnostics.append(diag)

rdjson = {
    'source': {
        'name': 'Vigil',
        'url': 'https://github.com/GuardianVigil-Lab/vigil'
    },
    'diagnostics': diagnostics
}

with open('${RDJSON_FILE}', 'w') as f:
    json.dump(rdjson, f, indent=2)
"

if command -v reviewdog >/dev/null 2>&1; then
  echo "  Posting inline annotations via reviewdog..."
  if [ -n "${GITHUB_TOKEN:-}" ] && [ -n "${CI:-}" ]; then
    export REVIEWDOG_GITHUB_API_TOKEN="${GITHUB_TOKEN}"
    reviewdog -f=rdjson -name="Vigil Review" -reporter=github-pr-review < "${RDJSON_FILE}" || true
  else
    echo "  (Running locally / outside CI; printing Reviewdog diff annotations to console)"
    DIFF_CMD="git diff origin/main...HEAD 2>/dev/null || git diff HEAD"
    reviewdog -f=rdjson -diff="${DIFF_CMD}" < "${RDJSON_FILE}" 2>/dev/null || true
  fi
else
  echo "  (reviewdog binary not found in PATH; RDJSON emitted to ${RDJSON_FILE})"
fi
