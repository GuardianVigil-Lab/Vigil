#!/usr/bin/env bash
set -e

export HOME="/home/vigil"
export GOPATH="${GOPATH:-/home/vigil/go}"
export GOCACHE="${GOCACHE:-/home/vigil/.cache/go-build}"
export PLAYWRIGHT_BROWSERS_PATH="${PLAYWRIGHT_BROWSERS_PATH:-/ms-playwright}"
mkdir -p "${GOPATH}" "${GOCACHE}" 2>/dev/null || true

# If running as root, detect host workspace UID/GID and drop privileges with gosu
if [ "$(id -u)" -eq 0 ]; then
  WORKSPACE_UID=$(stat -c '%u' /workspace 2>/dev/null || echo 1000)
  WORKSPACE_GID=$(stat -c '%g' /workspace 2>/dev/null || echo 1000)
  if [ "${WORKSPACE_UID}" -eq 0 ]; then
    WORKSPACE_UID=1000
    WORKSPACE_GID=1000
  fi
  VIGIL_UID="${VIGIL_UID:-$WORKSPACE_UID}"
  VIGIL_GID="${VIGIL_GID:-$WORKSPACE_GID}"

  if ! getent group "${VIGIL_GID}" >/dev/null 2>&1; then
    groupmod -g "${VIGIL_GID}" vigilgroup 2>/dev/null || groupadd -g "${VIGIL_GID}" vigilgroup 2>/dev/null || true
  fi

  if ! getent passwd "${VIGIL_UID}" >/dev/null 2>&1; then
    usermod -u "${VIGIL_UID}" -g "${VIGIL_GID}" vigiluser 2>/dev/null || useradd -u "${VIGIL_UID}" -g "${VIGIL_GID}" -d /home/vigil -s /bin/bash vigiluser 2>/dev/null || true
  fi

  # Map docker socket group if available for DooD
  if [ -S /var/run/docker.sock ]; then
    DOCKER_GID=$(stat -c '%g' /var/run/docker.sock 2>/dev/null || true)
    if [ -n "${DOCKER_GID}" ] && [ "${DOCKER_GID}" -ne 0 ]; then
      if ! getent group "${DOCKER_GID}" >/dev/null 2>&1; then
        groupadd -g "${DOCKER_GID}" dockergroup 2>/dev/null || true
      fi
      usermod -aG "${DOCKER_GID}" vigiluser 2>/dev/null || true
    fi
  fi

  chown -R "${VIGIL_UID}:${VIGIL_GID}" /home/vigil 2>/dev/null || true
  mkdir -p /workspace/reports
  chown -R "${VIGIL_UID}:${VIGIL_GID}" /workspace/reports 2>/dev/null || true

  RUNNER="/tools/vigil/vigil.sh"

  if [ "$#" -eq 0 ]; then
    exec gosu vigiluser "${RUNNER}" review
  elif [ "$1" = "fast" ] || [ "$1" = "quality" ] || [ "$1" = "security" ] || [ "$1" = "vapt" ] || [ "$1" = "test" ] || [ "$1" = "e2e" ] || [ "$1" = "review" ] || [ "$1" = "all" ]; then
    exec gosu vigiluser "${RUNNER}" "$@"
  elif [ "$1" = "--help" ] || [ "$1" = "-h" ] || [ "$1" = "help" ]; then
    exec gosu vigiluser /tools/vigil/bin/vigil --help
  else
    exec gosu vigiluser "$@"
  fi
fi

# Direct non-root execution
mkdir -p /workspace/reports 2>/dev/null || true

RUNNER="/tools/vigil/vigil.sh"

if [ "$#" -eq 0 ]; then
  exec "${RUNNER}" review
elif [ "$1" = "fast" ] || [ "$1" = "quality" ] || [ "$1" = "security" ] || [ "$1" = "vapt" ] || [ "$1" = "test" ] || [ "$1" = "e2e" ] || [ "$1" = "review" ] || [ "$1" = "all" ]; then
  exec "${RUNNER}" "$@"
elif [ "$1" = "--help" ] || [ "$1" = "-h" ] || [ "$1" = "help" ]; then
  exec /tools/vigil/bin/vigil --help
else
  exec "$@"
fi
