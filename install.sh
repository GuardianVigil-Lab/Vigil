#!/usr/bin/env sh
#
# Vigil 1-Command Universal Installer
# Supports: Linux (x86_64, aarch64/arm64), macOS (Apple Silicon M-series & Intel), Windows WSL2
#
# Usage:
#   curl -fsSL https://raw.githubusercontent.com/GuardianVigil-Lab/Vigil/main/install.sh | sh
#   or locally: ./install.sh
#

set -eu

echo "╔════════════════════════════════════════════════════════════════════╗"
echo "║          VIGIL — Security, VAPT & Review Engine Installer          ║"
echo "╚════════════════════════════════════════════════════════════════════╝"
echo ""

# 1. Platform Detection
OS="$(uname -s)"
ARCH="$(uname -m)"

IS_WSL=false
if [ -f /proc/version ] && grep -qi "microsoft" /proc/version; then
  IS_WSL=true
fi

PLATFORM_DESC="${OS} (${ARCH})"
if [ "$IS_WSL" = true ]; then
  PLATFORM_DESC="${PLATFORM_DESC} [WSL2]"
fi
echo "✔ Detected platform: ${PLATFORM_DESC}"

# 2. Determine target install directory
TARGET_DIR="${INSTALL_DIR:-}"
if [ -z "${TARGET_DIR}" ]; then
  if [ "$(id -u)" -eq 0 ]; then
    TARGET_DIR="/usr/local/bin"
  elif [ -w "/usr/local/bin" ]; then
    TARGET_DIR="/usr/local/bin"
  else
    TARGET_DIR="${HOME}/.local/bin"
  fi
fi

mkdir -p "${TARGET_DIR}"
TARGET_BIN="${TARGET_DIR}/vigil"

# 3. Install CLI binary
SCRIPT_DIR="$(cd "$(dirname "$0")" 2>/dev/null && pwd || echo "")"
if [ -n "${SCRIPT_DIR}" ] && [ -f "${SCRIPT_DIR}/bin/vigil" ]; then
  echo "Installing Vigil CLI from local repository to ${TARGET_BIN}..."
  cp "${SCRIPT_DIR}/bin/vigil" "${TARGET_BIN}"
else
  REPO_RAW_URL="${VIGIL_RAW_URL:-https://raw.githubusercontent.com/GuardianVigil-Lab/Vigil/main}"
  echo "Downloading Vigil CLI from ${REPO_RAW_URL}/bin/vigil to ${TARGET_BIN}..."
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "${REPO_RAW_URL}/bin/vigil" -o "${TARGET_BIN}"
  elif command -v wget >/dev/null 2>&1; then
    wget -qO "${TARGET_BIN}" "${REPO_RAW_URL}/bin/vigil"
  else
    echo "Error: Neither curl nor wget was found in PATH." >&2
    exit 1
  fi
fi

chmod +x "${TARGET_BIN}"
echo "✔ Installed Vigil CLI binary at ${TARGET_BIN}"

# 4. Check Docker & Pre-pull Core Image
CORE_IMAGE="ghcr.io/guardianvigil-lab/vigil:core"
if command -v docker >/dev/null 2>&1; then
  if docker info >/dev/null 2>&1; then
    echo "✔ Docker daemon is active."
    echo "Pulling lean core image (${CORE_IMAGE})..."
    if docker pull "${CORE_IMAGE}"; then
      echo "✔ Core image successfully pulled."
    else
      echo "⚠ Notice: Could not pull ${CORE_IMAGE}. It will be pulled on first run or can be built locally with 'vigil --build core'."
    fi
  else
    echo "⚠ Docker is installed but the Docker daemon does not appear to be running."
    echo "  Start Docker Desktop or 'sudo systemctl start docker' to use containerized batteries."
  fi
else
  echo "⚠ Docker was not found in PATH."
  echo "  You can run host-native audits using: vigil --standalone [battery]"
  echo "  To use containerized batteries, install Docker: https://docs.docker.com/get-docker/"
fi

# 5. PATH Verification
case ":${PATH}:" in
  *":${TARGET_DIR}:"*) ;;
  *)
    echo ""
    echo "⚠ Notice: ${TARGET_DIR} is not in your \$PATH."
    echo "  Add the following line to your ~/.bashrc, ~/.zshrc, or ~/.profile:"
    echo "    export PATH=\"${TARGET_DIR}:\$PATH\""
    ;;
esac

echo ""
echo "════════════════════════════════════════════════════════════════════"
echo "  Vigil installed successfully! 🎉"
echo "  Run 'vigil --help' to get started."
echo "════════════════════════════════════════════════════════════════════"
