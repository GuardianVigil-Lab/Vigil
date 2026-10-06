# Cross-Platform Execution Guide: Linux, macOS, and Windows

Vigil is designed as a **zero-host-dependency containerized engine**. Because all language toolchains (Go 1.27.1, Node.js 26.x, Python 3.11, PHP 8.2, Chromium headless, and 20+ security binaries) are encapsulated inside the container, you never need to install language runtimes or security tools on your host machine.

However, operating systems handle container virtualization, filesystem mounts, user IDs, and local networking differently. This guide provides in-depth, production-tested instructions for running Vigil on **Linux**, **macOS**, and **Windows**.

---

## Operating System Matrix

| Feature | Linux | macOS (Apple Silicon & Intel) | Windows (WSL2) | Windows (PowerShell) |
| :--- | :--- | :--- | :--- | :--- |
| **Runner Script** | `bin/vigil` | `bin/vigil` | `bin/vigil` | `bin/vigil.ps1` |
| **Container Engine** | Native Docker / Podman | Docker Desktop / OrbStack / Colima | Docker Desktop (WSL2 Backend) / Docker Engine | Docker Desktop |
| **Architecture** | Native `amd64` / `arm64` | Native `arm64` (Apple Silicon) / `amd64` | Native `amd64` / `arm64` | `amd64` |
| **Network Mode** | Direct `--network host` | Bridge with `host.docker.internal` | Direct host / Bridge | Bridge with `host.docker.internal` |
| **File Permissions** | Automatic UID:GID mapping | Automatic UID:GID mapping | Automatic UID:GID mapping | Windows ACL to Linux User |
| **Execution Speed** | ⚡ Fastest (native) | ⚡ Fast (native via ARM64 build) | ⚡ Fast (native Linux VHD) | Moderate (Hyper-V 9P bind) |

---

## 1. Linux (Ubuntu, Debian, Fedora, Arch, RHEL)

Linux is Vigil's primary native execution environment. Vigil shares the host kernel directly with zero virtualization overhead.

### Prerequisites
1. **Docker Engine** (version 20.10+):
   ```bash
   # Ubuntu / Debian
   sudo apt-get update && sudo apt-get install -y docker.io
   # Fedora / RHEL
   sudo dnf install -y docker-ce
   # Arch Linux
   sudo pacman -S docker
   ```
2. **Grant Non-Root Docker Access**:
   Ensure your current user is in the `docker` supplementary group to avoid requiring `sudo`:
   ```bash
   sudo usermod -aG docker $USER
   newgrp docker
   ```

### Execution
Run directly from your repository root using `bin/vigil`:
```bash
# Fast developer check (< 15 seconds)
./bin/vigil fast

# Full audit battery
./bin/vigil review

# Dynamic VAPT against a local service running on port 3000
./bin/vigil vapt
```

### Linux Key Mechanics
- **Native Host Networking (`--network host`)**: On Linux, `--network host` attaches the container directly to the host network stack. If your local Next.js frontend or Go service is listening on `localhost:3000` or `127.0.0.1:8080`, Vigil's VAPT and Playwright engines can reach it immediately with zero port forwarding.
- **Ambient UID/GID Preservation**: Vigil automatically forwards your host user identity (`-u $(id -u):$(id -g)`) and executes via `entrypoint.sh` using `gosu`. Any generated reports in `./reports/` are owned by your host user account, preventing annoying `root`-owned file permission issues.
- **Docker-outside-of-Docker (DooD)**: When running tools like Strix that orchestrate auxiliary test containers, Vigil mounts `/var/run/docker.sock` and translates paths using `VIGIL_HOST_WORKSPACE="$(pwd)"`.

---

## 2. macOS (Apple Silicon M1/M2/M3/M4 & Intel)

macOS runs Docker containers inside a lightweight Linux hypervisor. Vigil provides first-class support for both Apple Silicon (`arm64`) and Intel (`amd64`).

### Recommended Container Runtimes
You can use any of the following container runtimes on macOS:
1. **OrbStack (Fastest & Most Lightweight)**:
   ```bash
   brew install --cask orbstack
   ```
2. **Docker Desktop for Mac**:
   ```bash
   brew install --cask docker
   ```
3. **Colima (Free, Open-Source CLI Runtime)**:
   ```bash
   brew install colima docker
   colima start --cpu 4 --memory 8
   ```

### Architecture & Emulation
- Vigil publishes multi-arch container images to GHCR supporting both `linux/arm64` and `linux/amd64`.
- On Apple Silicon (M1/M2/M3/M4), Docker will automatically pull the native `arm64` image. **No Rosetta 2 emulation is required**, delivering full native performance.
- To verify you are running natively on ARM64:
  ```bash
  docker run --rm ghcr.io/guardianvigil-lab/vigil:latest uname -m
  # Should output: aarch64
  ```

### macOS Localhost & Network Resolution
> [!IMPORTANT]
> On macOS, the Docker container runs inside a lightweight VM. Therefore, `--network host` binds to the **VM's** localhost, not your macOS Mac host.

When targeting local servers running on your Mac host (such as a Next.js app running on `npm run dev` on port 3000):
- **Use `host.docker.internal` instead of `localhost`**:
  ```bash
  TARGET_URL=http://host.docker.internal:3000 ./bin/vigil vapt
  ```
- Vigil's VAPT runners (`strix_orchestrator.py`, `infra_scanner.sh`, and `bola_matrix.py`) automatically detect when `host.docker.internal` is provided and route traffic across the macOS hypervisor bridge.

### macOS Socket Permissions & stat
macOS uses BSD `stat` (`stat -f '%g'`) rather than GNU `stat` (`stat -c '%g'`). The `bin/vigil` launcher automatically detects Darwin and uses the appropriate flag:
```bash
if [[ "$(uname -s)" == "Darwin" ]]; then
  DOCKER_GID=$(stat -f '%g' /var/run/docker.sock 2>/dev/null || echo 0)
fi
```

### Filesystem Performance
To ensure blazing fast performance when mounting large codebases with `node_modules`:
- In Docker Desktop: Enable **VirtioFS** in *Settings -> General -> Virtual file sharing implementation*.
- In OrbStack: Native VirtioFS is enabled by default.

---

## 3. Windows (WSL2 & Native PowerShell)

Windows developers can run Vigil in two ways: **WSL2** (Recommended for peak performance) or **Native PowerShell**.

### Option A: Windows Subsystem for Linux (WSL2 - Strongly Recommended)

WSL2 provides a real Linux kernel running side-by-side with Windows, offering identical performance and path semantics to Linux.

#### Step 1: Install WSL2 & Ubuntu
Open PowerShell as Administrator:
```powershell
wsl --install -d Ubuntu
```
Reboot your computer when prompted.

#### Step 2: Configure Docker Desktop for WSL2
1. Install [Docker Desktop for Windows](https://www.docker.com/products/docker-desktop/).
2. Open Docker Desktop Settings -> **General** -> check **Use the WSL 2 based engine**.
3. Go to **Resources** -> **WSL Integration** -> enable integration for your **Ubuntu** distro.

#### Step 3: Run Vigil inside WSL2
Open your Ubuntu terminal and navigate to your project (store your projects inside the WSL filesystem, e.g. `~/projects/`, for 10x faster I/O compared to `/mnt/c/`):
```bash
cd ~/projects/my-app
./bin/vigil fast
```

---

### Option B: Native Windows PowerShell (`bin/vigil.ps1`)

If you prefer working directly in Windows PowerShell without opening a Linux shell, Vigil bundles a native PowerShell runner: `bin\vigil.ps1`.

#### Step 1: Ensure Docker Desktop is Running
Verify Docker is accessible from PowerShell:
```powershell
docker version
```

#### Step 2: Run Vigil Batteries
From PowerShell or Windows Terminal in your repository directory:

```powershell
# Fast developer check
.\bin\vigil.ps1 fast

# Full code review & security report
.\bin\vigil.ps1 review

# Autonomous VAPT
.\bin\vigil.ps1 vapt

# Interactive debugging shell inside container
.\bin\vigil.ps1 -Shell

# Rebuild local container image
.\bin\vigil.ps1 -Build
```

#### Windows PowerShell Technical Details
- **Path Translation**: `vigil.ps1` automatically converts Windows backslash paths (`C:\Users\Name\Projects\app`) into forward-slash Docker volume paths (`C:/Users/Name/Projects/app`) and maps them to `/workspace`.
- **Cache Persistence**: The host cache is stored at `$env:USERPROFILE\.cache\vigil` and mounted into `/home/vigil/.cache`.
- **Target URL resolution**: To probe a server running on Windows localhost from inside the container, use:
  ```powershell
  $env:TARGET_URL = "http://host.docker.internal:3000"
  .\bin\vigil.ps1 vapt
  ```

---

## 4. Troubleshooting Cross-Platform Issues

### Issue 1: `permission denied` on `/var/run/docker.sock`
- **Cause**: The host user does not belong to the docker group.
- **Fix (Linux)**: `sudo usermod -aG docker $USER` and log out/in.
- **Fix (macOS/Windows)**: Verify Docker Desktop settings -> *Advanced* -> ensure default Docker socket `/var/run/docker.sock` is enabled.

### Issue 2: Line Endings (`CRLF` vs `LF`) on Windows
- **Cause**: Git on Windows may check out `.sh` files with Windows `\r\n` line breaks.
- **Fix**: Configure git to preserve Linux line endings:
  ```powershell
  git config core.autocrlf input
  git checkout-index --force --all
  ```
  Vigil's `.gitattributes` already enforces `* text=auto eol=lf` across all shell scripts.

### Issue 3: High Memory / OOM during Playwright or Mutation Testing
- **Linux**: Memory uses host RAM directly.
- **macOS / Windows**: Allocate at least **4 GB of RAM** to Docker Desktop / OrbStack / WSL2 in their resource settings. Vigil sets `--shm-size=2gb` to prevent Chromium renderer crashes during headless browser operations.
