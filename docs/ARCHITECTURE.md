# Vigil Architecture & Execution Mechanics

Vigil is designed around zero-host dependencies, reproducible artifact generation, and fail-closed security invariants.

---

## 1. Container Topology & Privileges

```
Host Filesystem (Developer / CI Machine)
  ├── Source Code: /path/to/project
  ├── Docker Daemon: /var/run/docker.sock
  └── Cache: ~/.cache/vigil
       │
       ▼ [Volume Mount & DooD Bridge]
Vigil Container (debian:bookworm-slim)
  ├── User: vigiluser (mapped dynamically to host UID:GID via gosu)
  ├── Group: dockergroup (mapped dynamically to host docker.sock GID)
  ├── PATH: /usr/local/bin, /usr/local/go/bin, /tools/vigil
  ├── /workspace (Mounted host workspace)
  └── /tools/vigil (Vigil internals & runners)
```

### Docker-outside-of-Docker (DooD) Mechanics
Autonomous engines like Strix run sandbox containers to execute exploits safely without compromising the main testing environment.
When running inside a container, mounting `/workspace` into a nested child container fails because the host Docker daemon only understands host paths.

Vigil solves this via **Host Workspace Path Translation**:
1. Host runner `bin/vigil` exports `VIGIL_HOST_WORKSPACE="$(pwd)"`.
2. `strix_orchestrator.py` translates internal `/workspace/...` paths back to `${VIGIL_HOST_WORKSPACE}/...` before issuing Docker API requests.
3. Nested sandbox containers successfully mount project files directly from the host.

---

## 2. Multi-Stage Build Architecture

- **Stage 1 (Extractor)**:
  - Fetches pre-compiled static binaries: Hadolint, Zizmor, Gitleaks, TruffleHog, Syft, Grype, Trivy, Ast-Grep, Squawk, Nuclei, Ffuf, Oasdiff, Dockle, Toxiproxy, Reviewdog, Strix, Nikto, testssl.sh, and PHAR archives.
  - Ensures clean separation of build-time fetch dependencies from the final minimal image.
- **Stage 2 (Runtime)**:
  - Base: Debian Bookworm Slim with minimal glibc, curl, git, python3-dev, build-essential.
  - Node.js 26.x + Go 1.27.1 runtime.
  - Playwright Chromium headless engine and fonts (`/ms-playwright`).
  - Analysis tools: `golangci-lint`, `govulncheck`, `gosec`, `deadcode`, `nilaway`, `go-mutesting`, `ruff`, `vulture`, `schemathesis`, `semgrep`, `oxlint`, `knip`, `jscpd`.
  - Drops root privileges via `gosu` in `entrypoint.sh`.

---

## 3. Findings Normalization & Exit Codes

Vigil normalizes all findings into a strict four-tier hierarchy:

- **P0 (Critical Blocker)**: Exploitable BOLA/IDOR, hardcoded secrets/credentials, SQL injection vectors, or fabricated security verdicts. **Causes immediate exit code 1**.
- **P1 (High Severity)**: Unhandled exceptions on public routes, failing unit/mutation tests, insecure cookie flags, missing Server Action operator guards, high-severity CVEs with known exploits. **Causes immediate exit code 1**.
- **P2 (Medium / Advisory)**: Copy-paste duplication (> 3%), dead code, high cyclomatic complexity (> 15), missing error handling in Go. Non-blocking in fast mode.
- **P3 (Low / Informational)**: Styling suggestions, formatting hints, missing docstrings.
