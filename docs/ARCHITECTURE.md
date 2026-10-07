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

## 2. Multi-Target Docker Architecture & Tiering

Vigil is divided into two discrete build targets to optimize cold-start pull speeds and resource consumption:

### Target: `core` (~150MB compressed / 346MB uncompressed)
- **Base**: `debian:bookworm-slim` with minimal utilities (`ca-certificates`, `curl`, `git`, `jq`, `gosu`, `docker.io`, `python3`).
- **Pre-compiled static binaries**: `ast-grep` (sg), `gitleaks`, `trufflehog`, `zizmor`, `squawk` (v2.67.0+), `hadolint`, `trivy`, `syft`, `grype`.
- **Python Engines**: 18 anti-fabrication AST invariant rules (`engine/anti_fabrication/detector.py`), diff reviewer (`engine/code_review/pr_reviewer.py`), and SARIF 2.1.0 synthesizer (`engine/synthesizer/parse_results.py`).
- **Footprint**: Cold-start download in 5–10 seconds, RAM usage < 150MB. Zero Chromium, zero Node.js runtime, zero PHP, zero Go compiler.

### Target: `full` (~1.2GB compressed)
- **Base**: Inherits directly from `core` (`FROM core AS full`).
- **Compilers & Runtimes**: Node.js 26.x, Go 1.27.1, PHP 8.2 CLI, Perl, Nmap.
- **Dynamic VAPT & Red Teaming**: Strix autonomous AI red team orchestrator, BOLA/IDOR two-token matrix, Nuclei, Ffuf, Oasdiff, Dockle, Toxiproxy, Nikto, testssl.sh, Reviewdog.
- **Testing & Mutation Engines**: Headless Chromium + Playwright 1.48, Stryker Mutator, Vitest runner, `go-mutesting`, `golangci-lint`, `nilaway`, `gosec`, `govulncheck`, `deadcode`, `ruff`, `vulture`, `schemathesis`, `semgrep`.

---

## 3. Zero-QEMU Native Multi-Arch Publishing Pipeline

To completely eliminate slow CPU emulation bottlenecks, Vigil leverages GitHub Actions native hardware runners:

```
┌─────────────────────────────────┐       ┌─────────────────────────────────┐
│ Job 1: Native AMD64 Runner      │       │ Job 2: Native ARM64 Runner      │
│ runs-on: ubuntu-latest          │       │ runs-on: ubuntu-24.04-arm       │
├─────────────────────────────────┤       ├─────────────────────────────────┤
│ • Build & Push core-amd64       │       │ • Build & Push core-arm64       │
│ • Build & Push full-amd64       │       │ • Build & Push full-arm64       │
└────────────────┬────────────────┘       └────────────────┬────────────────┘
                 │                                         │
                 └────────────────────┬────────────────────┘
                                      ▼
                   ┌──────────────────────────────────────┐
                   │ Job 3: Manifest Merging (2 seconds)  │
                   │ runs-on: ubuntu-latest               │
                   ├──────────────────────────────────────┤
                   │ docker buildx imagetools create:     │
                   │   ghcr.io/.../vigil:core             │
                   │   ghcr.io/.../vigil:latest           │
                   └──────────────────────────────────────┘
```

1. **Native AMD64 Build**: Runs on `ubuntu-latest` without emulation.
2. **Native ARM64 Build**: Runs on `ubuntu-24.04-arm` (GitHub-hosted 4-core ARM64 hardware) with 0% QEMU overhead.
3. **Manifest Creation**: `docker buildx imagetools create` fetches the pre-pushed layer digests and publishes the multi-arch OCI manifest list in under 3 seconds.

---

## 4. Smart Host CLI Routing (`bin/vigil`)

The `vigil` CLI automatically routes tasks without user intervention:
- **Fast / Quality / Security**: Dispatches to `ghcr.io/guardianvigil-lab/vigil:core` for instant feedback.
- **VAPT / Test / E2E / Review**: Routes to `ghcr.io/guardianvigil-lab/vigil:latest` / `:full`.
- **Standalone Fallback**: When invoked with `--standalone` (or if Docker is absent), executes directly on the host using local scripts.
- **Non-Freezing Fallback**: Checks remote registries before considering local builds; never triggers unrequested local image compilation.

---

## 3. Findings Normalization & Exit Codes

Vigil normalizes all findings into a strict four-tier hierarchy:

- **P0 (Critical Blocker)**: Exploitable BOLA/IDOR, hardcoded secrets/credentials, SQL injection vectors, or fabricated security verdicts. **Causes immediate exit code 1**.
- **P1 (High Severity)**: Unhandled exceptions on public routes, failing unit/mutation tests, insecure cookie flags, missing Server Action operator guards, high-severity CVEs with known exploits. **Causes immediate exit code 1**.
- **P2 (Medium / Advisory)**: Copy-paste duplication (> 3%), dead code, high cyclomatic complexity (> 15), missing error handling in Go. Non-blocking in fast mode.
- **P3 (Low / Informational)**: Styling suggestions, formatting hints, missing docstrings.
