<div align="center">
  <img src="assets/logo.png" alt="Vigil Logo" width="180" />
  <h1>Vigil</h1>
  <p><strong>All-in-One Autonomous VAPT, Anti-Fabrication Code Review, and Zero-Host Security Engine</strong></p>

  <p>
    <a href="https://github.com/GuardianVigil-Lab/vigil/actions/workflows/ci.yml"><img src="https://github.com/GuardianVigil-Lab/vigil/actions/workflows/ci.yml/badge.svg" alt="CI" /></a>
    <a href="https://github.com/GuardianVigil-Lab/vigil/pkgs/container/vigil"><img src="https://img.shields.io/badge/ghcr.io-guardianvigil--lab%2Fvigil-blue?logo=docker" alt="Docker Image" /></a>
    <a href="LICENSE"><img src="https://img.shields.io/badge/License-Apache_2.0-green.svg" alt="License: Apache 2.0" /></a>
    <a href="docs/CROSS_PLATFORM.md"><img src="https://img.shields.io/badge/Platforms-Linux%20%7C%20macOS%20%7C%20Windows-blueviolet" alt="Platforms" /></a>
    <a href="https://m8ven.ai/mcp/guardianvigil-lab/vigil?s=readme"><img src="https://m8ven.ai/badge/mcp/guardianvigil-lab/vigil" alt="M8ven Score" /></a>
  </p>
</div>

**Vigil** is a unified, local-first enterprise security, VAPT, code quality, and PR review engine (`ghcr.io/guardianvigil-lab/vigil:latest`).

It consolidates what typically requires dozens of disconnected CI tools into a single zero-host-prerequisite container with native Model Context Protocol (MCP) and REST API capabilities:
- **Autonomous AI Penetration Testing**: Bundles [Strix 1.7.0](https://github.com/usestrix/strix) for autonomous vulnerability exploitation and red-team auditing.
- **Nessus-Equivalent Infrastructure Auditing**: Integrates Nmap NSE vulnerability scripts, testssl.sh TLS/cipher analysis, and Nikto web server probes.
- **OWASP Top 10 BOLA / IDOR Testing**: Automated two-token matrix test harness asserting cross-tenant data isolation and authorization refusals.
- **18-Rule Anti-Fabrication Engine**: AST and regex detectors asserting zero synthetic mocks, zero dummy data, and zero disconnected UI handlers.
- **CodeRabbit-Style Semantic PR Reviews**: Diff-scoped analysis producing line-by-line remediation patches and inline GitHub PR annotations via Reviewdog.
- **Containerized Playwright E2E User Personas**: Headless Chromium battery validating authentication, DOM/console errors, form boundary fuzzing, and RBAC isolation without installing browsers on the host.
- **Native MCP Server**: Integrated stdio JSON-RPC 2.0 server (`engine/mcp/vigil_mcp_server.py`) exposing 5 tools for Claude Code, Antigravity, Cursor, and Windsurf (`vigil_fast_scan`, `vigil_security_audit`, `vigil_vapt`, `vigil_review`, `vigil_fix`).
- **REST API & Webhooks**: Lightweight HTTP service (`engine/api/server.py`) with Swagger documentation (`/docs`), automated CI/CD webhooks (`/api/v1/webhook`), and programmatic SARIF retrieval.
- **Mutation Testing**: Integrated Stryker Mutator and go-mutesting to detect broken or undertested business logic.

---

## 1. System Architecture

```
┌────────────────────────────────────────────────────────────────────────────────────────┐
│                      VIGIL (ghcr.io/guardianvigil-lab/vigil:latest)                    │
├────────────────────┬────────────────────┬────────────────────┬─────────────────────────┤
│ Pillar 1 & 2:      │ Pillar 3:          │ Pillar 4:          │ Pillar 5 & 6:           │
│ AST & Code Quality │ SAST, SCA & Secrets│ Deep VAPT & RedTeam│ E2E, MCP, API & Reports │
├────────────────────┼────────────────────┼────────────────────┼─────────────────────────┤
│ • ast-grep (sg)    │ • 18-Rule Anti-    │ • Strix Autonomous │ • Headless Chromium     │
│ • golangci-lint    │   Fabrication AST  │   Red Teamer v1.7.0│   Playwright E2E        │
│ • ruff (Python)    │ • Gitleaks secrets │ • BOLA/IDOR two-   │ • Native MCP Server     │
│ • phpstan Level 8  │ • TruffleHog git   │   token matrix     │ • REST API & Webhooks   │
│ • dependency-cruise│ • Trivy (CVE & SCA)│ • Nmap NSE scripts │ • Stryker Mutator       │
│ • squawk (Postgres)│ • Syft & Grype SBOM│ • testssl.sh cipher│ • Non-root USER 1000    │
│ • knip & deadcode  │ • Semgrep rules    │ • Nikto web server │ • Unified SARIF 2.1.0   │
│ • jscpd duplication│ • Hadolint Docker  │ • Nuclei & Ffuf    │ • Markdown PR reports   │
└────────────────────┴────────────────────┴────────────────────┴─────────────────────────┘
```

---

## 2. Universal 1-Command Installation

Install the `vigil` CLI in seconds on **Linux**, **macOS** (Apple Silicon M-series & Intel), or **Windows WSL2**:

```bash
curl -fsSL https://raw.githubusercontent.com/GuardianVigil-Lab/Vigil/main/install.sh | sh
```

The installer verifies your platform, adds `vigil` to your `$PATH`, and pre-pulls the ultra-lean **Core** image (`ghcr.io/guardianvigil-lab/vigil:core`, ~150MB) with cold-start times of 5–10 seconds.

### Quickstart by Operating System

Navigate to any repository and run:

```bash
# ⚡ Fast developer iteration (< 15 seconds)
vigil fast

# 🛡️ Deep anti-fabrication (18 rules) & secrets audit
vigil security

# 🔍 Full enterprise review (all 6 pillars & SARIF report)
vigil review

# 💻 Running without Docker (host-native execution)
vigil --standalone fast
```

### macOS (Apple Silicon & Intel)
Vigil publishes native multi-arch images (`linux/arm64` and `linux/amd64`) built natively on dedicated ARM64 runners with **Zero QEMU emulation overhead**:
```bash
# Execute via portable runner
vigil fast

# Targeting local server running on your Mac host
TARGET_URL=http://host.docker.internal:3000 vigil vapt
```

### Windows (WSL2 or Native PowerShell)
- **Option A (WSL2 - Recommended)**: Run `curl -fsSL https://raw.githubusercontent.com/GuardianVigil-Lab/Vigil/main/install.sh | sh` inside your WSL2 Ubuntu terminal and run `vigil review`.
- **Option B (Native PowerShell)**: Use Vigil's native PowerShell runner:
  ```powershell
  git clone https://github.com/GuardianVigil-Lab/vigil.git
  cd vigil
  .\bin\vigil.ps1 fast
  .\bin\vigil.ps1 review
  ```

*For complete OS-specific configurations, networking, and filesystem tuning, see the [Cross-Platform Guide](docs/CROSS_PLATFORM.md).*

---

## 3. Battery Modes

Vigil structures audits into targeted, timed batteries:

| Mode | Target Time | Engines Executed | Purpose |
| :--- | :---: | :--- | :--- |
| `fast` | `< 15s` | ast-grep, gitleaks, zizmor, anti-fabrication on changed files, PR diff reviewer | Pre-commit hook & quick PR gate |
| `quality` | `~30s` | golangci-lint, ruff, knip, squawk, phpstan, jscpd (clone detection), PR reviewer | Code health & refactoring |
| `security`| `~45s` | Anti-fabrication (18 rules), gitleaks, trufflehog, trivy, syft/grype, semgrep, hadolint | SAST, SCA, and secret scanning |
| `vapt` | `~2m` | Strix red-teamer, BOLA cross-tenant matrix, Schemathesis, nmap, testssl, nikto, nuclei | Dynamic vulnerability assessment |
| `test` | `~1m` | Vitest, Go unit tests (`-race`), Stryker & go-mutesting mutation testing | Broken functionality & test efficacy |
| `e2e` | `~45s` | Playwright Chromium headless user personas (auth, DOM sweep, form boundary fuzzing) | End-to-end user persona testing |
| `review` | `~3m` | Full execution of all batteries above + SARIF 2.1.0 and Markdown synthesis | Complete pre-release sign-off |
| `full` | `~3m` | All-in-one execution of all 6 batteries (AST, SAST, QA tests, VAPT, SARIF) | Comprehensive single-command gate |

---

## 4. Model Context Protocol (MCP) Server

Vigil includes a native MCP server for AI coding assistants (Claude Code, Cursor, Antigravity, Windsurf).

### Configuration in AI Assistants (`mcp_config.json`):
```json
{
  "mcpServers": {
    "vigil": {
      "command": "python3",
      "args": ["/path/to/vigil/engine/mcp/vigil_mcp_server.py"],
      "env": {
        "PYTHONUNBUFFERED": "1"
      }
    }
  }
}
```

### Exposed MCP Tools:
- `vigil_full_scan(workspace_path, target_url, base_branch, skip_vapt, skip_qa)`: Complete all-in-one execution of all security, QA, VAPT, and review batteries in a single call.
- `vigil_fast_scan(workspace_path, fix_mode)`: Rapid AST invariant & syntax scan (<15s).
- `vigil_security_audit(workspace_path, severity_threshold)`: Anti-fabrication & secret detection.
- `vigil_vapt(target_url, workspace_path, test_matrix)`: BOLA matrix & penetration testing.
- `vigil_review(workspace_path, base_branch, post_comments)`: Automated PR code review & SARIF synthesis.
- `vigil_fix(workspace_path, issue_ids, dry_run)`: Automated remediation for known AST and quality issues.

---

## 5. REST API & Webhook Service

Run the self-contained headless API daemon:
```bash
export VIGIL_API_TOKEN="$(openssl rand -hex 32)"   # omit to get a one-off token printed at startup
export VIGIL_WORKSPACE_ROOT=/srv/repos              # scans may only run inside this directory
python3 engine/api/server.py --port 8080            # binds 127.0.0.1 by default
```
- **Interactive Swagger Documentation**: `http://localhost:8080/docs`
- **OpenAPI 3.0 Specification**: `http://localhost:8080/openapi.json`
- **Trigger Scan**: `POST /api/v1/scan` with `{"battery": "review", "workspace": "my-repo"}`
- **Retrieve SARIF**: `GET /api/v1/scans/{scan_id}/sarif`
- **Retrieve Markdown**: `GET /api/v1/scans/{scan_id}/report`
- **Incoming Webhook**: `POST /api/v1/webhook` (GitHub and GitLab, signed — see below)

Every request except `/api/v1/health`, `/docs` and `/openapi.json` needs
`Authorization: Bearer $VIGIL_API_TOKEN`:

```bash
curl -s -X POST http://127.0.0.1:8080/api/v1/scan \
  -H "Authorization: Bearer $VIGIL_API_TOKEN" -H "Content-Type: application/json" \
  -d '{"battery": "fast", "workspace": "my-repo"}'
```

| Setting | Default | Meaning |
|---|---|---|
| `VIGIL_API_TOKEN` | generated per run | Bearer token for scan and report routes. Required to bind anything but loopback. |
| `--host` / `VIGIL_API_HOST` | `127.0.0.1` | Interface to listen on. |
| `VIGIL_WORKSPACE_ROOT` | `/workspace`, else the current directory | A requested `workspace` must resolve inside it; symlinks out are refused. |
| `VIGIL_WEBHOOK_SECRET` | unset (webhooks off) | GitHub: the webhook secret, checked against `X-Hub-Signature-256`. GitLab: the secret token, checked against `X-Gitlab-Token`. |
| `VIGIL_DEFAULT_WORKSPACE` | `.` | Workspace a webhook scans, relative to the root. |
| `VIGIL_API_MAX_SCANS` | `2` | Concurrent scans; more answer `429`. |

Batteries are limited to `fast`, `quality`, `security`, `vapt`, `test`, `e2e`,
`review` and `full`; requests must be `application/json` and at most 1 MiB. The API
sends no CORS headers, so a web page cannot drive it from a browser.

---

## 6. GitHub Action Integration

Add Vigil to any repository's CI pipeline with `.github/workflows/vigil.yml`:

```yaml
name: Vigil Security & Quality Audit
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  audit:
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      pull-requests: write
    steps:
      - uses: actions/checkout@v4
      - name: Run Vigil Audit
        uses: GuardianVigil-Lab/vigil/action.yml@main
        with:
          battery: 'review'
          fail_on_blocker: 'true'
          sarif_upload: 'true'
          github_token: ${{ secrets.GITHUB_TOKEN }}
```

---

## 7. In-Depth Documentation

Explore Vigil's comprehensive documentation library:

- **[Architecture & Mechanics](docs/ARCHITECTURE.md)**: Deep dive into multi-stage container internals, UID/GID mapping, and caching.
- **[Getting Started & Developer Guide](docs/GETTING_STARTED.md)**: Step-by-step onboarding, CLI flags, and report interpretation.
- **[Cross-Platform Guide: Linux, macOS & Windows](docs/CROSS_PLATFORM.md)**: In-depth setup for Docker Desktop, OrbStack, Colima, WSL2, and PowerShell.
- **[How to Add Tools & Capabilities](docs/HOW_TO_ADD_TOOLS.md)**: Tutorial on adding new linters, security scanners, or test runners.
- **[How to Improve & Tune Vigil](docs/HOW_TO_IMPROVE.md)**: Optimizing scan speed, eliminating false positives, and tuning VAPT depth.
- **[Deep VAPT & Red Teaming Guide](docs/VAPT_GUIDE.md)**: Configuring Strix, BOLA matrix, Nmap, and live API penetration testing.
- **[Code Review & Anti-Fabrication Guide](docs/CODE_REVIEW.md)**: Invariant detection rules, CodeRabbit-style reviews, and Reviewdog.
- **[Containerized Playwright E2E Guide](docs/E2E_TESTING.md)**: Writing headless user personas, DOM error sweeps, and RBAC probes.
- **[Custom Invariant Rules Authoring](docs/CUSTOM_RULES.md)**: Writing ast-grep structural patterns and architectural guards.
- **[CI/CD Integration Guide](docs/CI_INTEGRATION.md)**: GitHub Actions, GitLab CI, Bitbucket Pipelines, and pre-commit hooks.
- **[Global Enterprise Stacks & Compliance Research](docs/RESEARCH_GLOBAL_EXPANSION.md)**: Comprehensive roadmap for Python, Java/Kotlin, Rust, C/C++, Ruby, IaC, and SOC2/ISO27001/HIPAA/PCI-DSS standards.

---

## 8. Security & Fail-Closed Gate Policy

Vigil enforces strict, non-negotiable exit codes:
- **Exit Code `1` (Blocked)**: Triggered on any **P0 (Critical)** or **P1 (High)** finding (e.g., active secret leak, unshielded Server Action, exploitable BOLA, mock data in production).
- **Exit Code `0` (Passed)**: Returned when only **P2 (Medium)**, **P3 (Low)**, or zero findings are detected.

---

## 9. License

Apache License 2.0 — see [LICENSE](LICENSE). Security issues: see [SECURITY.md](SECURITY.md).
