# Getting Started with Vigil

Welcome to Vigil. This guide covers everything you need to know to install, run, configure, and interpret audits using Vigil across any repository in your organization.

---

## 1. What is Vigil?

Vigil is a **zero-host-dependency containerized engine** that performs comprehensive code quality, security analysis, penetration testing, and user verification without requiring any developer on your team to manually install dozens of disparate tools.

Inside a single, standardized container, Vigil bundles:
- **Language Runtimes**: Node.js 26.x, Go 1.27.1, Python 3.11, PHP 8.2 CLI, Perl.
- **Browser Automation**: Pre-installed Chromium headless and Playwright.
- **Security & SAST**: Gitleaks, TruffleHog, Trivy, Grype, Syft SBOM, Hadolint, Zizmor, Semgrep, and 18 custom AST anti-fabrication rules.
- **Dynamic VAPT**: Strix autonomous AI agent, automated 2-token BOLA/IDOR matrix, Nmap NSE vulnerability scripts, testssl.sh TLS/cipher analyzer, Nikto web server auditor, and Nuclei.
- **Code Health & Quality**: ast-grep, golangci-lint, ruff, knip, squawk (Postgres zero-downtime migrations), phpstan, and jscpd clone detection.
- **Reporting Synthesizer**: Unified P0-P3 taxonomy, GitHub-compatible SARIF 2.1.0, color-coded ANSI terminal tables, and rich Markdown summaries.

---

## 2. System Requirements

The only requirement on your local workstation is a container runtime:
- **Docker** 20.10+ (Docker Engine on Linux, Docker Desktop or OrbStack on macOS, Docker Desktop or WSL2 on Windows).
- **Git** 2.30+.
- **Hardware**: Minimum 2 CPU cores and 4GB RAM allocated to Docker. Vigil sets `--shm-size=2gb` to support headless Chromium.

You do **not** need to install Go, Node, Python, PHP, Chromium, or security scanners on your host.

---

## 3. Installation Options

### Option A: Universal 1-Command Installer (Recommended)
Install Vigil in seconds across Linux, macOS (Apple Silicon & Intel), or Windows WSL2:

```bash
curl -fsSL https://raw.githubusercontent.com/GuardianVigil-Lab/Vigil/main/install.sh | sh
```

The installer will:
1. Detect your OS and architecture (`linux/amd64`, `linux/arm64`, macOS Darwin arm64/x86_64, or WSL2).
2. Install the `vigil` CLI into your PATH (`/usr/local/bin` or `~/.local/bin`).
3. Check Docker status and pre-pull the ultra-lean **Core** image (`ghcr.io/guardianvigil-lab/vigil:core`).
4. Validate execution and output quickstart instructions.

### Option B: Portable CLI Runner (`bin/vigil`)
You can download the single portable host runner script directly into your local `$PATH`:

```bash
# On Linux or macOS:
curl -fsSL https://raw.githubusercontent.com/GuardianVigil-Lab/vigil/main/bin/vigil -o ~/.local/bin/vigil
chmod +x ~/.local/bin/vigil
```

Verify your installation:
```bash
vigil --help
```

### Option C: Native Windows PowerShell Runner (`bin/vigil.ps1`)
On Windows workstations using native PowerShell:
```powershell
# Clone the repository
git clone https://github.com/GuardianVigil-Lab/vigil.git
cd vigil

# Run help
.\bin\vigil.ps1 -Help
```

### Option D: Direct Docker Run
You can run Vigil against any project without cloning or installing anything:
```bash
# Lean Core Tier (<150MB): fast developer iteration & security
docker run --rm \
  --network host \
  -u "$(id -u):$(id -g)" \
  -v "$(pwd):/workspace" \
  ghcr.io/guardianvigil-lab/vigil:core fast

# Full Tier (~1.2GB): deep VAPT, Playwright E2E & complete review
docker run --rm \
  --network host \
  --shm-size=2gb \
  -u "$(id -u):$(id -g)" \
  -e VIGIL_HOST_WORKSPACE="$(pwd)" \
  -v /var/run/docker.sock:/var/run/docker.sock \
  -v "$(pwd):/workspace" \
  ghcr.io/guardianvigil-lab/vigil:latest review
```

### Option E: Standalone Mode (No Docker Required)
If Docker is unavailable on your host, Vigil can run directly using host-native scripts and local tools:
```bash
vigil --standalone fast
```

---

## 3.1 Container Tiers & Smart Routing

Vigil provides an intelligent dual-tier container architecture:

| Tier | Size | Cold-Start Pull | Batteries Supported | Included Tools |
| :--- | :--- | :--- | :--- | :--- |
| **Core** (`vigil:core`) | ~150 MB | 5–10s | `fast`, `quality`, `security` | Pre-compiled static binaries (`ast-grep`, `gitleaks`, `trufflehog`, `zizmor`, `squawk`, `hadolint`, `trivy`, `syft`, `grype`), Python 3 with the 18 anti-fabrication rules, diff reviewer, and SARIF synthesizer. Zero Chromium, zero Node.js, zero PHP, zero Go runtime. |
| **Full** (`vigil:latest`) | ~1.2 GB | 30–60s | `vapt`, `test`, `e2e`, `review`, `full`, `all` | All Core tools plus Node.js 26.x, Go 1.27 compiler, PHP 8.2, Playwright headless Chromium, Strix autonomous AI red team, Nikto, testssl.sh, PHPStan, Stryker, and mutation engines. |

The `vigil` CLI automatically routes commands to the appropriate tier:
- Running `vigil fast`, `vigil quality`, or `vigil security` invokes `vigil:core`.
- Running `vigil vapt`, `vigil e2e`, `vigil review`, or `vigil full` invokes `vigil:latest`.
- If an image is not present locally, Vigil pulls it from GHCR without freezing on slow local builds.

---

## 4. Running Audit Batteries

Navigate to the root directory of any repository and invoke Vigil with the desired battery:

### 1. Fast Pre-Commit Ratchet (`fast`)
Runs only against modified files and staged changes in under 15 seconds:
```bash
vigil fast
```
*Checks: ast-grep structural patterns, gitleaks secret detection, zizmor GitHub Actions security, and anti-fabrication on modified lines.*

### 2. Code Quality & Dead Code (`quality`)
Deeply inspects code cleanliness, architecture, and duplication:
```bash
vigil quality
```
*Checks: golangci-lint with merge-base ratchet, ruff Python linting, knip dead code analysis, squawk Postgres migration locks, phpstan Level 8, and jscpd copy-paste clone detection (> 3% threshold).*

### 3. Full Security & SAST Sweep (`security`)
Thorough static application security testing and dependency vulnerability scanning:
```bash
vigil security
```
*Checks: 18-rule anti-fabrication detector, gitleaks, trufflehog, trivy container/filesystem CVE scan, syft SBOM generation, grype vulnerability match, semgrep security rules, and hadolint Dockerfile hygiene.*

### 4. Dynamic VAPT & Penetration Testing (`vapt`)
Active penetration testing and network auditing against running environments:
```bash
# Against local dev server (Linux / WSL2)
TARGET_URL=http://localhost:3000 vigil vapt

# Against local dev server (macOS / Windows Docker Desktop)
TARGET_URL=http://host.docker.internal:3000 vigil vapt

# Using Strix autonomous red teaming with BYO-LLM key
STRIX_LLM_API_KEY="sk-..." TARGET_URL=https://staging.example.com vigil vapt
```
*Checks: Strix autonomous agent exploits, 2-token BOLA/IDOR cross-tenant matrix, Nmap NSE vulnerability audit, testssl.sh TLS ciphers, Nikto web server auditor, and Nuclei.*

### 5. Headless Playwright E2E User Battery (`e2e`)
Runs real browser persona testing inside the container's pre-installed Chromium:
```bash
vigil e2e
```
*Checks: Authentication & session lifecycle, DOM error sweep (zero uncaught errors, zero 404s, zero CSP rejections), form boundary fuzzing, and multi-tenant RBAC DOM isolation.*

### 6. Complete Pre-Release Review (`review`)
Runs all batteries sequentially, synthesizes results, and produces executive reports:
```bash
vigil review
```

### 7. Complete All-in-One Full Scan (`full`)
Executes all batteries (fast AST invariants, deep security/anti-fabrication, QA test runner, dynamic VAPT, and review report synthesis) in a single consolidated pass:
```bash
vigil full
```
*Checks: Full end-to-end audit with automated SARIF generation in a single command.*

---

## 5. Understanding Audit Reports & Exit Codes

Every Vigil run generates outputs in your repository's `./reports/` directory:

### Terminal Summary Table
Immediately after execution, Vigil prints an ANSI color-coded summary:
```
╔══════════════════════════════════════════════════════════════════════════════╗
║                           VIGIL AUDIT REPORT                                 ║
╠══════════════════════════════╦══════╦══════╦══════╦══════╦═══════════════════╣
║ Scanner / Battery            ║  P0  ║  P1  ║  P2  ║  P3  ║ Status            ║
╠══════════════════════════════╬══════╬══════╬══════╬══════╬═══════════════════╣
║ anti_fabrication             ║    0 ║    0 ║    0 ║    0 ║ ✔ PASS            ║
║ gitleaks                     ║    0 ║    0 ║    0 ║    0 ║ ✔ PASS            ║
║ trivy                        ║    0 ║    0 ║    2 ║    5 ║ ⚠ WARN            ║
║ bola_matrix                  ║    0 ║    0 ║    0 ║    0 ║ ✔ PASS            ║
╠══════════════════════════════╩══════╩══════╩══════╩══════╩═══════════════════╣
║ TOTALS: P0=0 | P1=0 | P2=2 | P3=5                                            ║
║ VERDICT: PASSED (Zero Critical Blockers)                                    ║
╚══════════════════════════════════════════════════════════════════════════════╝
```

### Exit Codes & Gate Policies
- **Exit Code `1` (Merge Blocked)**: Triggered if **P0 (Critical)** or **P1 (High)** findings are detected. These represent security holes, active secret exposures, or broken functionality that must be resolved before merging.
- **Exit Code `0` (Merge Approved)**: Returned when findings are limited to **P2 (Medium)**, **P3 (Low)**, or zero issues.

### Generated Report Files
1. **`reports/vigil-review.md`**: Human-readable Markdown summary formatted for GitHub PR comments, containing severity badges, file/line links, scanner breakdowns, and line-by-line remediation patches.
2. **`reports/vigil.sarif`**: Standard OASIS SARIF 2.1.0 output compatible with GitHub Advanced Security / Code Scanning, VS Code SARIF viewer, and SonarQube.
3. **`reports/raw/`**: Raw JSON and log artifacts from individual tools (`gitleaks.json`, `strix.json`, `bola_matrix.json`, `hadolint.json`, etc.) for in-depth inspection and debugging.

---

## 6. Next Steps & Advanced Usage

- To configure Vigil for your specific operating system (Linux, macOS, or Windows), see the **[Cross-Platform Guide](CROSS_PLATFORM.md)**.
- To add a new scanner or custom linter to Vigil, see **[How to Add Tools](HOW_TO_ADD_TOOLS.md)**.
- To optimize performance and reduce false positives, see **[How to Improve Vigil](HOW_TO_IMPROVE.md)**.
- To configure autonomous penetration testing, see the **[VAPT Guide](VAPT_GUIDE.md)**.
