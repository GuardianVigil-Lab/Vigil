# Vigil Global Tooling Expansion & Compliance Roadmap

## Executive Overview

**Vigil** is designed to be the single, authoritative, local-first security and quality engine for software engineering organizations worldwide. This blueprint details the expansion matrix for supporting global enterprise technology stacks (Python, Java/Kotlin, Rust, Go, C/C++, Ruby, PHP, and Infrastructure as Code) alongside automated mapping to the world's most stringent regulatory standards: **SOC 2 Type II**, **ISO/IEC 27001:2022**, **PCI-DSS v4.0**, **HIPAA**, and the **OWASP Top 10:2025**.

---

## 1. Global Multi-Stack Tooling Matrix

To serve Fortune 500 enterprises, hyper-growth unicorns, and regulated sovereign entities, Vigil expands its 6-pillar battery to encompass the following native language runtimes and tooling adapters:

| Ecosystem | Target Runtimes & Frameworks | Primary Scanners & Analyzers | Security & Invariant Scope |
| :--- | :--- | :--- | :--- |
| **Python** | FastAPI, Django, Flask, PyTorch, Celery (Python 3.10–3.13) | `bandit`, `ruff` (flake8-bandit/bugbear), `pip-audit`, `defusedxml` | Insecure deserialization (`pickle`), SQL injection, raw shell execution, secret leakage, unpinned dependency vulnerabilities |
| **Java / Kotlin** | Spring Boot 3.x, Quarkus, Micronaut, Android (JDK 17/21) | `SpotBugs` + `FindSecBugs`, `OWASP Dependency-Check`, `Semgrep Java` | Spring `@PreAuthorize` authorization bypasses, XML External Entity (XXE), path traversal, JWT validation flaws, Log4j/Logback CVEs |
| **Rust** | Axum, Actix-web, Tokio, Embedded (Rust 1.78+) | `cargo-audit`, `cargo-deny`, `clippy` (pedantic security), `miri` | Advisory crate vulnerabilities, unvetted duplicate dependencies, unsafe pointer dereferences, license compliance |
| **Go** | Gin, Echo, Fiber, gRPC (Go 1.22–1.24) | `golangci-lint`, `govulncheck`, `gosec`, `nilaway`, `go-mutesting` | Egress control bypasses, nil pointer panics, concurrent race conditions, insecure TLS configs, mutation survival |
| **C / C++** | Systems, Embedded, FinTech low-latency (C17, C++20) | `cppcheck`, `flawfinder`, `clang-tidy`, AddressSanitizer (ASan) | Stack/heap buffer overflows, use-after-free, memory leaks, format string vulnerabilities, integer truncation |
| **Ruby** | Ruby on Rails 7+, Sinatra (Ruby 3.2+) | `brakeman`, `bundler-audit` | Rails Mass Assignment, unescaped SQL fragments, CSRF token omission, vulnerable rubygems |
| **PHP** | Laravel 11+, Symfony, WordPress (PHP 8.2–8.4) | `phpstan` (Level 8/max), `psalm`, `composer audit` | Type safety violations, unhandled exception paths, legacy deserialization, known CVEs in composer packages |
| **IaC & Cloud** | Terraform, OpenTofu, Helm, Kubernetes, CloudFormation | `checkov`, `trivy config`, `polaris`, `hadolint`, `dockle` | CIS Benchmark violations, privileged container execution, missing encryption at rest, overly permissive IAM wildcard policies |
| **Mobile (iOS/Android)** | Swift, Kotlin, React Native, Flutter | `MobSF` CLI, `Semgrep Mobile`, `apkid`, `detekt` | Hardcoded private keys/keystores, insecure local storage (Keychain/EncryptedSharedPreferences), OWASP MASVS compliance |
| **Cloud-Native & eBPF** | Kubernetes clusters, Docker runtimes, Cilium | `Falco` rules, `Tetragon` tracepoints, `kyverno-cli` | Unauthorized privilege escalation, namespace escapes, egress connection leaks to untrusted C2 IPs |
| **AI & LLM Workloads** | LangChain, LlamaIndex, OpenAI/Anthropic SDKs, vLLM | `promptfoo`, `garak`, `Semgrep LLM guards` | OWASP Top 10 for LLMs (prompt injection LLM01, sensitive data leakage LLM02, insecure output handling LLM04) |
| **Supply Chain & SBOM** | Multi-ecosystem packages & container images | `syft`, `grype`, `cosign`, `slsa-verifier` | SPDX 2.3 / CycloneDX 1.6 SBOM, SLSA Level 3 provenance attestations, Sigstore keyless signature verification |

---

## 2. Dynamic VAPT & Dynamic Application Security Testing (DAST)

Global enterprise applications require active runtime verification that static analysis alone cannot substantiate:

1. **Autonomous AI Red Teaming (Strix 1.7.0)**:
   - Dynamic LLM-driven exploit engine that crawls OpenAPI/Swagger schemas and frontend DOM trees to attempt real proof-of-concept exploits.
   - Verifies Server-Side Request Forgery (SSRF), Remote Code Execution (RCE), and Broken Object-Level Authorization (BOLA).

2. **Automated Cross-Tenant BOLA Matrix (`engine/vapt/bola_matrix.py`)**:
   - Executes dual-token differential fuzzing (`Tenant A Token` vs `Tenant B Resource ID`).
   - Asserts non-negotiable HTTP 403 Forbidden / 404 Not Found response codes on unauthorized boundary traversal.

3. **Infrastructure & TLS Posture Battery (`engine/vapt/infra_scanner.sh`)**:
   - **Nmap NSE**: Detects unhardened open ports (SSH, Redis, Postgres, MongoDB, Elasticsearch).
   - **testssl.sh**: Verifies cipher suite hygiene, forward secrecy (PFS), HSTS preloading, and absence of SSLv3/TLS 1.0/1.1 or deprecated CBC ciphers.
   - **Nikto / Ffuf**: Flags legacy server headers (`Server: Apache/2.4`, `X-Powered-By`), exposed debug endpoints (`/.git`, `/env`, `/actuator`, `/.env`), and directory indexing.

---

## 3. Global Regulatory Compliance Mapping

Vigil normalizes all scanner findings into a single unified SARIF 2.1.0 output with rule metadata mapped directly to global compliance requirements:

### 1. SOC 2 Type II Trust Services Criteria
- **CC6.1 (Logical Access Controls)**:
  - *Vigil Enforcements*: BOLA matrix tests, RBAC Playwright sweeps, secret and API token scans.
- **CC6.6 (Logical Boundary Protections)**:
  - *Vigil Enforcements*: Action authorization AST guards (`action-authorization-guard.yml`), CORS policy checks, HSTS/CSP validation.
- **CC6.8 (Malicious Code Prevention)**:
  - *Vigil Enforcements*: 18-rule anti-fabrication scanner, Syft SBOM generation, Grype/Trivy container scanning.
- **CC7.1 / CC7.2 (Vulnerability Management & Timely Remediation)**:
  - *Vigil Enforcements*: Non-negotiable P0/P1 CI exit code gates, Reviewdog automated GitHub pull request annotations.

### 2. ISO/IEC 27001:2022 Information Security Management
- **Control A.8.25 (Secure Development Life Cycle)**:
  - *Vigil Enforcements*: Automated pre-commit (`vigil fast`) and pre-merge (`vigil review`) battery gates.
- **Control A.8.28 (Secure Coding)**:
  - *Vigil Enforcements*: Structural AST invariant rules, SQL injection guards, memory-safe compiler configurations.
- **Control A.8.8 (Management of Technical Vulnerabilities)**:
  - *Vigil Enforcements*: Automated daily or PR-triggered dependency and container image CVE sweeps.

### 3. PCI-DSS v4.0 (Payment Card Industry Data Security Standard)
- **Requirement 6.2 (Secure Software Engineering)**:
  - *Vigil Enforcements*: Automated peer review diff generator (`pr_reviewer.py`), dead code pruning via Knip/deadcode.
- **Requirement 6.4 (Protection of Public-Facing Web Applications)**:
  - *Vigil Enforcements*: Autonomous DAST fuzzing via Strix, TLS 1.3 verification via testssl.sh, Nikto web server audits.
- **Requirement 6.5 (Mitigation of Common Software Vulnerabilities)**:
  - *Vigil Enforcements*: OWASP Top 10 test batteries with proof-of-concept verification.

### 4. HIPAA Security Rule (45 CFR Part 160 and Part 164, Subparts A and C)
- **§ 164.312(a)(1) (Access Controls)**:
  - *Vigil Enforcements*: Strict tenant isolation and assertOperator AST rules.
- **§ 164.312(b) (Audit Controls)**:
  - *Vigil Enforcements*: Fail-closed audit logging invariants ensuring all database operations emit structured audit records.
- **§ 164.312(e)(1) (Transmission Security)**:
  - *Vigil Enforcements*: Elimination of cleartext HTTP protocols, validation of mutual TLS (mTLS) configurations.

### 5. OWASP Top 10:2025 Standard
- **A01:2025 — Broken Access Control**: Verified via BOLA matrix and Playwright RBAC probes.
- **A02:2025 — Cryptographic Failures**: Verified via testssl.sh, TruffleHog secrets scanner, and weak hashing detectors.
- **A03:2025 — Software Supply Chain Failures**: Verified via Syft SBOM, Grype, Trivy, cargo-audit, and pip-audit.
- **A04:2025 — Insecure Design & Anti-Fabrication**: Verified via the 18-rule anti-fabrication detector and Stryker mutation tests.
- **A05:2025 — Security Misconfiguration**: Verified via Checkov IaC scanning, Hadolint Dockerfile audits, and Nikto header probes.

### 6. OWASP Top 10 for Large Language Models (LLMs) & GenAI (2025)
- **LLM01 (Prompt Injection)**: Prompt injection fuzzing using `promptfoo` and `garak` test batteries against AI chat/agent endpoints.
- **LLM02 (Sensitive Information Disclosure)**: PII/credential exfiltration detection in LLM responses and system prompts.
- **LLM03 (Supply Chain Vulnerabilities)**: Verification of third-party model weights, tokenizer dependencies, and PyPI model packages.
- **LLM04 (Data and Model Poisoning)**: Hash and signature verification of fine-tuning datasets and RAG document embeddings.
- **LLM05 (Improper Output Handling)**: AST rules asserting fail-safe sanitization of LLM-generated HTML, Markdown, and shell scripts.

### 7. OWASP Mobile Application Security Verification Standard (MASVS v2.0)
- **MASVS-STORAGE**: AST rules asserting that sensitive auth tokens and keys never persist in unencrypted `UserDefaults`, `SharedPreferences`, or world-readable filesystem paths.
- **MASVS-CRYPTO**: Detection of deprecated cryptographic primitives (MD5, SHA1, DES, ECB mode) in iOS/Android client runtimes.
- **MASVS-NETWORK**: Verification of certificate pinning, TLS 1.3 enforcement, and cleartext traffic blocking (`android:usesCleartextTraffic="false"`).

---

## 4. MCP & REST API Integration Architecture

To allow seamless consumption by modern AI agents and enterprise CI/CD pipelines, Vigil deploys two interoperability interfaces:

```
                    ┌─────────────────────────────────┐
                    │    AI Assistant / Operator      │
                    │ (Claude Code, Cursor, Windsurf) │
                    └────────────────┬────────────────┘
                                     │ Model Context Protocol (stdio)
                                     ▼
                    ┌─────────────────────────────────┐
                    │   Vigil Native MCP Server       │
                    │   (engine/mcp/vigil_mcp_server) │
                    └────────────────┬────────────────┘
                                     │
          ┌──────────────────────────┼──────────────────────────┐
          ▼                          ▼                          ▼
   vigil_fast_scan           vigil_security_audit           vigil_vapt
   (<15s AST Lint)           (Anti-Fab & Secrets)           (BOLA & Strix)

═════════════════════════════════════════════════════════════════════════════════

                    ┌─────────────────────────────────┐
                    │    CI/CD / SIEM / Webhooks      │
                    │ (GitHub, GitLab, Jira, Splunk)  │
                    └────────────────┬────────────────┘
                                     │ REST HTTP (JSON/OpenAPI)
                                     ▼
                    ┌─────────────────────────────────┐
                    │   Vigil REST API & Webhooks     │
                    │   (engine/api/server.py :8080)  │
                    └────────────────┬────────────────┘
                                     │
          ┌──────────────────────────┼──────────────────────────┐
          ▼                          ▼                          ▼
   POST /api/v1/scan         GET /api/v1/scans/{id}/sarif POST /api/v1/webhook
   (Headless Trigger)        (SARIF 2.1.0 Retrieval)      (Auto PR Review)
```

---

## 5. Implementation Roadmap

1. **Sprint 1 (Current Milestone)**:
   - Full Sentinel -> Vigil rebranding and zero-host container release (`ghcr.io/guardianvigil-lab/vigil:latest`).
   - Native MCP Server and REST API daemon with OpenAPI docs.
   - Comprehensive documentation push to Gemini Notebook with tagged multi-project retrieval.

2. **Sprint 2 (Q4 2026)**:
   - Packaging Python (`bandit`, `pip-audit`) and Java (`SpotBugs`) container layers.
   - Terraform / Kubernetes IaC scanner layer (`checkov`, `polaris`).
   - Real-time SARIF streaming over Server-Sent Events (SSE) in the REST API.

3. **Sprint 3 (Q1 2027)**:
   - Automated compliance report generator emitting audit-ready PDF/HTML packages for SOC 2 Type II and ISO 27001 auditors.
   - Distributed worker pool support for enterprise monorepos exceeding 1,000,000 lines of code.
