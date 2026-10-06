# Vigil Deep VAPT & Red Teaming Guide

Vigil delivers continuous, automated Vulnerability Assessment and Penetration Testing (VAPT) combining Strix AI penetration testing, OWASP Top 10 BOLA/IDOR matrix probes, and Nessus-equivalent transport and infrastructure auditing.

---

## 1. Strix Autonomous AI Red Team

Vigil integrates **Strix v1.7.0**, an autonomous agentic penetration tester that crawls API endpoints, mutates parameters, and attempts real-world exploits across the OWASP Top 10.

### Modes:
1. **Local BYO-LLM Execution**:
   - Provide an LLM API key to run locally:
     ```bash
     export STRIX_LLM_API_KEY="sk-..."
     export STRIX_MODEL="gpt-4o"  # or claude-3-5-sonnet, gemini-1.5-pro
     vigil vapt
     ```
2. **Strix Cloud API**:
   - Offload heavy multi-agent fuzzing to Strix Cloud:
     ```bash
     export STRIX_CLOUD_API_KEY="strix_live_..."
     vigil vapt
     ```
3. **Reproducible Exploits**:
   - Every verified vulnerability emits a standalone `curl` reproduction snippet in `reports/vigil-review.md`.

---

## 2. Automated BOLA / IDOR Cross-Tenant Matrix

Broken Object Level Authorization (BOLA) is the #1 API security vulnerability. Vigil includes an automated two-token matrix test harness (`engine/vapt/bola_matrix.py`):

```
                       Resource A (Tenant A)    Resource B (Tenant B)
                    ┌─────────────────────────┬─────────────────────────┐
Token A (Tenant A)  │  200 OK (Authorized)    │  403 / 404 (Zero Leak)  │
                    ├─────────────────────────┼─────────────────────────┤
Token B (Tenant B)  │  403 / 404 (Zero Leak)  │  200 OK (Authorized)    │
                    ├─────────────────────────┼─────────────────────────┤
Anonymous (No Token)│  401 / 403 (Refused)    │  401 / 403 (Refused)    │
                    └─────────────────────────┴─────────────────────────┘
```

If Token A successfully reads or mutates Resource B, Vigil immediately flags a **P0 Critical Security Blocker** and blocks PR merge.

---

## 3. Nessus-Equivalent Infrastructure Auditing (`infra_scanner.sh`)

Vigil runs:
1. **`nmap` + NSE**:
   - Port scanning, open service detection, and CVE matching via `vulners`.
2. **`testssl.sh`**:
   - Pure-bash SSL/TLS cipher auditor.
   - Asserts TLS 1.2+ minimum, flags weak ciphers (RC4, 3DES, EXPORT), verifies Perfect Forward Secrecy (PFS), and checks for Heartbleed and ROBOT.
3. **`nikto`**:
   - Web server misconfiguration scanner (detects `.git` exposures, directory traversal, dangerous HTTP methods like PUT/DELETE on unauthenticated endpoints).
