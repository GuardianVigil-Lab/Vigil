# How to Improve and Tune Vigil

Vigil is designed not just as a static scanner, but as an evolving enterprise QA and security platform. As your application grows, you will want to optimize its execution speed, reduce false positives, expand anti-fabrication heuristics, and deepen autonomous VAPT penetration testing.

This guide outlines practical techniques and best practices to continually elevate Vigil's capabilities.

---

## 1. Improving Execution Speed & Caching

Vigil delivers sub-15-second fast ratchets and sub-3-minute full reviews by leveraging multi-tiered caching:

### A. Persistent Volume Caching (`~/.cache/vigil`)
The host runner automatically maps `~/.cache/vigil` into the container at `/home/vigil/.cache`. This directory retains:
- **Go Build Cache** (`/home/vigil/.cache/go-build`): Prevents recompiling unchanged Go packages across runs.
- **Trivy Vulnerability Database** (`/home/vigil/.cache/trivy`): Avoids re-downloading the ~200MB CVE database on every execution.
- **npm Cache** (`/home/vigil/.cache/_cacache`): Caches JavaScript dependencies.

To warm or purge the cache:
```bash
# Check cache size on host
du -sh ~/.cache/vigil

# Clear cache if experiencing stale build state
rm -rf ~/.cache/vigil/*
```

### B. Git Merge-Base Incremental Diff Scoping
In fast mode (`./bin/vigil fast`), Vigil does not scan all 100,000+ files in your repository. Instead, it determines the diff boundary:
```bash
git diff --name-only origin/main...HEAD
```
- AST linters (`ast-grep`), secrets (`gitleaks`), and anti-fabrication (`detector.py`) execute **only against modified lines and files**.
- To optimize speed for feature branches, keep PR branches up to date with `main` to minimize the merge-base diff size.

### C. Parallelizing Battery Runners
For massive monorepos, you can run independent runner stages in parallel inside `runners/run_review.sh`:
```bash
# Run static AST linting and security scanning concurrently
bash /tools/vigil/runners/run_ast_lint.sh review &
PID_AST=$!
bash /tools/vigil/runners/run_security.sh &
PID_SEC=$!

wait $PID_AST
wait $PID_SEC
```

---

## 2. Eliminating False Positives & Tuning Severity

A security tool that produces false positives will be ignored by developers. Vigil provides granular mechanisms to tune rules:

### A. In-Code Inline Suppressions
Developers can suppress false alarms directly in code using standard suppression comments:
- **anti-fabrication**: `// vigil-ignore: SYNTHETIC_DELAY_MOCK` or `# vigil-ignore: FAKE_API_RESPONSE`
- **ast-grep**: `// ast-grep-ignore`
- **semgrep**: `// nosemgrep`
- **hadolint**: `# hadolint ignore=DL3018`
- **gitleaks**: Add `# gitleaks:allow` at the end of the line

### B. Fine-Tuning Severity Mappings (P0–P3)
Vigil gates PRs with a fail-closed policy:
- **P0 (Critical)**: Exploitable vulnerabilities, live secret leaks, unshielded Server Actions. **Blocks PR with exit code 1**.
- **P1 (High)**: High-confidence BOLA flaws, missing auth checks, dangerous XXE/SQLi. **Blocks PR with exit code 1**.
- **P2 (Medium)**: Deprecated functions, missing security headers, duplicate code > 3%. **Advisory only (exit code 0)**.
- **P3 (Low / Info)**: Code formatting, style suggestions, minor package bumps. **Informational (exit code 0)**.

To adjust rule severities, edit `engine/synthesizer/parse_results.py` under the appropriate parser function.

---

## 3. Hardening Anti-Fabrication Invariants

Vigil's anti-fabrication engine ([`detector.py`](../engine/anti_fabrication/detector.py)) enforces that no developer or AI agent commits mock data, disconnected UI handlers, or simulated business logic to production branches.

### Adding New Invariant Rules
To add a new detection rule (e.g. detecting disconnected OAuth mock buttons):
1. Open `engine/anti_fabrication/detector.py`.
2. Define a new rule check function:
   ```python
   def check_disconnected_oauth(file_path: str, content: str) -> List[Finding]:
       findings = []
       pattern = re.compile(r'onClick=\{?\(\)\s*=>\s*alert\(["\']OAuth coming soon["\']\)\}?')
       for i, line in enumerate(content.splitlines(), start=1):
           if pattern.search(line):
               findings.append(Finding(
                   rule_id="DISCONNECTED_OAUTH_STUB",
                   message="Detected placeholder OAuth click handler with alert dialog",
                   file_path=file_path,
                   line_number=i,
                   severity=Severity.P1
               ))
       return findings
   ```
3. Add a test case to the built-in self-check suite:
   ```python
   # In detector.py self-test section:
   test_code = '<button onClick={() => alert("OAuth coming soon")}>Google Login</button>'
   assert len(check_disconnected_oauth("login.tsx", test_code)) == 1
   ```
4. Verify with:
   ```bash
   python3 engine/anti_fabrication/detector.py --self-check
   # Output: detector self-check: 51 case(s) ok
   ```

---

## 4. Deepening Autonomous VAPT & Penetration Testing

The VAPT battery ([`runners/run_vapt.sh`](../runners/run_vapt.sh)) combines active exploit generation and stateful vulnerability assessment:

### A. Tuning Strix Autonomous Red Teamer
Strix ([`strix_orchestrator.py`](../engine/vapt/strix_orchestrator.py)) can be configured with custom instructions for your application's domain:
- Provide enterprise attack directives:
  ```bash
  export STRIX_INSTRUCTION="Focus penetration testing on the multi-tenant billing endpoints under /api/v1/billing, attempting to bypass subscription quotas and read other organization invoices."
  export STRIX_SCAN_MODE="deep"
  ./bin/vigil vapt
  ```
- Supply BYO-LLM API keys:
  ```bash
  export OPENAI_API_KEY="sk-..."
  # or
  export ANTHROPIC_API_KEY="sk-ant-..."
  ./bin/vigil vapt
  ```

### B. Expanding the BOLA / IDOR Two-Token Matrix
The BOLA matrix harness ([`bola_matrix.py`](../engine/vapt/bola_matrix.py)) tests Broken Object Level Authorization by sending requests with **Tenant A's** token accessing **Tenant B's** object IDs:
- To customize headers and endpoints, edit `engine/vapt/bola_matrix.py` to include custom header prefixes:
  ```python
  HEADERS_TENANT_A = {"Authorization": f"Bearer {token_a}", "X-Tenant-ID": "tenant-alpha"}
  HEADERS_TENANT_B = {"Authorization": f"Bearer {token_b}", "X-Tenant-ID": "tenant-bravo"}
  ```

### C. Adding Custom Nuclei CVE Templates
Vigil bundles ProjectDiscovery's `nuclei` v3.3.8. You can point Vigil at custom private vulnerability templates:
```bash
nuclei -t /workspace/security/templates/ -u "${TARGET_URL}" -json -o "${RAW_DIR}/nuclei.json"
```

---

## 5. Expanding Playwright E2E User Persona Testing

Vigil's Playwright runner ([`runners/run_e2e_user.sh`](../runners/run_e2e_user.sh)) executes headless user personas in pre-installed Chromium without any host browser dependencies.

### Adding New User Journeys
Create new spec files in `engine/e2e/core_journeys/`:
- `05_billing_upgrade_flow.spec.ts`: Tests Stripe checkout redirect and subscription state transitions.
- `06_team_invite_journey.spec.ts`: Tests organization invitation link generation and acceptance.
- `07_websocket_live_alerts.spec.ts`: Tests live threat stream ingestion and real-time canvas updates.

### Asserting Zero Console Errors & 404s
Ensure every new spec uses Vigil's zero-leak listener:
```typescript
page.on('console', msg => {
  if (msg.type() === 'error') {
    throw new Error(`Uncaught browser console error: ${msg.text()}`);
  }
});
page.on('pageerror', err => {
  throw new Error(`Uncaught runtime error on page: ${err.message}`);
});
```

---

## 6. Continuous Feedback & Telemetry-Free Metrics

Vigil does not phone home or transmit source code to any third-party telemetry servers. All metrics and findings remain strictly on your machine in `./reports/`:
- Ingest `reports/vigil.sarif` into GitHub Code Scanning for automated PR badges.
- Parse `reports/vigil-review.md` in CI to post automatic PR summary comments.
- Archive `reports/raw/` in CI artifacts for forensic audit history and SOC 2 / ISO 27001 compliance evidence.
