# How to Add Tools and Capabilities to Vigil

Vigil is designed as a modular, extensible engine. Whether you want to add a specialized static analyzer, a new vulnerability scanner, an API fuzzer, or a custom linter, this guide walks you step-by-step through the entire integration lifecycle.

---

## 1. Architectural Pipeline Overview

Adding a new tool to Vigil requires touching four clean seams:

```
┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐       ┌─────────────────┐
│ 1. Dockerfile   │ ───▶  │ 2. Tool Config  │ ───▶  │ 3. Battery      │ ───▶  │ 4. Synthesizer  │
│ Multi-stage     │       │ Default rules   │       │ Runner script   │       │ parse_results.py│
│ & multi-arch    │       │ under configs/  │       │ under runners/  │       │ JSON -> SARIF/MD│
└─────────────────┘       └─────────────────┘       └─────────────────┘       └─────────────────┘
```

1. **`Dockerfile`**: Download the binary (in Stage 1 Extractor) or install via package manager (Stage 2 Runtime) with multi-arch `TARGETARCH` support.
2. **`configs/<tool>/`**: Provide sensible default configurations so the tool executes without requiring configuration files in the target repository.
3. **`runners/run_<battery>.sh`**: Add the execution logic, redirecting structured output to `${RAW_DIR}/<tool>.json`.
4. **`engine/synthesizer/parse_results.py`**: Parse `${RAW_DIR}/<tool>.json`, map findings to Vigil's unified P0-P3 taxonomy, and feed into SARIF and Markdown reporting.

---

## 2. Step-by-Step Integration Guide

### Step 1: Install the Tool in `Dockerfile`

Vigil uses a two-stage build:
- **Stage 1 (`extractor`)**: Downloads pre-compiled binaries for both `amd64` and `arm64`.
- **Stage 2 (`debian:bookworm-slim`)**: Base runtime where binaries are copied to `/usr/local/bin/`.

#### Case A: Adding a Pre-Compiled Standalone Binary (Recommended)
Open `Dockerfile` and locate the `extractor` stage. Add your binary download using the `TARGETARCH` dispatch:

```dockerfile
# Stage 1: In the extractor stage RUN block:
RUN case "${TARGETARCH}" in \
      arm64) MYTOOL_ARCH="arm64" ;; \
      *)     MYTOOL_ARCH="x86_64" ;; \
    esac && \
    curl -fsSL "https://github.com/example/mytool/releases/download/v1.0.0/mytool-linux-${MYTOOL_ARCH}.tar.gz" \
      | tar -xz -C /out/bin mytool && \
    chmod +x /out/bin/mytool
```

Because `Dockerfile` has `COPY --from=extractor /out/bin/* /usr/local/bin/`, your new binary is automatically copied into the runtime path!

#### Case B: Adding an npm Global Tool
In Stage 2, add the package to the `npm install -g` list:
```dockerfile
RUN npm install -g --no-audit --no-fund \
    playwright@1.48.2 \
    jscpd@4 \
    my-npm-tool@latest
```

#### Case C: Adding a Python Security Tool
In Stage 2, add the package to the `pip install` list:
```dockerfile
RUN pip3 install --no-cache-dir --break-system-packages \
    defusedxml \
    my-python-tool
```

---

### Step 2: Add Default Configuration in `configs/<tool>/`

To ensure Vigil remains **zero-host-prerequisite**, provide a fallback configuration:

1. Create a directory: `configs/mytool/`
2. Add your default rule config, e.g. `configs/mytool/.mytool.yaml`:
   ```yaml
   rules:
     - id: no-raw-exec
       severity: ERROR
   exclude:
     - "node_modules/**"
     - "vendor/**"
   ```
3. Support **configuration inheritance**: In the runner script, allow repository-level configs to override Vigil defaults:
   ```bash
   CONFIG_ARG="/tools/vigil/configs/mytool/.mytool.yaml"
   if [ -f "${WORKSPACE}/.mytool.yaml" ]; then
     CONFIG_ARG="${WORKSPACE}/.mytool.yaml"
   fi
   ```

---

### Step 3: Wire into the Appropriate Runner Script

Select which battery mode the tool belongs to:

| Battery Script | Mode | Suitable Tool Types |
| :--- | :--- | :--- |
| `runners/run_fast.sh` | `fast` | Ultra-fast AST checks, git diff linters (< 5 seconds execution) |
| `runners/run_quality.sh` | `quality` | Typecheckers, dead code finders, duplication detectors, style |
| `runners/run_security.sh` | `security` | SAST analyzers, SCA vulnerability scanners, secret hunters |
| `runners/run_vapt.sh` | `vapt` | Dynamic network scanners, API fuzzers, red-team tools |
| `runners/run_qa_tests.sh` | `test` | Test runners, mutation testing engines, property-based tests |
| `runners/run_e2e_user.sh` | `e2e` | Browser automation, user persona testing |

Edit the chosen runner (e.g. `runners/run_security.sh`):

```bash
# 5. My New Security Tool
if command -v mytool >/dev/null 2>&1; then
  echo "  Running mytool scanner..."
  mytool scan \
    --config "${CONFIG_ARG}" \
    --format json \
    --output "${RAW_DIR}/mytool.json" \
    . 2>/dev/null || true
fi
```
*(Always append `|| true` so that an individual scanner failure does not crash the overall battery orchestrator).*

---

### Step 4: Parse Findings in `parse_results.py`

Open `engine/synthesizer/parse_results.py` and register your parser:

```python
def parse_mytool(raw_dir: str) -> List[Finding]:
    """Parse output from mytool scanner."""
    findings = []
    log_file = os.path.join(raw_dir, "mytool.json")
    if not os.path.isfile(log_file):
        return findings

    try:
        with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
            data = json.load(f)

        for item in data.get("issues", []):
            raw_sev = item.get("severity", "MEDIUM").upper()
            # Map tool severity to Vigil standard taxonomy
            if raw_sev in ("CRITICAL", "BLOCKER"):
                sev = Severity.P0
            elif raw_sev in ("HIGH", "ERROR"):
                sev = Severity.P1
            elif raw_sev in ("MEDIUM", "WARNING"):
                sev = Severity.P2
            else:
                sev = Severity.P3

            findings.append(Finding(
                tool="mytool",
                rule_id=item.get("rule_id", "MYTOOL_RULE"),
                severity=sev,
                file_path=item.get("file", "unknown"),
                line_number=int(item.get("line", 1)),
                message=item.get("description", "Security issue detected"),
                remediation=item.get("recommendation", "Review and fix issue.")
            ))
    except Exception as e:
        print(f"Warning: Failed to parse mytool results: {e}", file=sys.stderr)

    return findings
```

Add your parser to `collect_all_findings()`:
```python
all_findings.extend(parse_mytool(raw_dir))
```

That's it! Vigil will automatically:
- Categorize findings into **P0 (Critical)**, **P1 (High)**, **P2 (Medium)**, or **P3 (Low)**.
- Trigger an exit code `1` if any P0 or P1 finding is detected (enforcing the merge blocker).
- Render ANSI color tables in the terminal summary.
- Export standardized **SARIF 2.1.0** to `reports/vigil.sarif`.
- Generate rich GitHub Markdown tables with links and badges in `reports/vigil-review.md`.

---

## 3. Concrete Example: Adding Bandit (Python SAST)

Here is a full example showing how we would add Bandit to Vigil:

### 1. `Dockerfile`:
```dockerfile
RUN pip3 install --no-cache-dir --break-system-packages bandit
```

### 2. `configs/bandit/.bandit`:
```ini
[bandit]
exclude = /test,/tests,/node_modules
tests = B101,B102,B103,B104,B105,B106,B107
```

### 3. `runners/run_security.sh`:
```bash
if command -v bandit >/dev/null 2>&1 && [ -f "requirements.txt" -o -f "pyproject.toml" ]; then
  echo "  Running bandit Python SAST..."
  bandit -r . -f json -o "${RAW_DIR}/bandit.json" -c /tools/vigil/configs/bandit/.bandit 2>/dev/null || true
fi
```

### 4. `engine/synthesizer/parse_results.py`:
```python
def parse_bandit(raw_dir: str) -> List[Finding]:
    findings = []
    path = os.path.join(raw_dir, "bandit.json")
    if not os.path.exists(path):
        return findings
    try:
        with open(path) as f:
            data = json.load(f)
        for r in data.get("results", []):
            sev = Severity.P1 if r.get("issue_severity") == "HIGH" else Severity.P2
            findings.append(Finding(
                tool="bandit",
                rule_id=r.get("test_id", "B000"),
                severity=sev,
                file_path=r.get("filename", ""),
                line_number=r.get("line_number", 1),
                message=r.get("issue_text", ""),
                remediation=r.get("more_info", "")
            ))
    except Exception:
        pass
    return findings
```

---

## 4. Verification Checklist

Before opening a pull request with a new tool:

1. [ ] Rebuild the image: `docker build -t guardianvigil-vigil:local .`
2. [ ] Test the runner battery: `./bin/vigil <battery>`
3. [ ] Confirm output appears in `reports/vigil-review.md` and `reports/vigil.sarif`.
4. [ ] Ensure non-root user permissions work: `USER 1000:1000` must not throw permission denied errors.
5. [ ] Ensure the container builds on both `amd64` and `arm64`:
   ```bash
   docker buildx build --platform linux/amd64,linux/arm64 .
   ```
