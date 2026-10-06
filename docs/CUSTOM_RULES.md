# Authoring Custom AST-grep & Invariant Rules

Vigil allows authoring custom structural AST-grep rules, repository audit hooks, and anti-fabrication rules to enforce organization-specific architectural invariants.

---

## 1. Project-Specific AST Rules (`.vigil/rules/`)

Vigil automatically discovers and executes all AST rules placed in `.vigil/rules/*.yml` or `.vigil/rules/*.yaml` inside your repository.

### Example: Enforcing Server Action First-Line Authorization Guard
Create `.vigil/rules/action-auth-guard.yml` in your repository:

```yaml
id: server-action-missing-auth
message: Next.js Server Action must invoke an authorization guard as its first statement
severity: error
language: TypeScript
rule:
  all:
    - pattern: |
        export async function $FUNC($$$ARGS) {
          $$$BODY
        }
    - not:
        pattern: |
          export async function $FUNC($$$ARGS) {
            await auth($$$GUARD_ARGS);
            $$$REST
          }
```

Test your custom rules locally:
```bash
vigil fast
# or via docker directly:
docker run --rm -v "$(pwd):/workspace" ghcr.io/guardianvigil-lab/vigil:latest fast
```

---

## 2. Custom Audit Hooks (`.vigil/hooks/`)

You can add executable custom audit scripts to `.vigil/hooks/*.sh` or `.vigil/hooks/*.py`. Vigil runs all hooks during the audit and collects their output into `reports/raw/`:

```bash
mkdir -p .vigil/hooks
cat <<'EOF' > .vigil/hooks/check-license-headers.sh
#!/usr/bin/env bash
set -e
echo "Checking enterprise license headers..."
# exit 1 on failure
EOF
chmod +x .vigil/hooks/check-license-headers.sh
```

---

## 3. Adding Invariant Rules to `detector.py`

Global anti-fabrication rules can be added to `engine/anti_fabrication/detector.py`:

1. Define a regular expression or structural detector function.
2. Add rule to `raw_findings(rel, suffix, text)`.
3. Add a self-check test case to `SELF_CHECK_CASES` or `V2_SELF_CHECK_CASES`.
4. Run `python3 engine/anti_fabrication/detector.py --self-check` to prove that the rule detects positive fixtures and ignores negative near-misses.
