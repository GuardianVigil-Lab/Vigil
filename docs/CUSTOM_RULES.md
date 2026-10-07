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

---

## 4. Project Settings for the Anti-Fabrication Detector (`.vigil/fabrication.json`)

The detector ships with no knowledge of any particular codebase. A repository
tells it about itself in `.vigil/fabrication.json` (or a file passed with
`--config=path`). Every key is optional; unknown keys are an error, so a typo
cannot silently disable something.

```json
{
  "exempt": [
    { "path": "src/components/ExampleInput.tsx", "rule": "documentation-address",
      "reason": "placeholder text for the paste box, never rendered as a result" }
  ],
  "known_debt": [
    { "path": "src/legacy/feed.ts", "rule": "demo-named-data",
      "reason": "#42: replaced by the real feed in the next release" }
  ],
  "score_owners": ["backend/scoring/score.go"],
  "model_call_patterns": ["@/lib/llm"],
  "evidence_markers": ["providerVerdicts"],
  "allowed_paths": ["fixtures/"]
}
```

| Key | What it does |
|---|---|
| `exempt` | A hit that is not a fabrication. Every entry needs a reason. On a full sweep an entry that no longer matches anything fails as `stale-exemption`, so exemptions cannot outlive the code they excuse. |
| `known_debt` | A real fabrication you have not removed yet. The reason must start with an issue reference (`#42: ...`). The full sweep lists the debt every run and fails when an entry goes stale, so the list only shrinks. An entry cannot be both exempt and debt. |
| `score_owners` | Turns on `score-outside-scoring`: a `.score` / `.reputation` assignment anywhere but these files is reported. Off when unset. |
| `model_call_patterns` | Regexes that mark a file as calling a model, for projects that wrap their SDK. Without it, a wrapper hides every call and the prompt rule silently matches nothing. |
| `evidence_markers` | Regexes for the names your code uses when it hands observed evidence to a model. |
| `allowed_paths` | Extra path fragments to skip, added to the built-in test and tooling paths. |

Run `python3 engine/anti_fabrication/detector.py --self-check` after changing
the detector itself; it uses its own fixed settings and never reads yours.
