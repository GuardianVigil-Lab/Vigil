# Vigil Code Review, Anti-Fabrication & Quality Guide

Vigil acts as an open-source, on-premise alternative to CodeRabbit and commercial code review bots, while enforcing strict anti-fabrication invariants.

---

## 1. Anti-Fabrication & Fake Functionality (18 Rules)

Software systems handling security or operational telemetry must never invent findings or fake responses when upstream providers fail. Vigil enforces 18 invariant rules:

### Threat-Intel Invariant Rules (1-14)
1. `hardcoded-attribution`: Disallows literal threat actors (`APT28`, `Lazarus`, `Volt Typhoon`) in application source.
2. `hardcoded-cve`: Disallows hardcoded CVE strings presented as live scan outputs.
3. `verdict-on-error-path`: Flags returning `Malicious`/`Clean` on catch or timeout blocks.
4. `score-on-error-path`: Flags returning non-zero threat scores on failure branches.
5. `fake-named-data`: Detects mock or dummy data variables serving as production returns.
6. `simulated-return-value`: Detects literal constants under comments admitting they are simulated.
7. `llm-generated-intel`: Flags LLM prompts asking models to invent IOCs or attribution.
8. `substring-decides-verdict`: Detects indicators deciding their own verdict based on substring presence.
9. `invented-event-timestamp`: Flags records whose timestamp is computed from `Date.now()` to fake real-time activity.
10. `asserted-state`: Flags literal healthy or compromised states in telemetry arrays.
11. `empty-input-digest-as-sample`: Detects SHA256/MD5 hashes of empty strings passed off as malware.
12. `zero-jarm-as-fingerprint`: Detects 62-zero JARM strings passed off as TLS fingerprints.
13. `prompt-invents-finding`: Flags LLM prompts requesting judgment fields without supplying observed evidence.
14. `route-canned-fallback`: Flags API routes catching upstream failure and serving HTTP 200 with canned data.

### Generic Application Fake Functionality Rules (15-18)
15. `stub-click-handler`: Flags empty click/press handlers (`onClick={() => {}}`).
16. `synthetic-delay-mock`: Flags artificial `setTimeout` / `sleep` calls returning mock constants.
17. `unhandled-empty-catch`: Flags empty catch blocks swallowing errors and faking success.
18. `disconnected-form-submit`: Flags forms calling `e.preventDefault()` without any backend action or fetch.

---

## 2. Semantic PR Reviewer (`pr_reviewer.py`)

Analyzes `git diff origin/main...HEAD` for:
- SQL injection risks and unparameterized string interpolations.
- Ignored error returns (`_, _ = fn()`) in Go.
- Goroutine leaks and unbounded concurrency.
- Sensitive credentials logged to `console.log`.

Produces committable GitHub suggestions:
````markdown
```suggestion
const apiKey = process.env.API_KEY;
```
````

---

## 3. Inline GitHub PR Annotations (`reviewdog_wrapper.sh`)

Vigil integrates with `reviewdog` to convert all diff-scoped findings into Reviewdog Diagnostic Format (RDJSON). When run inside GitHub Actions with `GITHUB_TOKEN`, reviewdog posts inline comments on the exact diff lines of the PR without failing builds on pre-existing legacy code.
