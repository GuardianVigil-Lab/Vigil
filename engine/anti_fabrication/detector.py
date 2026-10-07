#!/usr/bin/env python3
"""Detect fabricated data, mock fallbacks, and simulated logic in enterprise applications.

Flags code paths that return plausible-looking production findings when the real
source is unavailable, disconnected UI mock handlers, and simulated business logic.

  python3 detector.py [paths...]             # default: src/ and backend/, else .
  python3 detector.py --changed              # files changed vs HEAD (local)
  python3 detector.py --changed=origin/main  # files changed vs a base ref (CI)
  python3 detector.py --json-out=report.json # also write findings as JSON
  python3 detector.py --config=path.json     # project settings (default .vigil/fabrication.json)
  python3 detector.py --self-check           # prove every rule still fires

Project settings are optional. See docs/CUSTOM_RULES.md for the file format:
exemptions with reasons, tracked debt, the module that owns scoring, extra
model-call and evidence patterns, and extra allowed paths.

Exit codes: 0 clean, 1 findings, 2 bad usage.
"""

from __future__ import annotations

import json
import re
import subprocess
import sys
from pathlib import Path

# Threat-intel vocabulary that should never appear as a literal in application
# code. Real findings arrive from a provider at runtime.
ATTRIBUTION_LITERALS = re.compile(
    r"""["'](?:
        (?:APT\s?\d+)                 # APT28, APT 29
      | Lazarus(?:\s+Group)?
      | Fancy\s+Bear | Cozy\s+Bear | Sandworm | Volt\s+Typhoon | Wicked\s+Panda
      | Cobalt\s+Strike | LockBit | AgentTesla | Formbook | Emotet | TrickBot
      | SolarWinds | Dtrack
    )["']""",
    re.VERBOSE | re.IGNORECASE,
)

# A hardcoded CVE presented as a scan result.
CVE_LITERAL = re.compile(r"""["']CVE-\d{4}-\d{4,7}["']""")

# Verdict fields assigned a literal rather than a computed value.
VERDICT_LITERAL = re.compile(
    r"""\b(?:reputation|verdict|status|threatLevel)\s*[:=]\s*["'](?:Malicious|Suspicious|Clean)["']""",
    re.IGNORECASE,
)

# Confidence/score fields set to a suspiciously specific constant.
SCORE_LITERAL = re.compile(
    r"""\b(?:score|threatScore|confidence|abuseConfidenceScore|similarity)\s*[:=]\s*(\d{2,3})\b"""
)

# Identifiers whose very name says the data is not real.
FAKE_NAME = re.compile(
    r"\b(?:mock|MOCK|Mock|FALLBACK_|fallbackData|dummy|DUMMY|fakeData|sampleResult|placeholderResult)\w*"
)

# A function that admits in its own comments that it is not real, sitting above
# a literal return: a similarity function returning a hardcoded 0.925 described
# as a "high-confidence match". No other rule looks at prose; the comment is the
# tell.
SIMULATION_TELL = re.compile(
    r"simulat(?:e|es|ed|ion)|in\s+production,?\s+this|for\s+now,?\s+return|"
    r"placeholder|stub(?:bed)?\s+(?:out|value|response)|would\s+(?:normally\s+)?compute",
    re.IGNORECASE,
)

# Ends the comment window. Without a boundary, one honest "in production..."
# note made every literal return in the *next* function look simulated, and an
# `export function` line did not read as a definition.
BLOCK_BOUNDARY = re.compile(
    r"^\s*$"                                            # blank line
    r"|^\s*[})\]];?\s*$"                                # a closing brace alone
    r"|^\s*(?:export\s+|default\s+|public\s+|private\s+|protected\s+|static\s+|async\s+)*"
    r"(?:def |func |function |class |const |let |var )"  # a definition
)

# A bare literal handed back as a result: `return 0.925`, `return 87`, `= 0.92`.
LITERAL_RETURN = re.compile(r"\breturn\s+(?:0?\.\d+|\d{1,3}(?:\.\d+)?)\s*(?:$|[#;/])")

# An LLM prompt asking the model to invent security data, such as "Generate 4
# realistic newly discovered Indicators of Compromise" fed into a product as if
# observed. A model told to invent IOCs produces exactly the fabricated
# attribution this detector exists to stop, at runtime instead of in source.
GENERATED_INTEL = re.compile(
    r"(?:generate|invent|fabricate|make\s+up|come\s+up\s+with|simulate)"
    # Quotes must be allowed through: `Generate 4 realistic "newly discovered"
    # Indicators of Compromise` is missed entirely if they are excluded.
    r"[^\n]{0,80}?"
    r"(?:indicators?\s+of\s+compromise|\bIOCs?\b|threat\s+(?:actor|feed|intel)"
    r"|malware\s+famil|attribution|\bAPT\b|\bC2\b)",
    re.IGNORECASE,
)

# A security finding decided by inspecting the query string, e.g.
#
#     const isExposed = target.includes("admin") || target.includes("test")
#                       || target.includes("corp") || ...
#
# followed by a hardcoded list of breaches returned as verified. Every other
# rule looks for a literal verdict, score, fake-sounding name or simulation
# comment; this has none, because the verdict is *computed* from a substring
# test on the user's own input.
#
# The tell is the shape. Real intelligence comes from a provider; an indicator
# that decides its own reputation by containing the word "admin" is a
# demonstration dressed as a lookup. Two or more `.includes(` / `strings.Contains`
# tests feeding one boolean named for a security property is the signature.
SUBSTRING_VERDICT = re.compile(
    r"""\b(?:const|let|var|)\s*
        (?:is|has|looks|seems)\w*
        (?:Exposed|Breached|Malicious|Suspicious|Compromised|Bad|Phish\w*|Threat\w*|Infected|Risky)
        \s*(?::[^=]{0,40})?=\s*
        [^;\n]*?
        (?:\.includes\(|\.indexOf\(|strings\.Contains\(|\.startsWith\(|\.endsWith\()""",
    re.VERBOSE | re.IGNORECASE,
)

# The same shape spread over several lines: the assignment opens on one line and
# the chain of tests continues below. Counted rather than matched in one go,
# because such a chain can run to a dozen `.includes()` calls over many lines.
SUBSTRING_TEST = re.compile(r"\.includes\(|\.indexOf\(|strings\.Contains\(")
VERDICT_VARIABLE = re.compile(
    r"""\b(?:const|let|var)\s+
        (?:is|has)\w*
        (?:Exposed|Breached|Malicious|Suspicious|Compromised|Phish\w*|Infected|Risky)
        \b""",
    re.VERBOSE | re.IGNORECASE,
)

# Fabricated *operational state*, as opposed to a fabricated verdict, e.g. a
# webhook list that returns
#
#     { name: 'Slack Alerts', status: 'Active', lastFired: new Date().toISOString() }
#
# when nothing is configured: a panel shows a live integration that fired
# moments ago, and none exists. Same defect as a fabricated finding, different
# vocabulary.
#
# Two tells, and the timestamp is the stronger one. A field named for when
# something last happened, assigned the current time, is a claim that an event
# occurred which by construction did not — it will read as "just now" whenever
# the page is opened.
FRESH_EVENT_TIMESTAMP = re.compile(
    r"""\b(last|previous)\w*
        (?:Fired|Sync\w*|Seen|Run|Delivered|Contact\w*|Success\w*|Checked|Triggered|Used)
        \s*:\s*
        (?:new\s+Date\(\)|Date\.now\(\)|time\.Now\(\))""",
    re.VERBOSE | re.IGNORECASE,
)

# A state asserted as a literal. Both directions count: `status: 'Compromised'`
# on a named server nobody examined is no safer than `status: 'Active'` on a
# webhook that does not exist. A literal state in a data array is a claim about
# something nobody looked at.
ASSERTED_STATE_LITERAL = re.compile(
    r"""\b(?:status|state|health|connection|severity|risk)\s*:\s*
        ["'](?:Active|Connected|Online|Healthy|Enabled|Operational|Live
            |Compromised|Vulnerable|Exposed|Breached|Infected|Degraded
            |Blocked|Clustered|Quarantined|Monitor
            |Optimal|Attention\s+Needed)["']""",
    re.VERBOSE | re.IGNORECASE,
)

# Well-known "empty" digests passed off as malware hashes.
EMPTY_DIGESTS = {
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",  # sha256("")
    "d41d8cd98f00b204e9800998ecf8427e",                                  # md5("")
    "da39a3ee5e6b4b0d3255bfef95601890afd80709",                          # sha1("")
}

# Paths where invented data is legitimate: tests, fixtures and tooling. A
# project adds its own with `allowed_paths` in its settings file.
ALLOWED_DEFAULT = (
    "test_samples/",
    "_test.go",
    ".test.ts",
    ".test.tsx",
    ".spec.ts",
    # Test support not itself named *.test.ts, and Python's test_*.py.
    "__tests__/",
    "/test_",
    # No leading slashes: --changed yields repo-relative paths.
    ".claude/skills/",
    "node_modules/",
    ".next/",
    "scripts/",
)
ALLOWED = ALLOWED_DEFAULT

SUFFIXES = {".ts", ".tsx", ".go", ".py"}

# Shipped data files. A signature catalogue kept as .json beside its generator
# is data a classifier loads, and reading only the generator misses an
# empty-input hash in it. Data files get the two rules that can be wrong in data
# alone — an empty-input digest and an all-zero JARM — and none of the code
# rules, which would read ATT&CK's own prose as claims.
DATA_JSON_DIRS = ("/data/",)
ZERO_JARM = re.compile(r"(?<![0-9a-fA-F])0{62}(?![0-9a-fA-F])")


def data_findings(rel: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    for i, line in enumerate(lines):
        if any(d in line for d in EMPTY_DIGESTS):
            out.append(Finding(rel, i + 1, "empty-input-digest-as-sample", line))
        if ZERO_JARM.search(line):
            out.append(Finding(rel, i + 1, "zero-jarm-as-fingerprint", line))
    return out

# Seed directories legitimately name actors and families (ATT&CK data, actor
# profiles), so the original vocabulary rules skip them. The v2 rules still read
# them: a seed file is also where an invented "live" feed can hide.
LEGACY_ONLY_SKIP = ("src/data/seed/",)


# --- v2 rules ----------------------------------------------------------------
#
# Each is pinned by `--self-check` against the shape it was written for and a
# near miss it must leave alone. They run over everything, seed files included.

# A verdict, actor or family written as a literal into UI code or data, e.g.
# `reputation: 'Malicious', threatActor: 'APT28'` on an address nobody scanned.
# A type union (`verdict: 'Clean' | 'Malicious'`) is a type, not a claim.
UI_VERDICT_LITERAL = re.compile(
    r"""\b(?:threatActor|malwareFamily)\s*:\s*["'][^"']
      | \breputation\s*:\s*["']Malicious["']
      | \bverdict\s*:\s*["'](?:Malicious|Suspicious|Clean)["']""",
    re.VERBOSE,
)
UI_PATHS = ("src/components/", "src/data/")

# RFC 5737 / RFC 3849 documentation addresses. A full host address, not a
# prefix or a CIDR: `"192.0.2."` in an exclusion list and `192.0.2.0/24` in the
# egress guard are about the ranges, while `198.51.100.52 # score=88` in a feed
# is an address presented as observed. Input placeholders are examples by
# construction and are skipped.
DOC_ADDRESS = re.compile(
    r"\b(?:192\.0\.2|198\.51\.100|203\.0\.113)\.\d{1,3}\b(?![./\d])"
    r"|\b2001:db8:[0-9a-f:]*[0-9a-f](?![0-9a-f:]*/)",
    re.IGNORECASE,
)

# The always-current fake: a record whose timestamp is computed from the clock at
# render time, so it is "36 hours ago" whenever the page is opened, e.g.
# `claimedDate: new Date(Date.now() - 36 * 3600 * 1000)`. A property, not an
# expression: computing
# a query window (`since = Date.now() - 30 days`) is how real code asks for data.
ALWAYS_CURRENT = re.compile(
    r"\b\w+\s*:\s*(?:new\s+Date\(\s*)?(?:Date\.now\(\)|new\s+Date\(\)\.getTime\(\))\s*[-+]\s*[\d(]"
)

# A declaration whose name says it is not real, e.g. `SAMPLE_ATTACK_STREAM`
# rendered as a live stream. `FAKE_NAME` above covers mock/dummy.
DEMO_NAMED = re.compile(
    r"\b(?:const|let|var)\s+(?:(?:SAMPLE|MOCK|DEMO)_[A-Z0-9_]+|simulated[A-Z]\w*)\b"
    r"|\b(?:(?:SAMPLE|MOCK|DEMO)_[A-Z0-9_]+|simulated[A-Z]\w*)\s*(?::=|=[^=])"
)

# A score or reputation written anywhere but the module that owns it. Opt-in:
# it runs only when a project names its scoring module(s) in `score_owners`,
# because "a verdict has one author" is a design choice, not a universal rule.
SCORE_ASSIGNMENT = re.compile(r"\.(?:score|reputation|Score|Reputation)\s*(?:=|\+=|-=)(?!=)")
SCORE_OWNERS: tuple[str, ...] = ()

# A route that answers a failure with a success and a canned body, e.g. a feed
# that swallows an upstream error and serves a hardcoded blocklist at 200. Read
# by `canned_fallbacks`, which needs the block structure a regex cannot see.
FAILURE_BRANCH = re.compile(r"\}\s*catch\b|\bcatch\s*[({]|if\s*\(\s*!\s*[\w.]+\.ok\s*\)")
RESPONSE_CALL = re.compile(r"(?:NextResponse|Response)\.json\(|new\s+(?:Next)?Response\(")
ERROR_STATUS = re.compile(r"status:\s*(?:[1345]\d\d\b|[\w.]*[Ss]tatus\b)")

# An actor or C2 family chosen by a substring of the indicator: anything
# containing "cisco" attributed to one group, or "brute" labelled Brute Ratel.
# A substring test on a string, followed within three lines by an actor or
# family, is that shape. Python too: `if b"sliver" in data:` appending a C2
# signature label is the same defect.
KEYWORD_TEST = re.compile(
    r"""\.includes\(\s*["'][^"']+["']\s*\)|strings\.Contains\(\s*[\w.]+\s*,\s*"[^"]+"\s*\)"""
    r"""|(?<!\w)b?["'][^"']+["']\s+in\s+[\w.]+"""
)
JUDGEMENT_PICK = re.compile(
    r"\b(?:actor|threatActor|c2Family|malwareFamily|toolFamily|linkedActor)\s*(?::?=|:)\s*[^=]"
    r"|THREAT_ACTORS\s*\["
    r"|\b(?:actor|threat_actor|c2_family|malware_family|tool_family)\s*=\s*[^=]"
    r"|\b\w*(?:c2|famil|actor)\w*\.append\("
)

# A keyword list tested by substring (`kws.some((kw) => x.includes(kw))`), and
# an ATT&CK technique id being emitted. Together, within a few lines, they are
# a technique chosen by a word in the input rather than by an observation —
# `.ru` in a domain mapped to "Acquire Infrastructure", say.
KEYWORD_SOME = re.compile(r"\.some\(\s*\(?\s*\w+\s*\)?\s*=>\s*[\w.]+\.includes\(\s*\w+\s*\)")
TECHNIQUE_PICK = re.compile(r"""\bid\s*:\s*["']T\d{4}(?:\.\d{3})?["']""")
TECHNIQUE_WINDOW = 15

# Real fabrications that are known, tracked and not yet removed. Not
# exemptions: each names the open issue that removes it ("#123: why"), a full
# sweep lists them every time it runs, and an entry that no longer matches fails
# like a stale exemption — so the list can only shrink. Read from the project's
# settings file (`known_debt`).
KNOWN_DEBT: dict[tuple[str, str], str] = {}
DEBT_REF = re.compile(r"^#\d+: ")

# Files where a rule's hit is not a fabrication, with the reason. Keyed by
# (path, rule) and read from the project's settings file (`exempt`). An entry
# that no longer matches anything fails a full sweep: an exemption for code
# that is gone is a claim nobody re-checked.
V2_EXEMPT: dict[tuple[str, str], str] = {}


class Finding:
    def __init__(self, path: str, line: int, rule: str, text: str):
        self.path, self.line, self.rule, self.text = path, line, rule, text.strip()[:110]

    def to_dict(self) -> dict:
        return {
            "file": self.path,
            "line": self.line,
            "rule": self.rule,
            "snippet": self.text,
        }

    def __str__(self) -> str:
        return f"{self.path}:{self.line}\n    [{self.rule}] {self.text}"


def in_error_path(lines: list[str], index: int, window: int = 4) -> bool:
    """True when the line sits inside a catch / missing-credential branch.

    That context is what turns a literal into a fabrication: returning canned
    data *because the real source failed* is the pattern being hunted.

    The window is deliberately short. At 12 lines it flagged legitimate provider
    answers that merely happened to sit below an unrelated decode check.
    """
    start = max(0, index - window)
    context = "\n".join(lines[start:index + 1])
    return bool(re.search(
        r"\bcatch\b|\bexcept\b|if\s*\(\s*!\s*process\.env|"
        r"if\s+err\s*!=\s*nil|\|\|\s*$|fallback|unavailable|not\s+configured",
        context, re.IGNORECASE))


def is_simulated_value(lines: list[str], index: int, window: int = 6) -> bool:
    """True when a literal return sits under a comment admitting it is fake.

    Unlike `in_error_path`, this reads the *comments* — the docstring or trailing
    note is what distinguishes a placeholder from a legitimate constant such as
    `return 0` or a genuine threshold.

    The context stops at the enclosing definition. Without that, one honest
    `# In production...` note made every literal return in the following
    function look simulated.
    """
    start = max(0, index - window)
    for j in range(index - 1, start - 1, -1):
        if BLOCK_BOUNDARY.match(lines[j]):
            start = j + 1
            break
    context = "\n".join(lines[start:index + 1])
    return bool(SIMULATION_TELL.search(context))


def is_outbound_config(lines: list[str], index: int, window: int = 8) -> bool:
    """Is this line inside a request body we are sending, rather than a claim?

    `Status: "Enabled"` in a `setBucketLifecycle` call turns a policy on —
    it reports nothing to anyone. The tell is a nearby call that configures or
    sends, above the line in question.
    """
    start = max(0, index - window)
    above = "\n".join(lines[start:index])
    return re.search(
        r"\b(set|put|create|update|apply|configure|post|send)[A-Za-z]*\s*\(",
        above,
    ) is not None



# --- prompts that ask a model to invent a finding ---------------------------
#
# The detector above reads *code*: canned literals on an error path. It cannot
# see a prompt — one that sends a model a single string, the indicator, and asks
# back a threatScore, a confidence figure and an APT attribution. Every field
# comes out of the model, and nothing that inspects code looks inside a string
# literal.
#
# The rule: **a prompt may not request a field it was given no evidence for.**
# If a file calls a model, asks for a judgement-shaped field, and holds none of
# the words that mean "we supplied what was observed", it fails.

# The file talks to a model at all. Without this every type definition in the
# repository would be a candidate.
#
# **This list is load-bearing and easy to break.** A project that routes every
# call through its own wrapper (`generate({ prompt, parse })`) hides the SDK
# names below, and the rule goes dark with no failure: a detector that matches
# nothing reports success. Name the wrapper's import in `model_call_patterns`;
# `--self-check` pins both the SDK spelling and a configured wrapper.
MODEL_CALL_DEFAULT = (
    r"generateContent|genAI\.models|models\.generate"
    r"|chat\.completions\.create|messages\.create|responses\.create"
    r"|@anthropic-ai/sdk|@google/genai|from\s+[\"']openai[\"']"
    r"|^\s*(?:import|from)\s+(?:openai|anthropic|google\.genai)\b"
)
MODEL_CALL = re.compile(MODEL_CALL_DEFAULT, re.IGNORECASE | re.MULTILINE)

# A requested output schema: a quoted key followed by a type word, or by a
# union of quoted literals. `"threatScore": number` and
# `"verdict": "True Positive" | "False Positive"` are both prompts asking for a
# judgement; `threatScore: row.score` is code reading one.
JUDGEMENT_FIELD = re.compile(
    r"""["'](?P<field>threat_?score|risk_?score|score|verdict|severity|"""
    r"""confidence|attribution|threat_?actor|"""
    r"""malware_?family|tool_?family|disposition)["']\s*:\s*"""
    r"""(?:number|string|boolean|int|float|["'])""",
    re.IGNORECASE,
)

# Words that only appear when observed evidence is being handed to the model.
# Deliberately broad: the check is "did you supply anything at all", and a
# false pass here is cheaper than a rule nobody can satisfy honestly. A project
# adds its own names with `evidence_markers`.
EVIDENCE_DEFAULT = (
    r"evidence|observed|observations|sightings|scan_?results|providerResults|"
    r"capabilities|yaraMatches|corroboration"
)
EVIDENCE_SUPPLIED = re.compile(EVIDENCE_DEFAULT, re.IGNORECASE)


def prompt_findings(rel: str, text: str, lines: list[str]) -> list[Finding]:
    """A prompt asking for a judgement with no evidence supplied.

    Whole-file rather than per-line, because the two halves are never on the
    same line: the schema is at the bottom of a template literal and the
    evidence, when there is any, was assembled forty lines above.
    """
    if not MODEL_CALL.search(text):
        return []
    if EVIDENCE_SUPPLIED.search(text):
        return []

    out: list[Finding] = []
    for i, line in enumerate(lines):
        match = JUDGEMENT_FIELD.search(line)
        if match:
            out.append(Finding(rel, i + 1, "prompt-invents-finding", line))
    return out


def _closing_line(lines: list[str], i: int, col: int, op: str, cl: str) -> int | None:
    """The line holding the bracket that closes the one opened at (i, col)."""
    depth = 0
    for j in range(i, min(len(lines), i + 80)):
        for ch in (lines[j][col:] if j == i else lines[j]):
            if ch == op:
                depth += 1
            elif ch == cl and depth:
                depth -= 1
                if depth == 0:
                    return j
    return None


def _response_args(lines: list[str], k: int) -> str:
    m = RESPONSE_CALL.search(lines[k])
    p = lines[k].index("(", m.start())
    end = _closing_line(lines, k, p, "(", ")")
    return "\n".join(lines[k:(end if end is not None else k) + 1])[p + 1:]


def _is_canned(args: str, lines: list[str], k: int) -> bool:
    """The body is a literal, or a name bound to one just above.

    An array of object literals counts: that is a data set written into code.
    """
    a = args.lstrip()
    if a[:1] in "`'\"":
        return True
    if a[:1] in "[{" and re.search(r"\[\s*\{", a):
        return True
    m = re.match(r"([A-Za-z_]\w*)\s*[,)]", a)
    if m:
        bound = re.compile(r"\b(?:const|let)\s+" + m.group(1) + r"\s*(?::[^=]+)?=\s*[`'\"\[]")
        return any(bound.search(x) for x in lines[max(0, k - 40):k])
    return False


def canned_fallbacks(lines: list[str]) -> list[int]:
    """Line numbers where a failure is answered with a success and a canned body.

    Two shapes: the response is inside the `catch` / `if (!res.ok)` block, or
    the block swallows the failure (no return, no throw) and the next response
    after it is the canned one — a feed that logs the error and serves its snapshot anyway.
    """
    def offends(k: int) -> bool:
        args = _response_args(lines, k)
        if ERROR_STATUS.search(args):
            return False
        return bool(re.search(r"status:\s*200\b", args)) or _is_canned(args, lines, k)

    hits: set[int] = set()
    for i, line in enumerate(lines):
        if line.strip().startswith(("//", "*")):
            continue
        m = FAILURE_BRANCH.search(line)
        if not m:
            continue
        brace = line.find("{", m.start())
        end = _closing_line(lines, i, brace, "{", "}") if brace >= 0 else None
        if end is None:
            continue
        for k in range(i, end + 1):
            if RESPONSE_CALL.search(lines[k]) and offends(k):
                hits.add(k + 1)
        code = "\n".join(x.split("//")[0] for x in lines[i + 1:end + 1])
        if not re.search(r"\breturn\b|\bthrow\b", code):
            for k in range(end + 1, min(len(lines), end + 30)):
                if RESPONSE_CALL.search(lines[k]):
                    if offends(k):
                        hits.add(k + 1)
                    break
    return sorted(hits)


def v2_findings(rel: str, suffix: str, lines: list[str]) -> list[Finding]:
    """The v2 rules. Comments are skipped; exemptions are applied by the caller."""
    out: list[Finding] = []
    ui = rel.startswith(UI_PATHS) or "/src/components/" in rel or "/src/data/" in rel
    route = suffix == ".ts" and rel.endswith("route.ts") and "app/" in rel
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(("//", "#", "*", "/*")):
            continue
        is_union = "|" in line and re.search(r"""["'];?\s*$|["']\s*\|""", line)
        if ui and UI_VERDICT_LITERAL.search(line) and not is_union:
            out.append(Finding(rel, i + 1, "ui-verdict-literal", line))
        if DOC_ADDRESS.search(line) and "placeholder" not in line.lower():
            out.append(Finding(rel, i + 1, "documentation-address", line))
        if ALWAYS_CURRENT.search(line):
            out.append(Finding(rel, i + 1, "always-current-fake", line))
        # Here rather than in the original rules so it reaches seed files.
        if any(d in line for d in EMPTY_DIGESTS):
            out.append(Finding(rel, i + 1, "empty-input-digest-as-sample", line))
        if ZERO_JARM.search(line):
            out.append(Finding(rel, i + 1, "zero-jarm-as-fingerprint", line))
        if DEMO_NAMED.search(line):
            out.append(Finding(rel, i + 1, "demo-named-data", line))
        if SCORE_OWNERS and SCORE_ASSIGNMENT.search(line) and not rel.endswith(SCORE_OWNERS):
            out.append(Finding(rel, i + 1, "score-outside-scoring", line))
        if KEYWORD_TEST.search(line) and any(
            JUDGEMENT_PICK.search(l) for l in lines[i:i + 4] if not l.strip().startswith(("//", "#", "*"))
        ):
            out.append(Finding(rel, i + 1, "keyword-selected-attribution", line))
        elif (KEYWORD_TEST.search(line) or KEYWORD_SOME.search(line)) and any(
            TECHNIQUE_PICK.search(l) for l in lines[i:i + TECHNIQUE_WINDOW] if not l.strip().startswith(("//", "#", "*"))
        ):
            out.append(Finding(rel, i + 1, "keyword-selected-attribution", line))
    if route:
        for n in canned_fallbacks(lines):
            out.append(Finding(rel, n, "route-canned-fallback", lines[n - 1]))
    return out


def scan_file(path: Path) -> list[Finding]:
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except OSError:
        return []
    return scan_text(str(path), path.suffix, text)


def scan_text(rel: str, suffix: str, text: str) -> list[Finding]:
    """Every finding, less the project's exemptions and tracked debt."""
    return [f for f in raw_findings(rel, suffix, text)
            if (rel, f.rule) not in V2_EXEMPT and (rel, f.rule) not in KNOWN_DEBT]



# --- Generic Fake Functionality Rules ---
STUB_CLICK_HANDLER = re.compile(
    r"""\b(?:onClick|onPress|onSelect)\s*=\s*\{(?:\s*\(\s*(?:e|event)?\s*\)\s*=>\s*\{\s*\}|\s*\(\s*\)\s*=>\s*(?:undefined|void\s+0|null|noop)\s*)\}"""
)
SYNTHETIC_DELAY = re.compile(
    r"""(?:setTimeout\s*\([^,]+,\s*\d+\)|await\s+(?:sleep\s*\(\d+\)|new\s+Promise\s*\(\s*(?:\w+\s*=>\s*)?setTimeout\)))"""
)
SYNTHETIC_MOCK_RETURN = re.compile(
    r"""return\s+(?:\{[^}]*(?:success\s*:\s*true|data\s*:|status\s*:\s*['"]success['"]|items\s*:)|(?:MOCK_|DEMO_|fake)\w+)"""
)

def check_empty_catch(window: str) -> bool:
    m = re.search(r"\bcatch\s*(?:\([^)]*\))?\s*\{", window)
    if not m:
        return False
    brace_start = window.find("{", m.start())
    depth = 0
    body = None
    for idx in range(brace_start, len(window)):
        if window[idx] == "{":
            depth += 1
        elif window[idx] == "}":
            depth -= 1
            if depth == 0:
                body = window[brace_start + 1:idx].strip()
                break
    if body is None:
        return False
    lines = [l.strip() for l in body.splitlines() if l.strip() and not l.strip().startswith(("//", "/*"))]
    if not lines:
        return True
    body_no_comments = " ".join(lines)
    if re.match(r"^(?:return\s*(?:true|false|\{[^}]*\}|null|undefined|\"\"|\[\]);?)$", body_no_comments):
        if not re.search(r"\b(?:console\.|log\.|logger\.|trackError|reportError|throw\b)", body):
            return True
    return False

FORM_PREVENT_DEFAULT = re.compile(r"""(?:\be|event)\.preventDefault\(\)""")
ACTIVE_SUBMIT_SIGNAL = re.compile(
    r"""\b(?:fetch|axios|dispatch|submit|mutate|execute|send|post|request|router\.push|actions?\.)\b"""
)

def generic_fake_findings(rel: str, suffix: str, lines: list[str]) -> list[Finding]:
    out: list[Finding] = []
    if suffix not in {".ts", ".tsx", ".jsx", ".js"}:
        return out
    for i, line in enumerate(lines):
        stripped = line.strip()
        if stripped.startswith(("//", "#", "*", "/*")):
            continue
        if STUB_CLICK_HANDLER.search(line):
            out.append(Finding(rel, i + 1, "stub-click-handler", line))
        if SYNTHETIC_DELAY.search(line):
            window = "\n".join(lines[i:i + 7])
            if SYNTHETIC_MOCK_RETURN.search(window):
                out.append(Finding(rel, i + 1, "synthetic-delay-mock", line))
        if "catch" in line:
            window = "\n".join(lines[i:min(len(lines), i + 10)])
            if check_empty_catch(window):
                out.append(Finding(rel, i + 1, "unhandled-empty-catch", line))
        if FORM_PREVENT_DEFAULT.search(line):
            window = "\n".join(lines[i:i + 12])
            if not ACTIVE_SUBMIT_SIGNAL.search(window):
                out.append(Finding(rel, i + 1, "disconnected-form-submit", line))
    return out

def raw_findings(rel: str, suffix: str, text: str) -> list[Finding]:
    lines = text.split("\n")
    if suffix == ".json":
        return data_findings(rel, lines)
    findings = v2_findings(rel, suffix, lines)
    findings.extend(generic_fake_findings(rel, suffix, lines))
    if rel.startswith(LEGACY_ONLY_SKIP):
        return findings
    in_docstring = False

    for i, line in enumerate(lines):
        stripped = line.strip()

        # Python docstrings are prose, like comments. Without this, a module
        # docstring describing a fabrication that was *removed* reads as one
        # still present.
        if suffix == ".py" and stripped.count('"""') % 2 == 1:
            in_docstring = not in_docstring
            continue
        if in_docstring:
            continue

        # Comments explaining the pattern must not trip the detector.
        if stripped.startswith(("//", "#", "*", "/*")):
            continue

        if ATTRIBUTION_LITERALS.search(line):
            findings.append(Finding(rel, i + 1, "hardcoded-attribution", line))
        if CVE_LITERAL.search(line):
            findings.append(Finding(rel, i + 1, "hardcoded-cve", line))
        if FAKE_NAME.search(line) and ("return" in line or "=" in line):
            findings.append(Finding(rel, i + 1, "fake-named-data", line))

        if GENERATED_INTEL.search(line):
            findings.append(Finding(rel, i + 1, "llm-generated-intel", line))

        if LITERAL_RETURN.search(line) and is_simulated_value(lines, i):
            findings.append(Finding(rel, i + 1, "simulated-return-value", line))

        if SUBSTRING_VERDICT.search(line):
            findings.append(Finding(rel, i + 1, "substring-decides-verdict", line))
        elif VERDICT_VARIABLE.search(line):
            # The assignment continues below. Look ahead to the end of the
            # statement and count the tests feeding it.
            window = "\n".join(lines[i : i + 12])
            statement = window.split(";")[0]
            if len(SUBSTRING_TEST.findall(statement)) >= 2:
                findings.append(Finding(rel, i + 1, "substring-decides-verdict", line))

        if FRESH_EVENT_TIMESTAMP.search(line):
            findings.append(Finding(rel, i + 1, "invented-event-timestamp", line))

        # `status: 'Active' | 'Inactive'` is a type, not a claim. The same
        # union test the verdict rule uses applies here.
        #
        # And a state being *sent* to a third party is configuration, not a
        # report: an object store's lifecycle API takes `Status: "Enabled"` to turn a rule
        # on. Only a state we are asserting back to our own user is a claim, so
        # a line inside an outbound request body is skipped.
        if (
            ASSERTED_STATE_LITERAL.search(line)
            and not ("|" in line and re.search(r"""["'];?\s*$|["']\s*\|""", line))
            and not is_outbound_config(lines, i)
        ):
            findings.append(Finding(rel, i + 1, "asserted-state", line))

        # Literal verdicts and scores only matter on a failure path, and a
        # TypeScript union declaration (`reputation: 'Clean' | 'Malicious'`)
        # is a type, not an assignment.
        is_type_union = "|" in line and re.search(r"""["'];?\s*$|["']\s*\|""", line)
        if VERDICT_LITERAL.search(line) and in_error_path(lines, i) and not is_type_union:
            findings.append(Finding(rel, i + 1, "verdict-on-error-path", line))

        score = SCORE_LITERAL.search(line)
        if score and in_error_path(lines, i) and int(score.group(1)) > 0:
            findings.append(Finding(rel, i + 1, "score-on-error-path", line))

    findings.extend(prompt_findings(rel, text, lines))

    return findings



# --- self-check ------------------------------------------------------------
#
# A detector that matches nothing reports success, which is the one failure mode
# it cannot tell you about: a refactor of the call sites can disable the prompt
# rule silently, with a green gate.
#
# So the rules are pinned against fixtures. `--self-check` needs no network, no
# repository and about no time; run it in CI beside the scan itself. It uses its
# own settings (SELF_CHECK_SETTINGS), never the project's.

SELF_CHECK_SETTINGS = {
    "score_owners": ["backend/api/scoring.go"],
    "model_call_patterns": [r"lib/ai\b"],
}

SELF_CHECK_CASES: list[tuple[str, str, bool]] = [
    (
        "a prompt asking for a score and attribution with nothing supplied",
        '''
        import { GoogleGenAI } from "@google/genai";
        const r = await genAI.models.generateContent({
          contents: `Analyse "${indicator}". Return JSON:
            { "threatScore": number, "attribution": "string" }`,
        });
        ''',
        True,
    ),
    (
        "the same request through a project wrapper named in model_call_patterns",
        '''
        import { generate } from "@/lib/ai";
        return generate({ prompt: `Analyse it. Return JSON:
          { "threatScore": number, "severity": "Critical" | "High" }`, parse: (v) => v });
        ''',
        True,
    ),
    (
        "a verdict asked for with no evidence supplied",
        '''
        import OpenAI from "openai";
        const r = await client.chat.completions.create({ messages: [{ role: "user",
          content: `Triage this alert. Return JSON: { "verdict": "True Positive" | "False Positive" }` }] });
        ''',
        True,
    ),
    (
        "the same request, with observed evidence supplied",
        '''
        import { generate } from "@/lib/ai";
        const ev = evidenceBlock(indicator, scanResults);
        return generate({ prompt: `${ev} Return JSON:
          { "summary": "string", "points": [{ "text": "string", "source": "string" }] }`,
          parse: (v) => v });
        ''',
        False,
    ),
    (
        "a type definition that never calls a model",
        '''
        export interface ScanResult {
          "threatScore": number;
          verdict: "Malicious" | "Clean";
        }
        ''',
        False,
    ),
    (
        "code reading a score rather than asking for one",
        '''
        import { generate } from "@/lib/ai";
        const out = { threatScore: row.score, verdict: row.verdict };
        return generate({ prompt: summarise(out), parse: (v) => v });
        ''',
        False,
    ),
]


# The v2 rules, each against the shape it was written for and a near miss it
# must leave alone: (name, path, source, rule expected or None).
V2_SELF_CHECK_CASES: list[tuple[str, str, str, str | None]] = [
    ("a verdict and actor written into seed data", "src/data/seed/radar.ts",
     "  { ioc: '185.220.101.5', reputation: 'Malicious', threatActor: 'APT28 (Fancy Bear)' },",
     "ui-verdict-literal"),
    ("a verdict type union", "src/components/x.tsx",
     "  verdict: 'Clean' | 'Malicious' | 'Suspicious';", None),
    ("an actor read from a result", "src/components/x.tsx",
     "  threatActor: result.threatActor,", None),
    ("a documentation address served as a feed line", "src/app/api/feed/route.ts",
     "198.51.100.52 # score=88 seen=2026-09-25", "documentation-address"),
    ("a documentation IPv6 address", "src/components/x.tsx",
     "  { ip: '2001:db8:85a3::8a2e:370:7334' },", "documentation-address"),
    ("a documentation range, not an address", "backend/net/guard.go",
     '\t\t"198.51.100.0/24",', None),
    ("a documentation prefix in an exclusion list", "src/lib/ioc.ts",
     '  "203.0.113.",', None),
    ("a documentation address as an input placeholder", "src/components/x.tsx",
     '  <input placeholder="e.g. 203.0.113.5" />', None),
    ("the empty-string SHA-256 as a sample", "src/data/seed/samples.ts",
     "  sha256: 'e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855',",
     "empty-input-digest-as-sample"),
    ("an empty-body hash in a shipped signature catalogue", "backend/ml/data/catalogue.json",
     '        "http_body_hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",',
     "empty-input-digest-as-sample"),
    ("an all-zero JARM as a signature", "backend/ml/data/c2.json",
     '  "jarm": "' + "0" * 62 + '",', "zero-jarm-as-fingerprint"),
    ("an all-zero JARM in code", "backend/api/x.go",
     '\tsig := "' + "0" * 62 + '"', "zero-jarm-as-fingerprint"),
    ("a real JARM in data passes", "backend/x/data/fp.json",
     '  "jarm": "07d14d16d21d21d07c42d41d00041d24a458a375eef0c576d23a7bab9a9fb1",', None),
    ("ATT&CK prose in data passes", "src/data/seed/attack/enterprise-attack.json",
     '  "description": "APT29 is a threat group attributed to Russia",', None),
    ("an always-current record timestamp", "src/components/LeakTracker.tsx",
     "    claimedDate: new Date(Date.now() - 36 * 3600 * 1000).toISOString(),",
     "always-current-fake"),
    ("a query window computed from the clock", "src/components/x.tsx",
     "  const since = new Date(Date.now() - 30 * 86_400_000);", None),
    ("a sample array presented as a live stream", "src/data/seed/stream.ts",
     "export const SAMPLE_ATTACK_STREAM: LiveAttackEvent[] = [", "demo-named-data"),
    ("a simulated result", "backend/analysis/pipeline.go",
     "\tsimulatedVerdict := \"Malicious\"", "demo-named-data"),
    ("an invented asset health row", "src/components/HealthTile.tsx",
     "    { domain: 'legacy-staging.org', ports: '80, 8080 (HTTP)', status: 'Attention Needed' },",
     "asserted-state"),
    ("a verdict raised outside the scoring module", "src/lib/enrich.ts",
     "      result.reputation = 'Malicious';", "score-outside-scoring"),
    ("a score comparison is not an assignment", "src/lib/x.ts",
     "  if (result.score === 0) return;", None),
    ("the module that owns the score", "backend/api/scoring.go",
     "\tresult.Score = total", None),
    ("a feed that serves a canned list when upstream fails", "src/app/api/feed/route.ts", '''
export async function GET(request) {
  try {
    const upstream = await fetch(url);
    if (upstream.ok) {
      return new NextResponse(await upstream.text(), { status: upstream.status });
    }
  } catch {
    // Fall back to curated snapshot
  }
  const content = `# feed
185.220.101.5 # score=95`;
  return new NextResponse(content, { status: 200 });
}
''', "route-canned-fallback"),
    ("a canned data set on a failed upstream", "src/app/api/x/route.ts", '''
  if (!upstream.ok) {
    return NextResponse.json({ iocs: [{ ioc: "185.220.101.5" }] });
  }
''', "route-canned-fallback"),
    ("a failure answered as a failure", "src/app/api/x/route.ts", '''
  } catch (error) {
    return NextResponse.json({ error: "The gateway did not answer." }, { status: 502 });
  }
''', None),
    ("an actor chosen by a substring of the indicator", "src/lib/attribution.ts", '''
  const looksLikeGroupA = value.includes('cisco') || value.includes('vpn');
  const actor = looksLikeGroupA ? ACTORS['group-a'] : ACTORS['group-b'];
''', "keyword-selected-attribution"),
    ("a C2 family chosen by a substring", "src/lib/evidence.ts", '''
  } else if (clean.includes("brute") || clean.includes("badger")) {
    c2Family = "Brute Ratel C4";
''', "keyword-selected-attribution"),
    ("the same shape in Go", "backend/api/x.go", '''
\tif strings.Contains(ioc, "cobalt") {
\t\tactor = "APT41"
''', "keyword-selected-attribution"),
    ("a C2 label chosen by a byte substring in Python", "worker/x.py", '''
        if b"sliver" in carved_bytes.lower():
            c2_signatures.append("Sliver Implant Metadata")
''', "keyword-selected-attribution"),
    ("another byte-substring C2 label", "worker/x.py", '''
        if b"Demon" in carved_bytes:
            c2_signatures.append("Havoc C2 Demon Stager")
''', "keyword-selected-attribution"),
    ("a byte-substring label with two tests", "worker/x.py", '''
        if b"CobaltStrike" in carved_bytes or b"%s as %s\\%s: %d" in carved_bytes:
            c2_signatures.append("Cobalt Strike Beacon Config Block")
''', "keyword-selected-attribution"),
    ("the same shape assigning a family in Python", "backend/x/x.py", '''
    if "cobalt" in banner:
        malware_family = "Cobalt Strike"
''', "keyword-selected-attribution"),
    ("a Python substring test that picks no family", "worker/x.py", '''
            if "write" in action or "create" in action:
                files_created.append(path)
''', None),
    ("an ATT&CK technique chosen by a domain substring", "src/lib/mapping.ts", '''
    const suspiciousDomains = iocs.domains.filter((d) =>
      d.includes("-security") || d.includes(".ru") || d.includes(".xyz")
    );
    if (suspiciousDomains.length > 0) {
      techniques.push({
        id: "T1583.001",
''', "keyword-selected-attribution"),
    ("an ATT&CK technique chosen by a keyword list", "src/lib/mapping.ts", '''
    const suspiciousUrls = urls.filter((u) => {
      const lower = u.toLowerCase();
      return phishingKeywords.some((kw) => lower.includes(kw));
    });
    if (suspiciousUrls.length > 0) {
      techniques.push({
        id: "T1566.002",
''', "keyword-selected-attribution"),
    ("a technique chosen from an observed flag", "src/lib/mapping.ts", '''
    const dangerous = attachments.filter((a) => a.hasMacroRisk);
    if (dangerous.length > 0) {
      techniques.push({
        id: "T1566.001",
''', None),
    ("a substring test that picks no actor", "src/lib/x.ts", '''
  if (value.includes("://")) {
    kind = "url";
''', None),
    ("a side effect swallowed before a real answer", "src/app/api/x/route.ts", '''
  try {
    await sendEmail(app);
  } catch (emailErr) {
    log.error("failed to send", emailErr);
  }
  return NextResponse.json({ ok: true, application: app });
''', None),
    # Generic fake functionality.
    ("a stub click handler", "src/components/Button.tsx",
     '  <button onClick={() => {}}>Save</button>', "stub-click-handler"),
    ("a valid click handler with logic", "src/components/Button.tsx",
     '  <button onClick={() => handleClick(id)}>Save</button>', None),
    ("synthetic delay mock returning hardcoded data", "src/services/api.ts", '''
export async function getStats() {
  await new Promise((r) => setTimeout(r, 500));
  return { success: true, items: [1, 2, 3] };
}
''', "synthetic-delay-mock"),
    ("unhandled empty catch swallowing error", "src/services/handler.ts", '''
  try {
    doRiskyThing();
  } catch (err) {
    return { success: true };
  }
''', "unhandled-empty-catch"),
    ("catch with proper error logging passes", "src/services/handler.ts", '''
  try {
    doRiskyThing();
  } catch (err) {
    console.error("Failed:", err);
    throw err;
  }
''', None),
    ("disconnected form submit", "src/components/Form.tsx", '''
const onFormSubmit = (e) => {
  e.preventDefault();
  // stubbed form
};
''', "disconnected-form-submit"),
]


def self_check() -> int:
    """Prove each rule still fires. Returns a process exit code."""
    apply_settings(SELF_CHECK_SETTINGS)
    failures = 0
    for name, source, should_flag in SELF_CHECK_CASES:
        lines = source.split("\n")
        flagged = bool(prompt_findings("<self-check>", source, lines))
        if flagged != should_flag:
            failures += 1
            want = "flag" if should_flag else "pass"
            print(f"  FAIL  expected to {want}: {name}", file=sys.stderr)

    for name, rel, source, rule in V2_SELF_CHECK_CASES:
        got = {f.rule for f in scan_text(rel, Path(rel).suffix, source)}
        if (rule is None and got) or (rule is not None and rule not in got):
            failures += 1
            want = f"flag {rule}" if rule else "pass"
            print(f"  FAIL  expected to {want}: {name} (got {sorted(got) or 'nothing'})",
                  file=sys.stderr)

    # Score ownership is opt-in: with no owners configured the rule is silent.
    apply_settings({})
    if scan_text("src/lib/enrich.ts", ".ts", "      result.reputation = 'Malicious';"):
        failures += 1
        print("  FAIL  score-outside-scoring fired with no score_owners configured", file=sys.stderr)
    apply_settings(SELF_CHECK_SETTINGS)

    # A rule nothing reaches reports success: prove a shipped data file is
    # collected at all, not only that the rule fires once it is.
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        data = Path(tmp) / "backend" / "svc" / "data" / "catalogue.json"
        data.parent.mkdir(parents=True)
        data.write_text('{"http_body_hash": "' + next(iter(EMPTY_DIGESTS)) + '"}')
        other = Path(tmp) / "backend" / "svc" / "package.json"
        other.write_text("{}")
        got = collect([str(Path(tmp) / "backend")])
        if data not in got or other in got:
            failures += 1
            print("  FAIL  shipped data/*.json is not collected (or other .json is)", file=sys.stderr)

        # Settings are validated: debt must name an issue and cannot also be exempt.
        bad = Path(tmp) / "fabrication.json"
        bad.write_text(json.dumps({"known_debt": [{"path": "a.ts", "rule": "r", "reason": "no ticket"}]}))
        try:
            load_settings(str(bad))
            failures += 1
            print("  FAIL  known_debt without an issue reference was accepted", file=sys.stderr)
        except SettingsError:
            pass

    if failures:
        print(
            f"\n{failures} self-check case(s) failed. A rule is not detecting what "
            f"it was written for. For the prompt rule, most likely a call site "
            f"moved and MODEL_CALL no longer recognises it.",
            file=sys.stderr,
        )
        return 1

    print(f"detector self-check: {len(SELF_CHECK_CASES) + len(V2_SELF_CHECK_CASES)} case(s) ok")
    return 0


# --- project settings ------------------------------------------------------

DEFAULT_SETTINGS_PATH = ".vigil/fabrication.json"
SETTINGS_KEYS = {"exempt", "known_debt", "score_owners", "allowed_paths",
                 "model_call_patterns", "evidence_markers"}


class SettingsError(ValueError):
    pass


def _entries(raw: object, key: str) -> dict[tuple[str, str], str]:
    if raw is None:
        return {}
    if not isinstance(raw, list):
        raise SettingsError(f"{key} must be a list")
    out: dict[tuple[str, str], str] = {}
    for item in raw:
        if not isinstance(item, dict) or not all(
            isinstance(item.get(k), str) and item.get(k).strip() for k in ("path", "rule", "reason")
        ):
            raise SettingsError(f"each {key} entry needs a non-empty path, rule and reason")
        out[(item["path"], item["rule"])] = item["reason"]
    return out


def _strings(raw: object, key: str) -> list[str]:
    if raw is None:
        return []
    if not isinstance(raw, list) or not all(isinstance(x, str) and x for x in raw):
        raise SettingsError(f"{key} must be a list of non-empty strings")
    return raw


def load_settings(path: str | None) -> dict:
    """Read and validate a settings file. A missing default file is no settings;
    a missing file named explicitly is an error."""
    explicit = path is not None
    p = Path(path or DEFAULT_SETTINGS_PATH)
    if not p.is_file():
        if explicit:
            raise SettingsError(f"settings file not found: {p}")
        return {}
    try:
        raw = json.loads(p.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise SettingsError(f"{p}: invalid JSON: {e}") from e
    if not isinstance(raw, dict):
        raise SettingsError(f"{p}: expected a JSON object")
    unknown = set(raw) - SETTINGS_KEYS
    if unknown:
        raise SettingsError(f"{p}: unknown key(s): {', '.join(sorted(unknown))}")
    settings = {
        "exempt": _entries(raw.get("exempt"), "exempt"),
        "known_debt": _entries(raw.get("known_debt"), "known_debt"),
        "score_owners": _strings(raw.get("score_owners"), "score_owners"),
        "allowed_paths": _strings(raw.get("allowed_paths"), "allowed_paths"),
        "model_call_patterns": _strings(raw.get("model_call_patterns"), "model_call_patterns"),
        "evidence_markers": _strings(raw.get("evidence_markers"), "evidence_markers"),
    }
    for key, reason in settings["known_debt"].items():
        if not DEBT_REF.match(reason):
            raise SettingsError(f"known_debt {key} must start with an issue reference ('#123: why')")
        if key in settings["exempt"]:
            raise SettingsError(f"{key} is both exempt and known debt; it is one or the other")
    for pattern in settings["model_call_patterns"] + settings["evidence_markers"]:
        try:
            re.compile(pattern)
        except re.error as e:
            raise SettingsError(f"invalid pattern {pattern!r}: {e}") from e
    return settings


def apply_settings(settings: dict) -> None:
    """Install settings into the module's rule tables. Replaces, never merges,
    so applying {} restores the defaults."""
    global V2_EXEMPT, KNOWN_DEBT, SCORE_OWNERS, ALLOWED, MODEL_CALL, EVIDENCE_SUPPLIED
    V2_EXEMPT = dict(settings.get("exempt", {}))
    KNOWN_DEBT = dict(settings.get("known_debt", {}))
    SCORE_OWNERS = tuple(settings.get("score_owners", ()))
    ALLOWED = ALLOWED_DEFAULT + tuple(settings.get("allowed_paths", ()))
    MODEL_CALL = re.compile(
        "|".join([MODEL_CALL_DEFAULT, *settings.get("model_call_patterns", [])]),
        re.IGNORECASE | re.MULTILINE,
    )
    EVIDENCE_SUPPLIED = re.compile(
        "|".join([EVIDENCE_DEFAULT, *settings.get("evidence_markers", [])]), re.IGNORECASE
    )


def collect(paths: list[str]) -> list[Path]:
    out: list[Path] = []
    for raw in paths:
        p = Path(raw)
        candidates = [p] if p.is_file() else p.rglob("*")
        for f in candidates:
            is_data = f.suffix == ".json" and any(d in "/" + str(f) for d in DATA_JSON_DIRS)
            if f.is_file() and (f.suffix in SUFFIXES or is_data) and not any(a in str(f) for a in ALLOWED):
                out.append(f)
    return sorted(set(out))


def changed_files(base: str | None = None) -> list[str]:
    """Files changed against `base` (three-dot, for CI) or the working tree."""
    diff_args = ["git", "diff", "--name-only"]
    diff_args += [f"{base}...HEAD"] if base else ["HEAD"]
    try:
        diff = subprocess.run(diff_args, capture_output=True, text=True, check=True)
        untracked = subprocess.run(
            ["git", "ls-files", "--others", "--exclude-standard"],
            capture_output=True, text=True, check=True,
        )
        return [f for f in (diff.stdout + untracked.stdout).split("\n") if f.strip()]
    except subprocess.CalledProcessError:
        print("not a git repository", file=sys.stderr)
        sys.exit(2)


def main() -> int:
    args = sys.argv[1:]
    if "--self-check" in args:
        return self_check()

    json_out = None
    config_path = None
    clean_args = []
    it = iter(args)
    for a in it:
        if a.startswith("--json-out="):
            json_out = a.split("=", 1)[1]
        elif a == "--json-out":
            json_out = next(it, None)
        elif a.startswith("--config="):
            config_path = a.split("=", 1)[1]
        elif a == "--config":
            config_path = next(it, None)
        elif a.startswith("--") and not a.startswith("--changed"):
            print(f"unknown option: {a}", file=sys.stderr)
            return 2
        else:
            clean_args.append(a)
    args = clean_args

    try:
        apply_settings(load_settings(config_path))
    except SettingsError as e:
        print(f"fabrication settings: {e}", file=sys.stderr)
        return 2

    changed_arg = next((a for a in args if a.startswith("--changed")), None)
    if changed_arg:
        base = changed_arg.split("=", 1)[1] if "=" in changed_arg else None
        targets = [f for f in changed_files(base) if Path(f).exists()]
        if not targets:
            print("No changed files to scan.")
            if json_out:
                Path(json_out).parent.mkdir(parents=True, exist_ok=True)
                Path(json_out).write_text("[]")
            return 0
    else:
        targets = args or [d for d in ("src", "backend") if Path(d).is_dir()] or ["."]

    files = collect(targets)
    findings: list[Finding] = []
    for f in files:
        findings.extend(scan_file(f))

    # A full sweep also proves every exemption still exempts something.
    if not changed_arg and not args:
        for table, entries in (("V2_EXEMPT", V2_EXEMPT), ("KNOWN_DEBT", KNOWN_DEBT)):
            for (path, rule), reason in entries.items():
                p = Path(path)
                text = p.read_text(encoding="utf-8", errors="ignore") if p.is_file() else ""
                if not any(f.rule == rule for f in raw_findings(path, p.suffix, text)):
                    findings.append(Finding(path, 0, "stale-exemption",
                                            f"{table}[{rule}] no longer matches anything: {reason}"))
        if KNOWN_DEBT:
            print(f"Known debt, not yet removed ({len(KNOWN_DEBT)}):")
            for (path, rule), reason in KNOWN_DEBT.items():
                print(f"  {path} [{rule}] {reason}")
            print()

    if json_out:
        Path(json_out).parent.mkdir(parents=True, exist_ok=True)
        Path(json_out).write_text(json.dumps([f.to_dict() for f in findings], indent=2))

    if not findings:
        print(f"No fabrication patterns found across {len(files)} file(s).")
        return 0

    by_rule: dict[str, list[Finding]] = {}
    for f in findings:
        by_rule.setdefault(f.rule, []).append(f)

    print(f"{len(findings)} possible fabrication(s) across {len(files)} file(s):\n")
    for rule, group in sorted(by_rule.items()):
        print(f"── {rule} ({len(group)})")
        for f in group:
            print(f"  {f}")
        print()

    print("Each is a candidate, not a verdict. Ask: if the real source is")
    print("unavailable, does this render as though it were observed data?")
    return 1


if __name__ == "__main__":
    sys.exit(main())
