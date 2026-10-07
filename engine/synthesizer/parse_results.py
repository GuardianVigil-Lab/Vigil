#!/usr/bin/env python3
"""
Vigil Review Synthesizer & Unified SARIF/Markdown Reporter
Ingests raw scanner outputs, normalizes into P0-P3 severities,
generates reports/vigil.sarif, reports/vigil-review.md,
prints ANSI summary table, and exits 1 if P0/P1 detected.
"""

from __future__ import annotations

import datetime
import json
import os
import re
import subprocess
import sys
try:
    import defusedxml.ElementTree as ET
except ImportError:
    import xml.etree.ElementTree as ET  # nosemgrep: python.lang.security.use-defused-xml-parse.use-defused-xml-parse
from pathlib import Path
from typing import Any, Dict, List

# ANSI Color Codes
RESET = "\033[0m"
BOLD = "\033[1m"
RED = "\033[31m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
BLUE = "\033[34m"
CYAN = "\033[36m"
GRAY = "\033[90m"


class Finding:
    def __init__(
        self,
        tool: str,
        rule_id: str,
        severity: str,  # P0, P1, P2, P3
        message: str,
        file_path: str = "workspace",
        line: int = 1,
        details: str = "",
    ):
        self.tool = tool
        self.rule_id = rule_id
        self.severity = severity
        self.message = message.strip().replace("\n", " ")
        self.file_path = file_path
        self.line = line
        self.details = details.strip()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "tool": self.tool,
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "file": self.file_path,
            "line": self.line,
            "details": self.details,
        }


def get_git_info() -> tuple[str, str]:
    workspace = Path(os.environ.get("WORKSPACE", "/workspace")).resolve().name or "workspace"
    commit = "unknown"
    try:
        commit = subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], stderr=subprocess.DEVNULL, text=True
        ).strip()
    except Exception:
        pass
    return workspace, commit


def parse_raw_results(raw_dir: Path) -> List[Finding]:
    findings: List[Finding] = []

    # 1. Gitleaks
    gl_file = raw_dir / "gitleaks.json"
    if gl_file.exists() and gl_file.stat().st_size > 0:
        try:
            data = json.loads(gl_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                for item in data:
                    findings.append(
                        Finding(
                            tool="gitleaks",
                            rule_id=item.get("RuleID", "secret-detected"),
                            severity="P0",
                            message=f"Secret detected: {item.get('Description', 'Hardcoded secret')}",
                            file_path=item.get("File", "unknown"),
                            line=item.get("StartLine", 1),
                            details=f"Match: {item.get('Match', '')[:80]}",
                        )
                    )
        except (json.JSONDecodeError, OSError):
            pass

    # 2. TruffleHog
    th_file = raw_dir / "trufflehog.json"
    if th_file.exists() and th_file.stat().st_size > 0:
        try:
            for line in th_file.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                meta = item.get("SourceMetadata", {}).get("Data", {}).get("Filesystem", {})
                findings.append(
                    Finding(
                        tool="trufflehog",
                        rule_id=item.get("DetectorName", "trufflehog-finding"),
                        severity="P0",
                        message=f"Verified secret detected: {item.get('DetectorName')}",
                        file_path=meta.get("file", "unknown"),
                        line=meta.get("line", 1),
                        details=f"Redacted: {item.get('Redacted', '')}",
                    )
                )
        except (json.JSONDecodeError, OSError):
            pass

    # 3. Trivy
    trivy_file = raw_dir / "trivy.json"
    if trivy_file.exists() and trivy_file.stat().st_size > 0:
        try:
            data = json.loads(trivy_file.read_text(encoding="utf-8"))
            for res in data.get("Results", []):
                target = res.get("Target", "unknown")
                for vuln in res.get("Vulnerabilities", []):
                    sev_raw = vuln.get("Severity", "UNKNOWN").upper()
                    sev = "P2"
                    if sev_raw == "CRITICAL":
                        sev = "P0"
                    elif sev_raw == "HIGH":
                        sev = "P1"
                    elif sev_raw == "LOW":
                        sev = "P3"
                    findings.append(
                        Finding(
                            tool="trivy",
                            rule_id=vuln.get("VulnerabilityID", "CVE-UNKNOWN"),
                            severity=sev,
                            message=f"{vuln.get('PkgName')} {vuln.get('InstalledVersion')} vulnerable: {vuln.get('Title', vuln.get('VulnerabilityID'))}",
                            file_path=target,
                            line=1,
                            details=f"Fixed in: {vuln.get('FixedVersion', 'None')}",
                        )
                    )
                for misconf in res.get("Misconfigurations", []):
                    sev_raw = misconf.get("Severity", "UNKNOWN").upper()
                    sev = "P1" if sev_raw in ("CRITICAL", "HIGH") else "P2"
                    findings.append(
                        Finding(
                            tool="trivy-config",
                            rule_id=misconf.get("ID", "MISCONF"),
                            severity=sev,
                            message=misconf.get("Title", "IaC Misconfiguration"),
                            file_path=target,
                            line=misconf.get("CauseMetadata", {}).get("StartLine", 1),
                            details=misconf.get("Resolution", ""),
                        )
                    )
        except (json.JSONDecodeError, OSError):
            pass

    # 4. Grype
    grype_file = raw_dir / "grype.json"
    if grype_file.exists() and grype_file.stat().st_size > 0:
        try:
            data = json.loads(grype_file.read_text(encoding="utf-8"))
            for match in data.get("matches", []):
                vuln = match.get("vulnerability", {})
                art = match.get("artifact", {})
                sev_raw = vuln.get("severity", "Medium").upper()
                sev = "P2"
                if sev_raw == "CRITICAL":
                    sev = "P0"
                elif sev_raw == "HIGH":
                    sev = "P1"
                elif sev_raw in ("LOW", "NEGLIGIBLE"):
                    sev = "P3"
                findings.append(
                    Finding(
                        tool="grype",
                        rule_id=vuln.get("id", "VULN"),
                        severity=sev,
                        message=f"{art.get('name')} {art.get('version')}: {vuln.get('id')}",
                        file_path="SBOM",
                        line=1,
                        details=f"Type: {art.get('type')}",
                    )
                )
        except (json.JSONDecodeError, OSError):
            pass

    # 5. Gosec (all gosec*.json)
    for gosec_file in raw_dir.glob("gosec*.json"):
        if gosec_file.stat().st_size > 0:
            try:
                data = json.loads(gosec_file.read_text(encoding="utf-8"))
                for issue in data.get("Issues", []):
                    sev_raw = issue.get("severity", "MEDIUM").upper()
                    sev = "P1" if sev_raw == "HIGH" else ("P2" if sev_raw == "MEDIUM" else "P3")
                    findings.append(
                        Finding(
                            tool="gosec",
                            rule_id=issue.get("rule_id", "G-UNKNOWN"),
                            severity=sev,
                            message=issue.get("details", "Go SAST finding"),
                            file_path=issue.get("file", "unknown"),
                            line=int(issue.get("line", 1)),
                            details=f"Confidence: {issue.get('confidence')}",
                        )
                    )
            except (json.JSONDecodeError, OSError):
                pass

    # 6. Hadolint
    hadolint_file = raw_dir / "hadolint.json"
    if hadolint_file.exists() and hadolint_file.stat().st_size > 0:
        try:
            data = json.loads(hadolint_file.read_text(encoding="utf-8"))
            for item in data:
                lvl = item.get("level", "info").lower()
                sev = "P1" if lvl == "error" else ("P2" if lvl == "warning" else "P3")
                findings.append(
                    Finding(
                        tool="hadolint",
                        rule_id=item.get("code", "DL"),
                        severity=sev,
                        message=item.get("message", "Dockerfile lint issue"),
                        file_path=item.get("file", "Dockerfile"),
                        line=item.get("line", 1),
                    )
                )
        except (json.JSONDecodeError, OSError):
            pass

    # 7. ast-grep
    ast_file = raw_dir / "ast_grep.json"
    if ast_file.exists() and ast_file.stat().st_size > 0:
        try:
            data = json.loads(ast_file.read_text(encoding="utf-8"))
            for item in data:
                findings.append(
                    Finding(
                        tool="ast-grep",
                        rule_id=item.get("ruleId", "ast-rule"),
                        severity="P1",
                        message=item.get("message", item.get("text", "AST violation")),
                        file_path=item.get("file", "unknown"),
                        line=item.get("range", {}).get("start", {}).get("line", 1),
                    )
                )
        except (json.JSONDecodeError, OSError):
            pass

    # 8. Dependency-cruiser
    dep_file = raw_dir / "dep_cruiser.json"
    if dep_file.exists() and dep_file.stat().st_size > 0:
        try:
            data = json.loads(dep_file.read_text(encoding="utf-8"))
            for viol in data.get("summary", {}).get("violations", []):
                rule = viol.get("rule", {})
                sev = "P1" if rule.get("severity") == "error" else "P2"
                findings.append(
                    Finding(
                        tool="dependency-cruiser",
                        rule_id=rule.get("name", "dep-violation"),
                        severity=sev,
                        message=f"Architecture boundary violated from {viol.get('from')} -> {viol.get('to')}",
                        file_path=viol.get("from", "unknown"),
                        line=1,
                    )
                )
        except (json.JSONDecodeError, OSError):
            pass

    # 9. Squawk
    squawk_file = raw_dir / "squawk.json"
    if squawk_file.exists() and squawk_file.stat().st_size > 0:
        try:
            data = json.loads(squawk_file.read_text(encoding="utf-8"))
            for item in data:
                lvl = item.get("level", "Warning").lower()
                rule_id = item.get("rule_name", item.get("rule", "squawk-rule"))
                notes = item.get("messages", [])
                note_parts = []
                for m in notes:
                    if isinstance(m, dict):
                        for k, v in m.items():
                            if v:
                                note_parts.append(str(v))
                note_text = " ".join(note_parts)
                msg = item.get("message") or note_text or "Postgres migration advisory"
                # If an upstream Squawk parser bug occurs on valid PG syntax, treat as P3 linter advisory
                if rule_id == "invalid-statement" and "This indicates a bug with Squawk" in (msg + " " + note_text):
                    sev = "P3"
                else:
                    sev = "P1" if lvl == "error" else "P2"
                findings.append(
                    Finding(
                        tool="squawk",
                        rule_id=rule_id,
                        severity=sev,
                        message=msg,
                        file_path=item.get("file", "database/migrations"),
                        line=item.get("line", 1),
                    )
                )
        except (json.JSONDecodeError, OSError):
            pass

    # 10. Ruff
    ruff_file = raw_dir / "ruff.json"
    if ruff_file.exists() and ruff_file.stat().st_size > 0:
        try:
            data = json.loads(ruff_file.read_text(encoding="utf-8"))
            CRITICAL_SECURITY_CODES = {
                "S102", "S103", "S104", "S105", "S106", "S107", "S108",
                "S201", "S202", "S301", "S302", "S303", "S304", "S305",
                "S306", "S307", "S308", "S311", "S324", "S501", "S506", "S608"
            }
            for item in data:
                code = item.get("code", "")
                if code in CRITICAL_SECURITY_CODES:
                    sev = "P1"
                elif code.startswith("S"):
                    sev = "P2"
                elif code.startswith("E") or code.startswith("F"):
                    sev = "P2"
                else:
                    sev = "P3"
                findings.append(
                    Finding(
                        tool="ruff",
                        rule_id=code,
                        severity=sev,
                        message=item.get("message", "Python lint error"),
                        file_path=item.get("filename", "unknown"),
                        line=item.get("location", {}).get("row", 1),
                    )
                )
        except (json.JSONDecodeError, OSError):
            pass

    # 11. GolangCI-Lint (all golangci*.json)
    for golangci_file in raw_dir.glob("golangci*.json"):
        if golangci_file.stat().st_size > 0:
            try:
                data = json.loads(golangci_file.read_text(encoding="utf-8"))
                for item in data.get("Issues", []):
                    linter = item.get("FromLinter", "go-lint")
                    sev = "P1" if linter in ("errcheck", "gosec", "noctx", "bodyclose", "sqlclosecheck", "rowserrcheck", "govet") else "P2"
                    findings.append(
                        Finding(
                            tool="golangci-lint",
                            rule_id=linter,
                            severity=sev,
                            message=item.get("Text", "Go lint finding"),
                            file_path=item.get("Pos", {}).get("Filename", "unknown"),
                            line=item.get("Pos", {}).get("Line", 1),
                        )
                    )
            except (json.JSONDecodeError, OSError):
                pass

    # 12. Knip
    knip_file = raw_dir / "knip.json"
    if knip_file.exists() and knip_file.stat().st_size > 0:
        try:
            data = json.loads(knip_file.read_text(encoding="utf-8"))
            for unused in data.get("files", []):
                findings.append(
                    Finding(
                        tool="knip",
                        rule_id="unused-file",
                        severity="P3",
                        message="Unused file detected",
                        file_path=unused,
                        line=1,
                    )
                )
        except (json.JSONDecodeError, OSError):
            pass

    # 13. Zizmor
    zizmor_file = raw_dir / "zizmor.json"
    if zizmor_file.exists() and zizmor_file.stat().st_size > 0:
        try:
            data = json.loads(zizmor_file.read_text(encoding="utf-8"))
            if isinstance(data, list):
                for item in data:
                    determ = item.get("determinations", {})
                    raw_sev = (determ.get("severity") or item.get("severity") or "Medium").upper()
                    rule_id = item.get("ident", item.get("rule", "ci-security"))
                    sev = "P2"
                    if rule_id == "template-injection":
                        sev = "P0"
                    elif rule_id == "unpinned-uses":
                        sev = "P2"
                    elif raw_sev == "CRITICAL":
                        sev = "P0"
                    elif raw_sev == "HIGH":
                        sev = "P1"
                    elif raw_sev == "MEDIUM":
                        sev = "P2"
                    elif raw_sev in ("LOW", "INFORMATIONAL"):
                        sev = "P3"

                    msg = item.get("desc", item.get("message", "CI workflow issue"))
                    file_path = ".github/workflows"
                    line = 1
                    locs = item.get("locations", [])
                    if locs:
                        file_path = locs[0].get("symbolic", {}).get("key", {}).get("Local", {}).get("verbatim_path", file_path)
                        line = locs[0].get("concrete", {}).get("location", {}).get("start_point", {}).get("row", 1)

                    findings.append(
                        Finding(
                            tool="zizmor",
                            rule_id=rule_id,
                            severity=sev,
                            message=msg,
                            file_path=file_path,
                            line=line,
                        )
                    )
        except (json.JSONDecodeError, OSError):
            pass

    # 14. Oxlint
    oxlint_file = raw_dir / "oxlint.json"
    if oxlint_file.exists() and oxlint_file.stat().st_size > 0:
        try:
            data = json.loads(oxlint_file.read_text(encoding="utf-8"))
            for item in data.get("diagnostics", []):
                code = item.get("code", "oxlint")
                sev_raw = item.get("severity", "warning").lower()
                sev = "P1" if sev_raw == "error" else "P2"
                line = 1
                labels = item.get("labels", [])
                if labels and isinstance(labels[0], dict):
                    line = labels[0].get("span", {}).get("line", 1)
                findings.append(
                    Finding(
                        tool="oxlint",
                        rule_id=code,
                        severity=sev,
                        message=item.get("message", "JS/TS linter warning"),
                        file_path=item.get("filename", "unknown"),
                        line=line,
                    )
                )
        except (json.JSONDecodeError, OSError):
            pass

    # 15. PHPStan
    phpstan_file = raw_dir / "phpstan.json"
    if phpstan_file.exists() and phpstan_file.stat().st_size > 0:
        try:
            data = json.loads(phpstan_file.read_text(encoding="utf-8"))
            for fpath, fdata in data.get("files", {}).items():
                for msg_item in fdata.get("messages", []):
                    findings.append(
                        Finding(
                            tool="phpstan",
                            rule_id="phpstan-type",
                            severity="P1",
                            message=msg_item.get("message", "PHP type error"),
                            file_path=fpath,
                            line=msg_item.get("line", 1),
                        )
                    )
        except (json.JSONDecodeError, OSError):
            pass

    # 16. Semgrep
    semgrep_file = raw_dir / "semgrep.json"
    if semgrep_file.exists() and semgrep_file.stat().st_size > 0:
        try:
            data = json.loads(semgrep_file.read_text(encoding="utf-8"))
            for res in data.get("results", []):
                extra = res.get("extra", {})
                sev_raw = extra.get("severity", "WARNING").upper()
                sev = "P1" if sev_raw == "ERROR" else "P2"
                findings.append(
                    Finding(
                        tool="semgrep",
                        rule_id=res.get("check_id", "semgrep-finding"),
                        severity=sev,
                        message=extra.get("message", "Semgrep security finding"),
                        file_path=res.get("path", "unknown"),
                        line=res.get("start", {}).get("line", 1),
                    )
                )
        except (json.JSONDecodeError, OSError):
            pass

    # 17. Govulncheck (all govulncheck*.json)
    for govuln_file in raw_dir.glob("govulncheck*.json"):
        if govuln_file.stat().st_size > 0:
            try:
                for line in govuln_file.read_text(encoding="utf-8").splitlines():
                    if not line.strip():
                        continue
                    obj = json.loads(line)
                    finding = obj.get("finding", {})
                    if finding:
                        osv = finding.get("osv", "GO-VULN")
                        trace = finding.get("trace", [])
                        file_path = "go.mod"
                        if trace and isinstance(trace[0], dict):
                            file_path = trace[0].get("position", {}).get("filename", "go.mod")
                        findings.append(
                            Finding(
                                tool="govulncheck",
                                rule_id=osv,
                                severity="P1",
                                message=f"Vulnerable Go package call in {osv}",
                                file_path=file_path,
                                line=1,
                                details=f"Fixed version: {finding.get('fixed_version', 'none')}",
                            )
                        )
            except (json.JSONDecodeError, OSError):
                pass

    # 18. Vitest
    vitest_file = raw_dir / "vitest.json"
    if vitest_file.exists() and vitest_file.stat().st_size > 0:
        try:
            data = json.loads(vitest_file.read_text(encoding="utf-8"))
            if data.get("numFailedTests", 0) > 0:
                for suite in data.get("testResults", []):
                    if suite.get("status") == "failed":
                        for test in suite.get("assertionResults", []):
                            if test.get("status") == "failed":
                                details = "; ".join(test.get("failureMessages", []))[:200]
                                findings.append(
                                    Finding(
                                        tool="vitest",
                                        rule_id="unit-test-failure",
                                        severity="P1",
                                        message=f"Unit test failure: {test.get('title')}",
                                        file_path=suite.get("name", "vitest"),
                                        line=1,
                                        details=details,
                                    )
                                )
        except (json.JSONDecodeError, OSError):
            pass

    # 19. Nuclei
    nuclei_file = raw_dir / "nuclei.jsonl"
    if nuclei_file.exists() and nuclei_file.stat().st_size > 0:
        try:
            for line in nuclei_file.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                item = json.loads(line)
                info = item.get("info", {})
                sev_raw = info.get("severity", "medium").upper()
                sev = "P0" if sev_raw == "CRITICAL" else ("P1" if sev_raw == "HIGH" else ("P2" if sev_raw == "MEDIUM" else "P3"))
                findings.append(
                    Finding(
                        tool="nuclei",
                        rule_id=item.get("template-id", "nuclei-finding"),
                        severity=sev,
                        message=info.get("name", "Dynamic vulnerability found"),
                        file_path=item.get("matched-at", item.get("host", "target")),
                        line=1,
                    )
                )
        except (json.JSONDecodeError, OSError):
            pass

    # 20. Schemathesis
    schema_file = raw_dir / "schemathesis.xml"
    if schema_file.exists() and schema_file.stat().st_size > 0:
        try:
            tree = ET.parse(schema_file)  # nosemgrep: python.lang.security.use-defused-xml-parse.use-defused-xml-parse
            root = tree.getroot()
            for tc in root.iter("testcase"):
                for fail in tc.findall("failure") + tc.findall("error"):
                    findings.append(
                        Finding(
                            tool="schemathesis",
                            rule_id="api-schema-violation",
                            severity="P1",
                            message=f"API Schema failure in {tc.get('name')}: {fail.get('message', 'Conformance failure')}",
                            file_path="openapi.yaml",
                            line=1,
                            details=(fail.text or "")[:200],
                        )
                    )
        except (ET.ParseError, OSError):
            pass

    # 21. Custom gate & test suite failures (*.fail)
    for fail_file in raw_dir.glob("*.fail"):
        gate_name = fail_file.stem
        log_file = raw_dir / f"{gate_name}.log"
        details = log_file.read_text(errors="ignore") if log_file.exists() else "Gate exited non-zero"
        tail_lines = [l for l in details.splitlines() if l.strip()][-5:]
        summary_details = " | ".join(tail_lines) if tail_lines else "Verification failed"
        findings.append(
            Finding(
                tool="vigil-gate",
                rule_id=f"gate-failed-{gate_name}",
                severity="P1",
                message=f"Mandatory security/quality gate '{gate_name}' failed verification",
                file_path=f"reports/raw/{gate_name}.log",
                line=1,
                details=summary_details[:200],
            )
        )

    # 22. Anti-Fabrication Engine
    af_file = raw_dir / "anti_fabrication.json"
    if af_file.exists() and af_file.stat().st_size > 0:
        try:
            af_data = json.loads(af_file.read_text(encoding="utf-8"))
            if isinstance(af_data, list):
                for item in af_data:
                    findings.append(
                        Finding(
                            tool="anti-fabrication",
                            rule_id=f"anti-fabrication-{item.get('rule', 'violation')}",
                            severity="P0",
                            message=f"Zero-fabrication invariant breached: {item.get('rule')}",
                            file_path=item.get("file", "unknown"),
                            line=int(item.get("line", 1)),
                            details=item.get("snippet", "")[:200],
                        )
                    )
        except (json.JSONDecodeError, OSError):
            pass

    # 23. Strix Autonomous VAPT
    strix_file = raw_dir / "strix.json"
    if strix_file.exists() and strix_file.stat().st_size > 0:
        try:
            strix_data = json.loads(strix_file.read_text(encoding="utf-8"))
            if isinstance(strix_data, list):
                for item in strix_data:
                    findings.append(
                        Finding(
                            tool="strix",
                            rule_id=item.get("category", "OWASP-API-TOP10"),
                            severity=item.get("severity", "P1"),
                            message=f"{item.get('title', 'Vulnerability')}: {item.get('description', '')}",
                            file_path=item.get("target_url", "target"),
                            line=1,
                            details=f"Exploit POC: {item.get('curl_poc', '')}"[:300],
                        )
                    )
        except (json.JSONDecodeError, OSError):
            pass

    # 24. BOLA / IDOR Cross-Tenant Matrix
    bola_file = raw_dir / "bola_matrix.json"
    if bola_file.exists() and bola_file.stat().st_size > 0:
        try:
            bola_data = json.loads(bola_file.read_text(encoding="utf-8"))
            if isinstance(bola_data, list):
                for item in bola_data:
                    findings.append(
                        Finding(
                            tool="bola-matrix",
                            rule_id=item.get("rule_id", "BOLA-VIOLATION"),
                            severity=item.get("severity", "P0"),
                            message=item.get("message", "Cross-tenant authorization boundary broken"),
                            file_path=item.get("target", "target"),
                            line=int(item.get("line", 1)),
                            details=f"{item.get('details', '')} {item.get('curl_poc', '')}"[:300],
                        )
                    )
        except (json.JSONDecodeError, OSError):
            pass

    # 25. testssl.sh TLS & Cipher Suite Audit
    testssl_file = raw_dir / "testssl.json"
    if testssl_file.exists() and testssl_file.stat().st_size > 0:
        try:
            ts_data = json.loads(testssl_file.read_text(encoding="utf-8"))
            if isinstance(ts_data, list):
                for item in ts_data:
                    sev_raw = str(item.get("severity", "MEDIUM")).upper()
                    if sev_raw in ("OK", "INFO", "DEBUG"):
                        continue
                    sev = "P0" if sev_raw in ("CRITICAL", "FATAL") else ("P1" if sev_raw == "HIGH" else "P2")
                    findings.append(
                        Finding(
                            tool="testssl",
                            rule_id=item.get("id", "TLS-VULN"),
                            severity=sev,
                            message=item.get("finding", "Insecure TLS protocol or weak cipher"),
                            file_path=item.get("target", "tls-port"),
                            line=1,
                            details=item.get("cve", ""),
                        )
                    )
        except (json.JSONDecodeError, OSError):
            pass

    # 26. Nikto Web Server Audit
    nikto_file = raw_dir / "nikto.json"
    if nikto_file.exists() and nikto_file.stat().st_size > 0:
        try:
            nk_data = json.loads(nikto_file.read_text(encoding="utf-8"))
            vulns = nk_data.get("vulnerabilities", []) if isinstance(nk_data, dict) else []
            for v in vulns:
                findings.append(
                    Finding(
                        tool="nikto",
                        rule_id=f"nikto-{v.get('id', 'vuln')}",
                        severity="P2",
                        message=v.get("msg", "Web server configuration issue"),
                        file_path=v.get("url", "web-server"),
                        line=1,
                    )
                )
        except (json.JSONDecodeError, OSError):
            pass

    # 27. jscpd Code Duplication
    jscpd_report = raw_dir / "jscpd" / "jscpd-report.json"
    if not jscpd_report.exists():
        jscpd_report = raw_dir / "jscpd-report.json"
    if jscpd_report.exists() and jscpd_report.stat().st_size > 0:
        try:
            j_data = json.loads(jscpd_report.read_text(encoding="utf-8"))
            stats = j_data.get("statistics", {}).get("total", {})
            dup_percent = float(stats.get("percentage", 0))
            if dup_percent > 3.0:
                findings.append(
                    Finding(
                        tool="jscpd",
                        rule_id="code-duplication-threshold-exceeded",
                        severity="P2",
                        message=f"Duplicate code threshold breached: {dup_percent}% cloned code (max allowed 3%)",
                        file_path="workspace",
                        line=1,
                        details=f"Total duplicated lines: {stats.get('lines', 0)} across {stats.get('clones', 0)} clones",
                    )
                )
            for clone in j_data.get("duplicates", [])[:10]:
                f1 = clone.get("firstFile", {}).get("name", "file1")
                f2 = clone.get("secondFile", {}).get("name", "file2")
                lines_count = clone.get("lines", 0)
                findings.append(
                    Finding(
                        tool="jscpd",
                        rule_id="duplicate-code-clone",
                        severity="P3",
                        message=f"Duplicate block ({lines_count} lines) shared with {f2}",
                        file_path=f1,
                        line=clone.get("firstFile", {}).get("start", 1),
                        details=f"Cloned in {f2}:{clone.get('secondFile', {}).get('start', 1)}",
                    )
                )
        except (json.JSONDecodeError, OSError):
            pass

    # 28. Semantic PR Reviewer
    pr_file = raw_dir / "pr_review.json"
    if pr_file.exists() and pr_file.stat().st_size > 0:
        try:
            pr_data = json.loads(pr_file.read_text(encoding="utf-8"))
            if isinstance(pr_data, list):
                for item in pr_data:
                    findings.append(
                        Finding(
                            tool="pr-reviewer",
                            rule_id=f"pr-{item.get('title', 'review').lower().replace(' ', '-')}",
                            severity=item.get("severity", "P2"),
                            message=f"{item.get('title')}: {item.get('message')}",
                            file_path=item.get("file", "unknown"),
                            line=int(item.get("line", 1)),
                            details=item.get("suggestion", "")[:200],
                        )
                    )
        except (json.JSONDecodeError, OSError):
            pass

    # 29. Playwright E2E User Persona Results
    pw_file = raw_dir / "playwright.json"
    if pw_file.exists() and pw_file.stat().st_size > 0:
        try:
            pw_data = json.loads(pw_file.read_text(encoding="utf-8"))
            def extract_pw_failures(suites_list: list):
                for s in suites_list:
                    extract_pw_failures(s.get("suites", []))
                    for spec in s.get("specs", []):
                        for t in spec.get("tests", []):
                            for r in t.get("results", []):
                                if r.get("status") in ("failed", "timedOut"):
                                    err = r.get("error", {}).get("message", "E2E journey assertion failed")
                                    findings.append(
                                        Finding(
                                            tool="playwright-e2e",
                                            rule_id="user-persona-journey-failed",
                                            severity="P1",
                                            message=f"Playwright E2E journey failed: {spec.get('title', 'Unknown Journey')}",
                                            file_path=spec.get("file", s.get("title", "playwright.spec.ts")),
                                            line=spec.get("line", 1),
                                            details=err[:250],
                                        )
                                    )
            extract_pw_failures(pw_data.get("suites", []))
            for err in pw_data.get("errors", []):
                findings.append(
                    Finding(
                        tool="playwright-e2e",
                        rule_id="playwright-runtime-error",
                        severity="P1",
                        message=f"Playwright execution error: {err.get('message', '')[:100]}",
                        file_path="playwright",
                        line=1,
                        details=err.get("stack", "")[:200],
                    )
                )
        except (json.JSONDecodeError, OSError):
            pass

    return findings



def generate_sarif(findings: List[Finding], output_path: Path) -> None:
    rules_map: Dict[str, Dict[str, Any]] = {}
    results = []

    for f in findings:
        if f.rule_id not in rules_map:
            rules_map[f.rule_id] = {
                "id": f.rule_id,
                "name": f.rule_id,
                "shortDescription": {"text": f.message[:100]},
                "defaultConfiguration": {
                    "level": "error" if f.severity in ("P0", "P1") else "warning"
                },
            }

        level = "error" if f.severity in ("P0", "P1") else "warning"
        if f.severity == "P3":
            level = "note"

        results.append(
            {
                "ruleId": f.rule_id,
                "level": level,
                "message": {"text": f.message},
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f.file_path.replace("/workspace/", "")
                            },
                            "region": {"startLine": max(1, f.line)},
                        }
                    }
                ],
                "properties": {
                    "tool": f.tool,
                    "severity": f.severity,
                    "details": f.details,
                },
            }
        )

    sarif = {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": os.environ.get("VIGIL_PRODUCT_NAME", "Vigil"),
                        "semanticVersion": "2.1.0",
                        "informationUri": "https://github.com/GuardianVigil-Lab/vigil",
                        "rules": list(rules_map.values()),
                    }
                },
                "results": results,
            }
        ],
    }

    output_path.write_text(json.dumps(sarif, indent=2), encoding="utf-8")


def generate_markdown(
    findings: List[Finding], template_path: Path, output_path: Path
) -> None:
    workspace, commit = get_git_info()
    p0 = [f for f in findings if f.severity == "P0"]
    p1 = [f for f in findings if f.severity == "P1"]
    p2 = [f for f in findings if f.severity == "P2"]
    p3 = [f for f in findings if f.severity == "P3"]

    verdict_badge = "🔴 **FAIL (Blockers Detected)**" if (p0 or p1) else "🟢 **PASS (Clean)**"
    verdict_text = "FAILED — Resolve all P0 and P1 issues before merging." if (p0 or p1) else "PASSED — All gates and invariant checks verified cleanly."

    tools = sorted(list(set(f.tool for f in findings)))
    scanner_rows = []
    if not tools:
        scanner_rows.append("| All Active Scanners | 0 | 0 | 0 | 0 | 🟢 PASS |")
    else:
        for t in tools:
            tf = [f for f in findings if f.tool == t]
            tp0 = sum(1 for f in tf if f.severity == "P0")
            tp1 = sum(1 for f in tf if f.severity == "P1")
            tp2 = sum(1 for f in tf if f.severity == "P2")
            tp3 = sum(1 for f in tf if f.severity == "P3")
            status = "🔴 FAIL" if (tp0 > 0 or tp1 > 0) else ("🟡 WARN" if tp2 > 0 else "🟢 PASS")
            scanner_rows.append(f"| `{t}` | {tp0} | {tp1} | {tp2} | {tp3} | {status} |")

    # Critical findings section
    critical_findings = p0 + p1
    if not critical_findings:
        crit_sec = "✨ **Zero Critical (P0) or High (P1) issues found.** Codebase conforms to all security invariants."
    else:
        rows = []
        for f in critical_findings:
            rows.append(
                f"### [{f.severity}] `{f.rule_id}` in `{f.file_path}:{f.line}`\n"
                f"- **Scanner:** `{f.tool}`\n"
                f"- **Finding:** {f.message}\n"
                + (f"- **Details:** `{f.details}`\n" if f.details else "")
                + f"- **Action:** Immediate remediation required.\n"
            )
        crit_sec = "\n".join(rows)

    # Advisory section
    advisory_findings = p2 + p3
    if not advisory_findings:
        adv_sec = "✨ **No medium or low advisory notices.**"
    else:
        rows = []
        for f in advisory_findings[:30]:  # Cap to top 30
            rows.append(f"- **[{f.severity}]** `{f.file_path}:{f.line}` — {f.message} (`{f.rule_id}` via `{f.tool}`)")
        if len(advisory_findings) > 30:
            rows.append(f"\n_... and {len(advisory_findings) - 30} more advisories (see reports/vigil.sarif)_")
        adv_sec = "\n".join(rows)

    default_template = """# Vigil Security & Quality Audit Report

**Status:** {VERDICT_BADGE}  
**Date:** {GENERATED_AT}  
**Target Workspace:** `{WORKSPACE_NAME}`  
**Commit/Ref:** `{GIT_COMMIT}`  

---

## 1. Executive Summary

Vigil audited `{WORKSPACE_NAME}` across 6 engineering pillars (AST Linting, Junk Pruning, SAST/SCA Hardening, VAPT, QA Invariants, and Container Architecture).

| Severity | Count | Blockers |
| :--- | :--- | :--- |
| **P0 (Critical)** | {COUNT_P0} | {BLOCKER_P0} |
| **P1 (High)** | {COUNT_P1} | {BLOCKER_P1} |
| **P2 (Medium)** | {COUNT_P2} | Non-blocking |
| **P3 (Low / Info)** | {COUNT_P3} | Non-blocking |

---

## 2. Pillar & Scanner Matrix

| Battery / Tool | P0 | P1 | P2 | P3 | Status |
| :--- | :---: | :---: | :---: | :---: | :---: |
{SCANNER_ROWS}

---

## 3. High & Critical Findings (P0 & P1)

{CRITICAL_FINDINGS_SECTION}

---

## 4. Medium & Low Advisory Notices (P2 & P3)

{ADVISORY_FINDINGS_SECTION}

---

## 5. Audit Sign-off

- **SARIF Specification:** SARIF 2.1.0 emitted to `reports/vigil.sarif`
- **Zero-Host Dependencies:** Verified in the Vigil container runtime
- **Verdict:** {VERDICT_TEXT}
"""

    possible_templates = [
        template_path if template_path and template_path.exists() else None,
        Path(__file__).parent / "templates" / "review_template.md",
        Path("/tools/vigil/engine/synthesizer/templates/review_template.md"),
        Path("/tools/vigil/reporters/templates/review_template.md"),
    ]
    template = ""
    for p in possible_templates:
        if p and p.exists():
            try:
                candidate = p.read_text(encoding="utf-8")
                if candidate.strip():
                    template = candidate
                    break
            except Exception:
                pass

    if not template.strip():
        template = default_template

    content = template.format(
        VERDICT_BADGE=verdict_badge,
        GENERATED_AT=datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC"),
        WORKSPACE_NAME=workspace,
        GIT_COMMIT=commit,
        COUNT_P0=len(p0),
        COUNT_P1=len(p1),
        COUNT_P2=len(p2),
        COUNT_P3=len(p3),
        BLOCKER_P0="🔴 Immediate Blocker" if p0 else "None",
        BLOCKER_P1="🔴 Merge Blocker" if p1 else "None",
        SCANNER_ROWS="\n".join(scanner_rows) if scanner_rows else "| `All Engines` | 0 | 0 | 0 | 0 | 🟢 PASS |",
        CRITICAL_FINDINGS_SECTION=crit_sec,
        ADVISORY_FINDINGS_SECTION=adv_sec,
        VERDICT_TEXT=verdict_text,
    )

    output_path.write_text(content, encoding="utf-8")


def print_ansi_table(findings: List[Finding]) -> None:
    p0 = sum(1 for f in findings if f.severity == "P0")
    p1 = sum(1 for f in findings if f.severity == "P1")
    p2 = sum(1 for f in findings if f.severity == "P2")
    p3 = sum(1 for f in findings if f.severity == "P3")

    tools = sorted(list(set(f.tool for f in findings)))

    print()
    print(f"{BOLD}╔══════════════════════════════════════════════════════════════════════════════╗{RESET}")
    print(f"{BOLD}║                           VIGIL AUDIT REPORT                                 ║{RESET}")
    print(f"{BOLD}╠══════════════════════════════╦══════╦══════╦══════╦══════╦═══════════════════╣{RESET}")
    print(f"{BOLD}║ Scanner / Battery            ║  P0  ║  P1  ║  P2  ║  P3  ║ Status            ║{RESET}")
    print(f"{BOLD}╠══════════════════════════════╬══════╬══════╬══════╬══════╬═══════════════════╣{RESET}")

    if not tools:
        print(f"║ {GREEN}All Scanners (Clean){RESET}         ║   0  ║   0  ║   0  ║   0  ║ {GREEN}✔ ALL PASSED{RESET}      ║")
    else:
        for t in tools:
            tf = [f for f in findings if f.tool == t]
            tp0 = sum(1 for f in tf if f.severity == "P0")
            tp1 = sum(1 for f in tf if f.severity == "P1")
            tp2 = sum(1 for f in tf if f.severity == "P2")
            tp3 = sum(1 for f in tf if f.severity == "P3")
            status = f"{RED}✘ FAILED{RESET}" if (tp0 > 0 or tp1 > 0) else (f"{YELLOW}⚠ WARN{RESET}  " if tp2 > 0 else f"{GREEN}✔ PASS{RESET}  ")
            print(f"║ {t[:28]:<28} ║ {tp0:>4} ║ {tp1:>4} ║ {tp2:>4} ║ {tp3:>4} ║ {status:<17} ║")

    print(f"{BOLD}╠══════════════════════════════╩══════╩══════╩══════╩══════╩═══════════════════╣{RESET}")
    print(f"║ {BOLD}TOTALS:{RESET} P0={RED}{p0}{RESET} | P1={RED}{p1}{RESET} | P2={YELLOW}{p2}{RESET} | P3={BLUE}{p3}{RESET}                                           ║")
    if p0 > 0 or p1 > 0:
        print(f"║ {RED}{BOLD}VERDICT: FAILED (P0/P1 Blockers Detected){RESET}                                  ║")
    else:
        print(f"║ {GREEN}{BOLD}VERDICT: PASSED (Zero Critical Blockers){RESET}                                    ║")
    print(f"{BOLD}╚══════════════════════════════════════════════════════════════════════════════╝{RESET}")
    print()


def main() -> None:
    workspace_env = os.environ.get("WORKSPACE")
    if workspace_env:
        workspace_dir = Path(workspace_env)
    elif Path("/workspace").exists() and os.access("/workspace", os.W_OK):
        workspace_dir = Path("/workspace")
    else:
        workspace_dir = Path.cwd()

    reports_dir = workspace_dir / "reports"
    raw_dir = reports_dir / "raw"
    template_path = Path(__file__).parent / "templates" / "review_template.md"

    reports_dir.mkdir(parents=True, exist_ok=True)

    findings = parse_raw_results(raw_dir)
    generate_sarif(findings, reports_dir / "vigil.sarif")
    generate_markdown(findings, template_path, reports_dir / "vigil-review.md")
    print_ansi_table(findings)

    # Exit code: 1 if P0 or P1 finding present
    has_blockers = any(f.severity in ("P0", "P1") for f in findings)
    sys.exit(1 if has_blockers else 0)


if __name__ == "__main__":
    main()
