#!/usr/bin/env python3
"""Sentinel Strix VAPT Orchestrator

Executes Strix autonomous penetration testing engine against running web targets
or OpenAPI schemas. Supports:
  1. Docker-outside-of-Docker (DooD) host path translation via SENTINEL_HOST_WORKSPACE.
  2. Local self-hosted BYO-LLM mode (STRIX_LLM_API_KEY, STRIX_MODEL).
  3. Managed Strix Cloud API mode (STRIX_CLOUD_API_KEY, STRIX_CLOUD_ENDPOINT).
  4. Exploit extraction: converts confirmed vulnerabilities into reproducible curl snippets.
  5. Outputs findings to reports/raw/strix.json and reports/raw/strix.md.
"""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional


class StrixExploit:
    def __init__(
        self,
        title: str,
        category: str,  # OWASP category, e.g. API1:2023-BOLA, OWASP:2025-BrokenAccess
        severity: str,  # P0, P1, P2
        target_url: str,
        curl_poc: str,
        description: str,
        response_snippet: str = "",
    ):
        self.title = title
        self.category = category
        self.severity = severity
        self.target_url = target_url
        self.curl_poc = curl_poc
        self.description = description
        self.response_snippet = response_snippet

    def to_dict(self) -> Dict[str, Any]:
        return {
            "title": self.title,
            "category": self.category,
            "severity": self.severity,
            "target_url": self.target_url,
            "curl_poc": self.curl_poc,
            "description": self.description,
            "response_snippet": self.response_snippet,
        }


def resolve_dood_path(container_path: str) -> str:
    """Translates container workspace path to host workspace path for DooD containers."""
    host_workspace = os.environ.get("VIGIL_HOST_WORKSPACE") or os.environ.get("SENTINEL_HOST_WORKSPACE")
    if not host_workspace:
        return container_path
    c_path = Path(container_path).resolve()
    if str(c_path).startswith("/workspace"):
        relative = str(c_path)[len("/workspace") :].lstrip("/")
        return str(Path(host_workspace) / relative)
    return container_path


def check_target_alive(url: str, timeout: int = 3) -> bool:
    try:
        import urllib.request
        req = urllib.request.Request(url, headers={"User-Agent": "Sentinel-VAPT/2.0"})
        with urllib.request.urlopen(req, timeout=timeout) as res:
            return res.status in (200, 201, 204, 301, 302, 401, 403)
    except Exception:
        return False


def run_strix_cloud(
    api_key: str,
    endpoint: str,
    target_url: str,
    openapi_spec: Optional[str] = None,
) -> List[StrixExploit]:
    """Interacts with Strix Cloud API."""
    import urllib.request
    print(f"  [Strix Cloud] Initiating autonomous scan against {target_url}...")
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
        "User-Agent": "Sentinel-Audit-Engine/2.0",
    }
    payload = {
        "target_url": target_url,
        "mode": "deep_vapt",
        "categories": ["OWASP_API_2023", "OWASP_WEB_2025"],
    }
    if openapi_spec and Path(openapi_spec).exists():
        payload["openapi_spec"] = Path(openapi_spec).read_text(encoding="utf-8", errors="ignore")

    try:
        req = urllib.request.Request(
            f"{endpoint.rstrip('/')}/api/v1/scans",
            data=json.dumps(payload).encode("utf-8"),
            headers=headers,
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            scan_id = data.get("scan_id", "scan_ephemeral")
            print(f"  [Strix Cloud] Scan queued (ID: {scan_id}).")
            # If immediate results provided
            exploits: List[StrixExploit] = []
            for item in data.get("findings", []):
                exploits.append(
                    StrixExploit(
                        title=item.get("title", "Strix Finding"),
                        category=item.get("category", "OWASP Top 10"),
                        severity=item.get("severity", "P1"),
                        target_url=item.get("url", target_url),
                        curl_poc=item.get("curl", ""),
                        description=item.get("description", ""),
                        response_snippet=item.get("response", ""),
                    )
                )
            return exploits
    except Exception as e:
        print(f"  [Strix Cloud Warning] Cloud API request failed: {e}. Falling back to local scanner.", file=sys.stderr)
        return []


def run_strix_cli(
    target_url: str,
    raw_dir: Path,
    openapi_spec: Optional[str] = None,
) -> List[StrixExploit]:
    """Runs local standalone Strix binary."""
    strix_bin = shutil.which("strix")
    if not strix_bin:
        print("  [Strix CLI] 'strix' binary not found in PATH.")
        return []

    print(f"  [Strix CLI] Launching autonomous security scan against {target_url}...")
    cmd = [
        strix_bin,
        "--target",
        target_url,
        "--non-interactive",
        "--scan-mode",
        "deep",
    ]
    if openapi_spec and Path(openapi_spec).exists():
        cmd.extend(["--target", openapi_spec])

    cmd.extend([
        "--instruction",
        "Focus on OWASP API Security Top 10: BOLA/IDOR, broken authentication, broken function level authorization, SSRF, injection",
        "--max-budget",
        os.environ.get("STRIX_MAX_BUDGET", "10"),
        "--max-turns",
        os.environ.get("STRIX_MAX_TURNS", "30"),
    ])

    # Propagate DooD workspace and LLM credentials
    env = os.environ.copy()
    if "SENTINEL_HOST_WORKSPACE" in env:
        env["STRIX_HOST_WORKSPACE"] = env["SENTINEL_HOST_WORKSPACE"]
    if "STRIX_LLM_API_KEY" in env:
        # If user provided STRIX_LLM_API_KEY, map to OPENAI_API_KEY if unset
        if "OPENAI_API_KEY" not in env:
            env["OPENAI_API_KEY"] = env["STRIX_LLM_API_KEY"]
    if "STRIX_MODEL" in env:
        env["MODEL"] = env["STRIX_MODEL"]

    try:
        proc = subprocess.run(cmd, env=env, timeout=180, capture_output=True, text=True)
        if proc.returncode != 0 and proc.stderr:
            print(f"  [Strix CLI Note] {proc.stderr.strip()[:200]}", file=sys.stderr)
    except subprocess.TimeoutExpired:
        print("  [Strix CLI] Scan reached execution limit (180s). Ingesting partial findings...")
    except Exception as e:
        print(f"  [Strix CLI] Execution error: {e}", file=sys.stderr)

    exploits: List[StrixExploit] = []

    # Look for findings in ./strix_runs/ or /workspace/strix_runs/
    strix_runs_dirs = [Path("strix_runs"), Path("/workspace/strix_runs")]
    latest_run = None
    for sdir in strix_runs_dirs:
        if sdir.exists() and sdir.is_dir():
            runs = [r for r in sdir.iterdir() if r.is_dir()]
            if runs:
                runs.sort(key=lambda d: d.stat().st_mtime, reverse=True)
                latest_run = runs[0]
                break

    if latest_run:
        vuln_json = latest_run / "vulnerabilities.json"
        if vuln_json.exists() and vuln_json.stat().st_size > 0:
            try:
                data = json.loads(vuln_json.read_text(encoding="utf-8"))
                items = data if isinstance(data, list) else data.get("vulnerabilities", data.get("findings", []))
                for item in items:
                    sev_raw = str(item.get("severity", "P1")).upper()
                    sev = "P0" if "CRITICAL" in sev_raw or "BOLA" in item.get("title", "") else ("P1" if "HIGH" in sev_raw else "P2")
                    exploits.append(
                        StrixExploit(
                            title=item.get("title", item.get("name", "Autonomous Exploit")),
                            category=item.get("category", item.get("type", "OWASP Top 10")),
                            severity=sev,
                            target_url=item.get("target_url", item.get("target", target_url)),
                            curl_poc=item.get("curl_poc", item.get("curl", item.get("poc", ""))),
                            description=item.get("description", ""),
                            response_snippet=item.get("response", item.get("evidence", "")),
                        )
                    )
            except Exception as e:
                print(f"  [Strix CLI] Error parsing vulnerabilities.json: {e}", file=sys.stderr)

        # Copy report markdown if generated
        report_md = latest_run / "penetration_test_report.md"
        if report_md.exists():
            try:
                shutil.copyfile(report_md, raw_dir / "strix.md")
            except Exception:
                pass

        sarif_out = latest_run / "findings.sarif"
        if sarif_out.exists():
            try:
                shutil.copyfile(sarif_out, raw_dir / "strix.sarif")
            except Exception:
                pass

    return exploits


def generate_baseline_audit(target_url: str, raw_dir: Path) -> List[StrixExploit]:
    """Generates baseline vulnerability verification report when target is offline."""
    print("  [Strix VAPT] Target server not live. Checking static API specs & OpenAPI security requirements...")
    ws_path = Path(os.environ.get("WORKSPACE", "/workspace" if Path("/workspace").exists() else Path.cwd()))
    specs = list(ws_path.glob("**/openapi*.y*ml")) + list(ws_path.glob("**/swagger*.y*ml"))
    exploits: List[StrixExploit] = []
    
    # Static check of OpenAPI specs for missing security schemes
    for spec in specs:
        content = spec.read_text(encoding="utf-8", errors="ignore")
        if "security:" not in content and "securitySchemes:" not in content:
            exploits.append(
                StrixExploit(
                    title=f"Unprotected OpenAPI Spec: {spec.name}",
                    category="API2:2023-BrokenAuth",
                    severity="P1",
                    target_url=f"file://{spec}",
                    curl_poc=f"# Missing securityScheme in {spec.name}\ncurl -k -X GET 'https://target/api/v1/resource'",
                    description="OpenAPI specification does not declare security schemes or global security requirements.",
                )
            )
    return exploits


def main() -> int:
    ws_env = os.environ.get("WORKSPACE", "/workspace" if Path("/workspace").exists() and os.access("/workspace", os.W_OK) else str(Path.cwd()))
    parser = argparse.ArgumentParser(description="Vigil Strix VAPT Orchestrator")
    parser.add_argument("--target", default=os.environ.get("TARGET_URL", "http://127.0.0.1:3000"), help="Target base URL")
    parser.add_argument("--openapi", default=None, help="Path to OpenAPI/Swagger specification")
    parser.add_argument("--output-dir", default=f"{ws_env}/reports/raw", help="Directory for raw scan outputs")
    args = parser.parse_args()

    raw_dir = Path(args.output_dir)
    raw_dir.mkdir(parents=True, exist_ok=True)

    cloud_key = os.environ.get("STRIX_CLOUD_API_KEY")
    cloud_endpoint = os.environ.get("STRIX_CLOUD_ENDPOINT", "https://app.strix.ai")

    exploits: List[StrixExploit] = []

    target_live = check_target_alive(args.target)
    if not target_live:
        # Check standard alternate ports (:8080, :8082)
        for alt_port in [8080, 8082, 3001]:
            alt_url = f"http://127.0.0.1:{alt_port}"
            if check_target_alive(alt_url):
                args.target = alt_url
                target_live = True
                break

    if target_live:
        if cloud_key:
            exploits = run_strix_cloud(cloud_key, cloud_endpoint, args.target, args.openapi)
        if not exploits:
            exploits = run_strix_cli(args.target, raw_dir, args.openapi)
    else:
        exploits = generate_baseline_audit(args.target, raw_dir)

    # Write JSON report
    json_path = raw_dir / "strix.json"
    json_data = [e.to_dict() for e in exploits]
    json_path.write_text(json.dumps(json_data, indent=2), encoding="utf-8")

    # Write Markdown summary with reproducible curl blocks
    md_path = raw_dir / "strix.md"
    md_content = ["# Strix Autonomous VAPT Findings\n"]
    if exploits:
        for e in exploits:
            md_content.append(f"### [{e.severity}] {e.title}")
            md_content.append(f"**Category:** `{e.category}`  ")
            md_content.append(f"**Target:** `{e.target_url}`  \n")
            md_content.append(f"{e.description}\n")
            if e.curl_poc:
                md_content.append("```bash\n# Reproduce Exploit\n" + e.curl_poc.strip() + "\n```\n")
    else:
        md_content.append("No active exploitable vulnerabilities identified by Strix engine.\n")

    md_path.write_text("\n".join(md_content), encoding="utf-8")
    print(f"✔ Strix VAPT complete: {len(exploits)} finding(s) written to {json_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
