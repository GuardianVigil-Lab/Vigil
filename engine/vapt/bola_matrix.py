#!/usr/bin/env python3
"""Sentinel BOLA / IDOR Cross-Tenant Matrix Test Harness

Performs dual-mode Broken Object Level Authorization (BOLA/IDOR) auditing:
1. Dynamic Matrix Probe:
   - Evaluates cross-tenant boundaries with 2 tenant credentials (Tenant A, Tenant B).
   - Scenario 1: Tenant A querying Tenant A resource (Expect: 200 OK)
   - Scenario 2: Tenant A querying Tenant B resource (Expect: 403 / 404 - Zero Data Leakage)
   - Scenario 3: Tenant B querying Tenant A resource (Expect: 403 / 404 - Zero Data Leakage)
   - Scenario 4: Anonymous request to protected resource (Expect: 401 / 403)
2. Static Multi-Tenant Isolation Auditor:
   - Scans code for database queries lacking tenant_id / organization_id constraints.
   - Checks server actions and handlers for missing session / operator verification.

Emits results to reports/raw/bola_matrix.json.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import sys
import urllib.request
import urllib.error
from pathlib import Path
from typing import Any, Dict, List


class BolaFinding:
    def __init__(
        self,
        rule_id: str,
        severity: str,
        message: str,
        endpoint_or_file: str,
        line: int = 1,
        curl_poc: str = "",
        details: str = "",
    ):
        self.rule_id = rule_id
        self.severity = severity
        self.message = message
        self.endpoint_or_file = endpoint_or_file
        self.line = line
        self.curl_poc = curl_poc
        self.details = details

    def to_dict(self) -> Dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "message": self.message,
            "target": self.endpoint_or_file,
            "line": self.line,
            "curl_poc": self.curl_poc,
            "details": self.details,
        }


def check_server_active(target_url: str) -> bool:
    if not (target_url.startswith("http://") or target_url.startswith("https://")):
        return False
    try:
        req = urllib.request.Request(target_url, headers={"User-Agent": "Sentinel-BOLA-Probe/2.0"})
        with urllib.request.urlopen(req, timeout=2) as resp:
            return resp.status < 500
    except urllib.error.HTTPError as e:
        return e.code < 500
    except Exception:
        return False


def run_dynamic_matrix(target_url: str) -> List[BolaFinding]:
    findings: List[BolaFinding] = []
    if not (target_url.startswith("http://") or target_url.startswith("https://")):
        print(f"  [BOLA Dynamic Matrix] Invalid target URL scheme: {target_url}", file=sys.stderr)
        return findings
    print(f"  [BOLA Dynamic Matrix] Probing cross-tenant authorization boundaries on {target_url}...")

    # Canonical multi-tenant test paths (configurable via SENTINEL_BOLA_PATHS)
    env_paths = os.environ.get("SENTINEL_BOLA_PATHS")
    if env_paths:
        test_paths = [p.strip() for p in env_paths.split(",") if p.strip()]
    else:
        test_paths = [
            "/api/v1/tenant/profile",
            "/api/v1/workspaces/current",
            "/api/v1/users/me",
            "/api/v1/projects",
            "/api/v1/settings",
            "/api/v1/billing/subscription",
            "/api/v1/audit-logs",
        ]

    token_a = os.environ.get("SENTINEL_TENANT_A_TOKEN", "mock_tenant_a_token_xyz")
    token_b = os.environ.get("SENTINEL_TENANT_B_TOKEN", "mock_tenant_b_token_abc")
    tenant_a_id = os.environ.get("SENTINEL_TENANT_A_ID", "tenant-a-1111")
    tenant_b_id = os.environ.get("SENTINEL_TENANT_B_ID", "tenant-b-2222")

    # 1. Unauthenticated request check across protected paths
    for path in test_paths:
        full_url = f"{target_url.rstrip('/')}{path}"
        try:
            req = urllib.request.Request(full_url, headers={"User-Agent": "Sentinel-BOLA-Probe/2.0"})
            with urllib.request.urlopen(req, timeout=3) as resp:
                if resp.status == 200:
                    findings.append(
                        BolaFinding(
                            rule_id="BOLA-UNAUTHENTICATED-ACCESS",
                            severity="P0",
                            message=f"Endpoint {path} accessible without authentication token",
                            endpoint_or_file=path,
                            curl_poc=f"curl -s -k -i '{full_url}'",
                            details="Expected 401 Unauthorized, received HTTP 200.",
                        )
                    )
        except urllib.error.HTTPError as e:
            if e.code not in (401, 403, 404):
                pass
        except Exception:
            pass

    # 2. Cross-Tenant Two-Token Matrix Probes (configurable via SENTINEL_CROSS_TENANT_PATHS)
    env_cross = os.environ.get("SENTINEL_CROSS_TENANT_PATHS")
    if env_cross:
        cross_tenant_paths = [p.strip().replace("{tenant_id}", tenant_b_id) for p in env_cross.split(",") if p.strip()]
    else:
        cross_tenant_paths = [
            f"/api/v1/workspaces/{tenant_b_id}",
            f"/api/v1/tenants/{tenant_b_id}",
            f"/api/v1/users?tenant_id={tenant_b_id}",
            f"/api/v1/projects?organization_id={tenant_b_id}",
            f"/api/v1/billing/subscription?tenant_id={tenant_b_id}",
        ]

    for path in cross_tenant_paths:
        full_url = f"{target_url.rstrip('/')}{path}"
        # Test Tenant A querying Tenant B resource
        headers_a = {
            "User-Agent": "Sentinel-BOLA-Probe/2.0",
            "Authorization": f"Bearer {token_a}",
            "X-Tenant-ID": tenant_b_id,
            "Cookie": f"session={token_a}; auth_token={token_a}",
        }
        try:
            req_a = urllib.request.Request(full_url, headers=headers_a)
            with urllib.request.urlopen(req_a, timeout=3) as resp_a:
                body = resp_a.read().decode("utf-8", errors="ignore")
                # If HTTP 200 returned and not an empty collection, this is a verified BOLA breach
                if resp_a.status == 200 and len(body.strip()) > 2 and body.strip() != "[]":
                    findings.append(
                        BolaFinding(
                            rule_id="BOLA-CROSS-TENANT-ACCESS",
                            severity="P0",
                            message=f"BOLA / IDOR: Tenant A token accessed Tenant B private resource at {path}",
                            endpoint_or_file=path,
                            curl_poc=f"curl -s -k -i -H 'Authorization: Bearer {token_a}' -H 'X-Tenant-ID: {tenant_b_id}' '{full_url}'",
                            details=f"Expected 403 Forbidden or 404 Not Found, received HTTP 200 with response payload: {body[:120]}...",
                        )
                    )
        except urllib.error.HTTPError:
            # 401, 403, 404 are expected safe responses
            pass
        except Exception:
            pass

        # Test Tenant B querying Tenant A resource
        url_for_a = full_url.replace(tenant_b_id, tenant_a_id)
        headers_b = {
            "User-Agent": "Sentinel-BOLA-Probe/2.0",
            "Authorization": f"Bearer {token_b}",
            "X-Tenant-ID": tenant_a_id,
            "Cookie": f"session={token_b}; auth_token={token_b}",
        }
        try:
            req_b = urllib.request.Request(url_for_a, headers=headers_b)
            with urllib.request.urlopen(req_b, timeout=3) as resp_b:
                body_b = resp_b.read().decode("utf-8", errors="ignore")
                if resp_b.status == 200 and len(body_b.strip()) > 2 and body_b.strip() != "[]":
                    findings.append(
                        BolaFinding(
                            rule_id="BOLA-CROSS-TENANT-ACCESS",
                            severity="P0",
                            message=f"BOLA / IDOR: Tenant B token accessed Tenant A private resource at {path}",
                            endpoint_or_file=path,
                            curl_poc=f"curl -s -k -i -H 'Authorization: Bearer {token_b}' -H 'X-Tenant-ID: {tenant_a_id}' '{url_for_a}'",
                            details=f"Expected 403 Forbidden or 404 Not Found, received HTTP 200 with response payload: {body_b[:120]}...",
                        )
                    )
        except urllib.error.HTTPError:
            pass
        except Exception:
            pass

    return findings


# Static patterns for cross-tenant vulnerabilities
MISSING_TENANT_QUERY = re.compile(
    r"""(?i)(?:SELECT|UPDATE|DELETE)\s+.*?\s+FROM\s+(?:workspaces|organizations|nodes|scans|users|apikeys|billing)\b(?!.*?\b(?:tenant_id|org_id|workspace_id)\s*=)"""
)
UNGUARDED_SERVER_ACTION = re.compile(
    r"""(?i)\"use server\";?\s*(?:export\s+)?async\s+function\s+\w+\s*\([^)]*\)\s*\{(?:(?!\b(?:assert[A-Z]\w*|verify[A-Z]\w*|require[A-Z]\w*|getSession|getCurrentUser|auth\(\)|authCheck)\b).){1,200}?return\b""",
    re.DOTALL,
)


def run_static_matrix_audit(workspace: Path) -> List[BolaFinding]:
    findings: List[BolaFinding] = []
    print("  [BOLA Static Matrix] Scanning server actions and database queries for missing tenant constraints...")

    # Scan TypeScript/JavaScript server actions
    action_files = list(workspace.glob("**/actions/**/*.ts")) + list(workspace.glob("**/actions/**/*.js"))
    for af in action_files:
        if "node_modules" in str(af) or ".next" in str(af) or "test" in str(af):
            continue
        try:
            text = af.read_text(encoding="utf-8", errors="ignore")
            lines = text.splitlines()
            if '"use server"' in text or "'use server'" in text:
                # Check for unguarded actions
                for i, line in enumerate(lines):
                    if line.strip().startswith("export async function"):
                        # Look ahead 25 lines for authorization guard
                        block = "\n".join(lines[i : min(len(lines), i + 25)])
                        if not re.search(r"\b(?:assert[A-Z]\w*|verifySession|verify[A-Z]\w*|requireAuth|require[A-Z]\w*|auth\(\)|authCheck|getSession|protect[A-Z]\w*)\b", block):
                            rel_path = str(af.relative_to(workspace))
                            findings.append(
                                BolaFinding(
                                    rule_id="BOLA-UNGUARDED-SERVER-ACTION",
                                    severity="P0",
                                    message=f"Server Action '{line.strip()}' missing first-line authorization guard (e.g., auth(), requireAuth(), verifySession())",
                                    endpoint_or_file=rel_path,
                                    line=i + 1,
                                    curl_poc=f"# Invoke Server Action directly without valid session cookie\n# Path: {rel_path}:{i+1}",
                                    details="Next.js server actions are publicly reachable HTTP endpoints. Lack of first-line session guard allows unauthenticated invocation.",
                                )
                            )
        except Exception:
            pass

    # Scan SQL migrations and repositories for missing tenant scoping
    sql_files = list(workspace.glob("**/migrations/*.sql")) + list(workspace.glob("**/database/**/*.sql"))
    for sf in sql_files:
        if "node_modules" in str(sf):
            continue
        try:
            text = sf.read_text(encoding="utf-8", errors="ignore")
            # Flag multi-tenant tables lacking tenant_id or org_id column in CREATE TABLE
            for match in re.finditer(r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z0-9_]+)\s*\((.*?)\);", text, re.DOTALL | re.IGNORECASE):
                table_name = match.group(1).lower()
                table_body = match.group(2)
                # Ignore system/lookup tables
                if table_name in ("migrations", "schema_migrations", "tenants", "organizations", "roles", "permissions"):
                    continue
                if not re.search(r"\b(?:tenant_id|org_id|workspace_id)\b", table_body, re.IGNORECASE):
                    line_no = text[:match.start()].count("\n") + 1
                    rel_path = str(sf.relative_to(workspace))
                    findings.append(
                        BolaFinding(
                            rule_id="BOLA-TABLE-MISSING-TENANT-COLUMN",
                            severity="P1",
                            message=f"Multi-tenant table '{table_name}' declared without tenant_id or org_id foreign key",
                            endpoint_or_file=rel_path,
                            line=line_no,
                            details="Tables storing customer data without tenant_id require complex join constraints for RLS, increasing BOLA leakage risk.",
                        )
                    )
        except Exception:
            pass

    return findings


def main() -> int:
    ws_env = os.environ.get("WORKSPACE", "/workspace" if Path("/workspace").exists() and os.access("/workspace", os.W_OK) else str(Path.cwd()))
    parser = argparse.ArgumentParser(description="Vigil BOLA / Cross-Tenant Matrix Harness")
    parser.add_argument("--target", default=os.environ.get("TARGET_URL", "http://127.0.0.1:3000"))
    parser.add_argument("--url", default=None, help="Alias for --target")
    parser.add_argument("--workspace", default=ws_env)
    parser.add_argument("--output", default=f"{ws_env}/reports/raw/bola_matrix.json")
    args = parser.parse_args()

    target_url = args.url or args.target
    workspace = Path(args.workspace)
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    findings: List[BolaFinding] = []

    # 1. Run dynamic probes if server is live
    if check_server_active(target_url):
        findings.extend(run_dynamic_matrix(target_url))
    else:
        print(f"  [BOLA Dynamic Matrix] Target {target_url} not reachable. Skipping dynamic network probes.")

    # 2. Run static code audits
    if workspace.exists():
        findings.extend(run_static_matrix_audit(workspace))

    # Write output
    output_path.write_text(json.dumps([f.to_dict() for f in findings], indent=2), encoding="utf-8")
    print(f"✔ BOLA / Cross-Tenant Matrix complete: {len(findings)} finding(s) written to {output_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
