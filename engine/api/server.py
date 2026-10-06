#!/usr/bin/env python3
"""
Vigil REST API & Webhook Service
Provides HTTP endpoints for triggering audits, querying scan statuses,
retrieving SARIF / Markdown reports, receiving CI webhooks, and browsing OpenAPI docs.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import re
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import parse_qs, urlparse

VIGIL_ROOT = Path(__file__).resolve().parent.parent.parent

# In-memory scan store
SCANS: Dict[str, Dict[str, Any]] = {}
SCANS_LOCK = threading.Lock()


def execute_scan_worker(scan_id: str, battery: str, workspace: str, target_url: Optional[str]) -> None:
    """Background worker thread executing Vigil orchestrator."""
    with SCANS_LOCK:
        SCANS[scan_id]["status"] = "running"
        SCANS[scan_id]["started_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    start_time = time.time()
    try:
        ws_path = Path(workspace).resolve()
        if not ws_path.exists():
            ws_path.mkdir(parents=True, exist_ok=True)

        reports_dir = ws_path / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        vigil_script = VIGIL_ROOT / "vigil.sh"
        if not vigil_script.exists():
            vigil_script = VIGIL_ROOT / "sentinel.sh"

        env = os.environ.copy()
        env["WORKSPACE"] = str(ws_path)
        if target_url:
            env["TARGET_URL"] = target_url

        cmd = ["bash", str(vigil_script), battery]
        proc = subprocess.run(
            cmd,
            cwd=str(ws_path),
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            timeout=300,
            env=env,
        )
        exit_code = proc.returncode
        stdout = proc.stdout
        stderr = proc.stderr
    except subprocess.TimeoutExpired:
        exit_code = 124
        stdout = ""
        stderr = "Scan timed out after 300 seconds"
    except Exception as e:
        exit_code = 1
        stdout = ""
        stderr = f"Execution error: {str(e)}"

    elapsed = round(time.time() - start_time, 2)
    sarif_path = ws_path / "reports" / "vigil.sarif"
    if not sarif_path.exists():
        sarif_path = ws_path / "reports" / "sentinel.sarif"

    markdown_path = ws_path / "reports" / "vigil-review.md"
    if not markdown_path.exists():
        markdown_path = ws_path / "reports" / "sentinel-review.md"

    # Count findings from SARIF if available
    p0 = p1 = p2 = p3 = 0
    if sarif_path.exists():
        try:
            sarif_data = json.loads(sarif_path.read_text(encoding="utf-8"))
            for run in sarif_data.get("runs", []):
                for res in run.get("results", []):
                    sev = res.get("properties", {}).get("severity", "P2")
                    if sev == "P0":
                        p0 += 1
                    elif sev == "P1":
                        p1 += 1
                    elif sev == "P2":
                        p2 += 1
                    else:
                        p3 += 1
        except Exception:
            pass

    verdict = "PASSED" if exit_code == 0 else "FAILED"

    with SCANS_LOCK:
        SCANS[scan_id].update({
            "status": "completed",
            "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "elapsed_seconds": elapsed,
            "exit_code": exit_code,
            "verdict": verdict,
            "blockers": p0 + p1,
            "advisories": p2 + p3,
            "findings_summary": {"p0": p0, "p1": p1, "p2": p2, "p3": p3},
            "sarif_path": str(sarif_path) if sarif_path.exists() else None,
            "markdown_path": str(markdown_path) if markdown_path.exists() else None,
            "log": (stdout + "\n" + stderr).strip(),
        })


OPENAPI_SPEC = {
    "openapi": "3.0.3",
    "info": {
        "title": "Vigil Security & Quality Engine REST API",
        "description": "Enterprise API for triggering Vigil audits, querying SARIF reports, and handling CI/CD webhooks.",
        "version": "2.1.0",
        "contact": {
            "name": "GuardianVigil Engineering",
            "url": "https://github.com/GuardianVigil-Lab/vigil",
        },
    },
    "paths": {
        "/api/v1/health": {
            "get": {
                "summary": "Engine Health Check",
                "responses": {
                    "200": {"description": "Service is healthy and operational"}
                }
            }
        },
        "/api/v1/scan": {
            "post": {
                "summary": "Trigger a New Audit Scan",
                "requestBody": {
                    "required": True,
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "battery": {
                                        "type": "string",
                                        "enum": ["fast", "quality", "security", "vapt", "test", "e2e", "review"],
                                        "default": "review"
                                    },
                                    "workspace": {
                                        "type": "string",
                                        "default": "."
                                    },
                                    "target_url": {
                                        "type": "string",
                                        "default": "http://127.0.0.1:3000"
                                    },
                                    "async": {
                                        "type": "boolean",
                                        "default": True
                                    }
                                }
                            }
                        }
                    }
                },
                "responses": {
                    "202": {"description": "Scan queued or running"},
                    "200": {"description": "Scan completed (synchronous mode)"}
                }
            }
        },
        "/api/v1/scans/{scan_id}": {
            "get": {
                "summary": "Get Scan Status and Summary",
                "parameters": [
                    {
                        "name": "scan_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"}
                    }
                ],
                "responses": {
                    "200": {"description": "Current status and metrics of the requested scan"},
                    "404": {"description": "Scan not found"}
                }
            }
        },
        "/api/v1/scans/{scan_id}/sarif": {
            "get": {
                "summary": "Retrieve SARIF 2.1.0 Report",
                "parameters": [
                    {
                        "name": "scan_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"}
                    }
                ],
                "responses": {
                    "200": {"description": "SARIF 2.1.0 JSON payload"},
                    "404": {"description": "SARIF report not found"}
                }
            }
        },
        "/api/v1/scans/{scan_id}/report": {
            "get": {
                "summary": "Retrieve Markdown Audit Review",
                "parameters": [
                    {
                        "name": "scan_id",
                        "in": "path",
                        "required": True,
                        "schema": {"type": "string"}
                    }
                ],
                "responses": {
                    "200": {"description": "Markdown formatted audit report"},
                    "404": {"description": "Report not found"}
                }
            }
        },
        "/api/v1/webhook": {
            "post": {
                "summary": "Handle GitHub or GitLab Incoming Webhook",
                "responses": {
                    "202": {"description": "Webhook received and audit scan initiated"}
                }
            }
        }
    }
}

SWAGGER_HTML = f"""<!DOCTYPE html>
<html>
<head>
  <title>Vigil REST API Documentation</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui.css">
  <style>
    body {{ margin: 0; background: #0f172a; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; }}
    .swagger-ui .topbar {{ display: none; }}
    #swagger-ui {{ background: #ffffff; margin: 24px auto; max-width: 1200px; border-radius: 8px; box-shadow: 0 4px 6px -1px rgba(0, 0, 0, 0.1); padding: 16px; min-height: 80vh; }}
    .header {{ padding: 24px 32px; background: #020617; border-bottom: 1px solid #1e293b; color: white; display: flex; align-items: center; justify-content: space-between; }}
    .header h1 {{ margin: 0; font-size: 20px; font-weight: 700; color: #38bdf8; display: flex; align-items: center; gap: 10px; }}
    .badge {{ background: #1e293b; padding: 4px 10px; border-radius: 9999px; font-size: 12px; color: #94a3b8; font-weight: 600; }}
  </style>
</head>
<body>
  <div class="header">
    <h1>🛡️ Vigil Security & Quality Engine API</h1>
    <span class="badge">v2.1.0 (Enterprise)</span>
  </div>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5.11.0/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function() {{
      window.ui = SwaggerUIBundle({{
        url: '/openapi.json',
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
        layout: "BaseLayout"
      }});
    }};
  </script>
</body>
</html>
"""


class VigilAPIHandler(BaseHTTPRequestHandler):
    """HTTP request handler for Vigil REST API."""

    def _send_json(self, status: int, data: Any) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-GitHub-Event")
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(self, status: int, text: str, content_type: str = "text/plain") -> None:
        payload = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.end_headers()
        self.wfile.write(payload)

    def do_OPTIONS(self) -> None:
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization, X-GitHub-Event")
        self.end_headers()

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path in ("", "/health", "/api/v1/health"):
            self._send_json(200, {
                "status": "healthy",
                "service": "Vigil Security & Quality Engine",
                "version": "2.1.0",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "active_scans": len([s for s in SCANS.values() if s.get("status") == "running"]),
            })
            return

        if path == "/openapi.json":
            self._send_json(200, OPENAPI_SPEC)
            return

        if path in ("/docs", "/api"):
            self._send_text(200, SWAGGER_HTML, content_type="text/html")
            return

        # Matches /api/v1/scans/{scan_id}
        m_scan = re.match(r"^/api/v1/scans/([a-zA-Z0-9_-]+)$", path)
        if m_scan:
            scan_id = m_scan.group(1)
            with SCANS_LOCK:
                scan = SCANS.get(scan_id)
            if not scan:
                self._send_json(404, {"error": "Scan not found", "scan_id": scan_id})
            else:
                self._send_json(200, scan)
            return

        # Matches /api/v1/scans/{scan_id}/sarif
        m_sarif = re.match(r"^/api/v1/scans/([a-zA-Z0-9_-]+)/sarif$", path)
        if m_sarif:
            scan_id = m_sarif.group(1)
            with SCANS_LOCK:
                scan = SCANS.get(scan_id)
            if not scan:
                self._send_json(404, {"error": "Scan not found", "scan_id": scan_id})
                return
            if scan.get("status") in ("queued", "running"):
                self._send_json(202, {"status": scan.get("status"), "message": "Scan is still in progress. Please retry after completion.", "scan_id": scan_id})
                return
            sarif_file = scan.get("sarif_path")
            if sarif_file and Path(sarif_file).exists():
                try:
                    sarif_json = json.loads(Path(sarif_file).read_text(encoding="utf-8"))
                    self._send_json(200, sarif_json)
                except Exception as parse_err:
                    self._send_json(500, {"error": f"Failed to parse SARIF report: {str(parse_err)}", "scan_id": scan_id})
            else:
                self._send_json(404, {"error": "SARIF file not generated or missing", "scan_id": scan_id})
            return

        # Matches /api/v1/scans/{scan_id}/report
        m_rep = re.match(r"^/api/v1/scans/([a-zA-Z0-9_-]+)/report$", path)
        if m_rep:
            scan_id = m_rep.group(1)
            with SCANS_LOCK:
                scan = SCANS.get(scan_id)
            if not scan:
                self._send_json(404, {"error": "Scan not found", "scan_id": scan_id})
                return
            if scan.get("status") in ("queued", "running"):
                self._send_json(202, {"status": scan.get("status"), "message": "Scan is still in progress. Please retry after completion.", "scan_id": scan_id})
                return
            rep_file = scan.get("markdown_path")
            if rep_file and Path(rep_file).exists():
                rep_md = Path(rep_file).read_text(encoding="utf-8")
                self._send_text(200, rep_md, content_type="text/markdown")
            else:
                self._send_json(404, {"error": "Report not generated or missing", "scan_id": scan_id})
            return

        self._send_json(404, {"error": "Endpoint not found", "path": path})

    def do_POST(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length).decode("utf-8") if content_length > 0 else "{}"

        try:
            payload = json.loads(body) if body.strip() else {}
        except Exception:
            payload = {}

        if path == "/api/v1/scan":
            battery = payload.get("battery", "review")
            workspace = payload.get("workspace", ".")
            target_url = payload.get("target_url")
            is_async = payload.get("async", payload.get("is_async", True))

            scan_id = str(uuid.uuid4())
            with SCANS_LOCK:
                SCANS[scan_id] = {
                    "scan_id": scan_id,
                    "battery": battery,
                    "workspace": workspace,
                    "target_url": target_url,
                    "status": "queued",
                    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }

            if is_async:
                t = threading.Thread(
                    target=execute_scan_worker,
                    args=(scan_id, battery, workspace, target_url),
                    daemon=True,
                )
                t.start()
                self._send_json(202, {
                    "scan_id": scan_id,
                    "status": "queued",
                    "message": f"Vigil audit '{battery}' enqueued for workspace '{workspace}'",
                    "status_url": f"/api/v1/scans/{scan_id}",
                    "sarif_url": f"/api/v1/scans/{scan_id}/sarif",
                    "report_url": f"/api/v1/scans/{scan_id}/report",
                })
            else:
                execute_scan_worker(scan_id, battery, workspace, target_url)
                with SCANS_LOCK:
                    res = SCANS[scan_id]
                self._send_json(200, res)
            return

        if path == "/api/v1/webhook":
            event_type = self.headers.get("X-GitHub-Event") or self.headers.get("X-Gitlab-Event") or "push"
            scan_id = str(uuid.uuid4())
            repo_name = payload.get("repository", {}).get("name", "webhook-repo")
            workspace = os.environ.get("VIGIL_DEFAULT_WORKSPACE", ".")

            with SCANS_LOCK:
                SCANS[scan_id] = {
                    "scan_id": scan_id,
                    "event": event_type,
                    "repository": repo_name,
                    "battery": "review",
                    "workspace": workspace,
                    "status": "queued",
                    "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                }

            t = threading.Thread(
                target=execute_scan_worker,
                args=(scan_id, "review", workspace, None),
                daemon=True,
            )
            t.start()

            self._send_json(202, {
                "scan_id": scan_id,
                "event": event_type,
                "status": "enqueued",
                "message": f"Audit triggered for event '{event_type}' on '{repo_name}'",
                "status_url": f"/api/v1/scans/{scan_id}",
            })
            return

        self._send_json(404, {"error": "Endpoint not found", "path": path})


def run_server(host: str = "0.0.0.0", port: int = 8080) -> None:
    server = ThreadingHTTPServer((host, port), VigilAPIHandler)
    print(f"══════════════════════════════════════════════════════════════════════")
    print(f"  Vigil REST API Server listening on http://{host}:{port}")
    print(f"  Swagger OpenAPI Documentation: http://{host}:{port}/docs")
    print(f"  OpenAPI Specification:        http://{host}:{port}/openapi.json")
    print(f"  Health Check:                 http://{host}:{port}/api/v1/health")
    print(f"══════════════════════════════════════════════════════════════════════")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Vigil REST API Server.")
        server.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(description="Vigil REST API & Webhook Service")
    parser.add_argument("--host", default="0.0.0.0", help="Host interface to bind")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
