#!/usr/bin/env python3
"""
Vigil REST API & Webhook Service
Provides HTTP endpoints for triggering audits, querying scan statuses,
retrieving SARIF / Markdown reports, receiving CI webhooks, and browsing OpenAPI docs.
"""

from __future__ import annotations

import argparse
import datetime
import hashlib
import hmac
import ipaddress
import json
import os
import re
import secrets
import subprocess
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

VIGIL_ROOT = Path(__file__).resolve().parent.parent.parent

# In-memory scan store
SCANS: Dict[str, Dict[str, Any]] = {}
SCANS_LOCK = threading.Lock()

BATTERIES = ("fast", "quality", "security", "vapt", "test", "e2e", "review")
MAX_BODY_BYTES = 1 << 20

# Set by run_server; module-level so the handler and the tests share them.
API_TOKEN = ""
WEBHOOK_SECRET = ""
MAX_RUNNING = 2


class RequestError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message


def workspace_root() -> Path:
    """The only directory scans may run in. Every requested workspace must
    resolve inside it, so a caller cannot point a scan at /etc or $HOME."""
    configured = os.environ.get("VIGIL_WORKSPACE_ROOT")
    if configured:
        return Path(configured).resolve()
    if Path("/workspace").is_dir():
        return Path("/workspace").resolve()
    return Path.cwd().resolve()


def resolve_workspace(requested: Any) -> Path:
    if requested is None:
        requested = "."
    if not isinstance(requested, str) or "\x00" in requested:
        raise RequestError(400, "workspace must be a path string")
    root = workspace_root()
    candidate = Path(requested)
    resolved = (candidate if candidate.is_absolute() else root / candidate).resolve()
    if resolved != root and root not in resolved.parents:
        raise RequestError(403, "workspace must be inside the configured workspace root")
    if not resolved.is_dir():
        raise RequestError(400, "workspace does not exist")
    return resolved


def validate_battery(battery: Any) -> str:
    if battery not in BATTERIES:
        raise RequestError(400, f"battery must be one of: {', '.join(BATTERIES)}")
    return battery


def validate_target_url(target_url: Any) -> Optional[str]:
    if target_url is None:
        return None
    if not isinstance(target_url, str):
        raise RequestError(400, "target_url must be a string")
    parsed = urlparse(target_url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise RequestError(400, "target_url must be an http(s) URL")
    return target_url


def bearer_ok(header: Optional[str]) -> bool:
    if not API_TOKEN or not header or not header.startswith("Bearer "):
        return False
    return hmac.compare_digest(header[len("Bearer "):].encode(), API_TOKEN.encode())


def webhook_signature_ok(headers: Any, body: bytes) -> bool:
    """GitHub signs the raw body (X-Hub-Signature-256); GitLab sends the shared
    secret itself (X-Gitlab-Token). Either must match WEBHOOK_SECRET."""
    if not WEBHOOK_SECRET:
        return False
    sig = headers.get("X-Hub-Signature-256")
    if sig:
        expected = "sha256=" + hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()
        return hmac.compare_digest(sig.encode(), expected.encode())
    token = headers.get("X-Gitlab-Token")
    if token:
        return hmac.compare_digest(token.encode(), WEBHOOK_SECRET.encode())
    return False




def execute_scan_worker(scan_id: str, battery: str, workspace: str, target_url: Optional[str]) -> None:
    """Background worker thread executing Vigil orchestrator."""
    with SCANS_LOCK:
        SCANS[scan_id]["status"] = "running"
        SCANS[scan_id]["started_at"] = datetime.datetime.now(datetime.timezone.utc).isoformat()

    start_time = time.time()
    try:
        ws_path = Path(workspace)
        reports_dir = ws_path / "reports"
        reports_dir.mkdir(parents=True, exist_ok=True)

        vigil_script = VIGIL_ROOT / "vigil.sh"

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
    ws_path = Path(workspace)
    sarif_path = ws_path / "reports" / "vigil.sarif"

    markdown_path = ws_path / "reports" / "vigil-review.md"

    # Count findings from the SARIF report. A missing or unreadable report is
    # "not counted", never zero findings.
    p0 = p1 = p2 = p3 = 0
    counted = False
    findings_error = None
    if not sarif_path.exists():
        findings_error = "no SARIF report was produced"
    else:
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
            counted = True
        except (OSError, ValueError, AttributeError) as e:
            findings_error = f"SARIF report could not be read: {e.__class__.__name__}"

    verdict = "PASSED" if exit_code == 0 else "FAILED"

    with SCANS_LOCK:
        SCANS[scan_id].update({
            "status": "completed",
            "completed_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            "elapsed_seconds": elapsed,
            "exit_code": exit_code,
            "verdict": verdict,
            "blockers": p0 + p1 if counted else None,
            "advisories": p2 + p3 if counted else None,
            "findings_summary": {"p0": p0, "p1": p1, "p2": p2, "p3": p3} if counted else None,
            "findings_error": findings_error,
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
            "name": "Vigil",
            "url": "https://github.com/GuardianVigil-Lab/vigil",
        },
    },
    "components": {
        "securitySchemes": {
            "bearer": {"type": "http", "scheme": "bearer"},
            "webhookSignature": {"type": "apiKey", "in": "header", "name": "X-Hub-Signature-256"},
        }
    },
    "security": [{"bearer": []}],
    "paths": {
        "/api/v1/health": {
            "get": {
                "summary": "Engine Health Check",
                "security": [],
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
                                        "default": ".",
                                        "description": "Path inside VIGIL_WORKSPACE_ROOT"
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
                "description": "Requires VIGIL_WEBHOOK_SECRET. GitHub requests must carry a valid X-Hub-Signature-256; GitLab requests an X-Gitlab-Token equal to the secret.",
                "security": [{"webhookSignature": []}],
                "responses": {
                    "202": {"description": "Webhook received and audit scan initiated"},
                    "401": {"description": "Missing or invalid signature"},
                    "503": {"description": "No webhook secret is configured"}
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
    """HTTP request handler for Vigil REST API.

    No CORS headers: the API is for CI systems and local tools, not for other
    origins' pages, and a browser page must not be able to start a scan.
    """

    server_version = "Vigil"
    sys_version = ""

    def _send_json(self, status: int, data: Any) -> None:
        payload = json.dumps(data, indent=2).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(payload)

    def _send_text(self, status: int, text: str, content_type: str = "text/plain") -> None:
        payload = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", f"{content_type}; charset=utf-8")
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def _authorized(self) -> bool:
        if bearer_ok(self.headers.get("Authorization")):
            return True
        self._send_json(401, {"error": "A valid Authorization: Bearer <VIGIL_API_TOKEN> header is required"})
        return False

    def _read_body(self) -> bytes:
        raw_len = self.headers.get("Content-Length", "0")
        try:
            length = int(raw_len)
        except ValueError:
            raise RequestError(400, "invalid Content-Length") from None
        if length < 0:
            raise RequestError(400, "invalid Content-Length")
        if length > MAX_BODY_BYTES:
            raise RequestError(413, f"request body exceeds {MAX_BODY_BYTES} bytes")
        return self.rfile.read(length) if length else b""

    def _get_scan(self, scan_id: str) -> Optional[Dict[str, Any]]:
        with SCANS_LOCK:
            scan = SCANS.get(scan_id)
            return dict(scan) if scan else None

    def do_GET(self) -> None:
        parsed = urlparse(self.path)
        path = parsed.path.rstrip("/")

        if path in ("", "/health", "/api/v1/health"):
            self._send_json(200, {
                "status": "healthy",
                "service": "Vigil Security & Quality Engine",
                "version": "2.1.0",
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
            })
            return

        if path == "/openapi.json":
            self._send_json(200, OPENAPI_SPEC)
            return

        if path in ("/docs", "/api"):
            self._send_text(200, SWAGGER_HTML, content_type="text/html")
            return

        m = re.match(r"^/api/v1/scans/([a-zA-Z0-9_-]+)(/sarif|/report)?$", path)
        if not m:
            self._send_json(404, {"error": "Endpoint not found"})
            return
        if not self._authorized():
            return

        scan_id, kind = m.group(1), m.group(2)
        scan = self._get_scan(scan_id)
        if not scan:
            self._send_json(404, {"error": "Scan not found", "scan_id": scan_id})
            return
        if kind is None:
            self._send_json(200, scan)
            return
        if scan.get("status") in ("queued", "running"):
            self._send_json(202, {"status": scan.get("status"), "message": "Scan is still in progress. Please retry after completion.", "scan_id": scan_id})
            return

        if kind == "/sarif":
            sarif_file = scan.get("sarif_path")
            if sarif_file and Path(sarif_file).exists():
                try:
                    self._send_json(200, json.loads(Path(sarif_file).read_text(encoding="utf-8")))
                except (OSError, ValueError):
                    self._send_json(500, {"error": "Failed to parse SARIF report", "scan_id": scan_id})
            else:
                self._send_json(404, {"error": "SARIF file not generated or missing", "scan_id": scan_id})
            return

        rep_file = scan.get("markdown_path")
        if rep_file and Path(rep_file).exists():
            self._send_text(200, Path(rep_file).read_text(encoding="utf-8"), content_type="text/markdown")
        else:
            self._send_json(404, {"error": "Report not generated or missing", "scan_id": scan_id})

    def do_POST(self) -> None:
        path = urlparse(self.path).path.rstrip("/")
        try:
            if path == "/api/v1/scan":
                self._post_scan()
            elif path == "/api/v1/webhook":
                self._post_webhook()
            else:
                self._send_json(404, {"error": "Endpoint not found"})
        except RequestError as e:
            self._send_json(e.status, {"error": e.message})

    def _start(self, record: Dict[str, Any], battery: str, workspace: Path,
               target_url: Optional[str], is_async: bool = True) -> Optional[Dict[str, Any]]:
        """Register and start a scan, or refuse when too many are running."""
        with SCANS_LOCK:
            if sum(1 for s in SCANS.values() if s.get("status") in ("queued", "running")) >= MAX_RUNNING:
                raise RequestError(429, "too many scans are running; retry later")
            SCANS[record["scan_id"]] = record
        if is_async:
            threading.Thread(
                target=execute_scan_worker,
                args=(record["scan_id"], battery, str(workspace), target_url),
                daemon=True,
            ).start()
            return None
        execute_scan_worker(record["scan_id"], battery, str(workspace), target_url)
        return self._get_scan(record["scan_id"])

    def _post_scan(self) -> None:
        if not self._authorized():
            return
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type != "application/json":
            raise RequestError(415, "Content-Type must be application/json")
        body = self._read_body()
        try:
            payload = json.loads(body) if body.strip() else {}
        except ValueError:
            raise RequestError(400, "body is not valid JSON") from None
        if not isinstance(payload, dict):
            raise RequestError(400, "body must be a JSON object")

        battery = validate_battery(payload.get("battery", "review"))
        workspace = resolve_workspace(payload.get("workspace", "."))
        target_url = validate_target_url(payload.get("target_url"))
        is_async = payload.get("async", payload.get("is_async", True)) is not False

        scan_id = str(uuid.uuid4())
        record = {
            "scan_id": scan_id,
            "battery": battery,
            "workspace": str(workspace),
            "target_url": target_url,
            "status": "queued",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        result = self._start(record, battery, workspace, target_url, is_async)
        if result is not None:
            self._send_json(200, result)
            return
        self._send_json(202, {
            "scan_id": scan_id,
            "status": "queued",
            "message": f"Vigil audit '{battery}' enqueued",
            "status_url": f"/api/v1/scans/{scan_id}",
            "sarif_url": f"/api/v1/scans/{scan_id}/sarif",
            "report_url": f"/api/v1/scans/{scan_id}/report",
        })

    def _post_webhook(self) -> None:
        if not WEBHOOK_SECRET:
            raise RequestError(503, "webhooks are disabled: set VIGIL_WEBHOOK_SECRET to enable them")
        body = self._read_body()
        if not webhook_signature_ok(self.headers, body):
            raise RequestError(401, "missing or invalid webhook signature")

        event_type = self.headers.get("X-GitHub-Event") or self.headers.get("X-Gitlab-Event") or "push"
        if event_type == "ping":
            self._send_json(200, {"status": "pong"})
            return
        try:
            payload = json.loads(body) if body.strip() else {}
        except ValueError:
            raise RequestError(400, "body is not valid JSON") from None
        repo = payload.get("repository") if isinstance(payload, dict) else None
        repo_name = repo.get("name", "webhook-repo") if isinstance(repo, dict) else "webhook-repo"
        workspace = resolve_workspace(os.environ.get("VIGIL_DEFAULT_WORKSPACE", "."))

        scan_id = str(uuid.uuid4())
        record = {
            "scan_id": scan_id,
            "event": event_type,
            "repository": str(repo_name)[:200],
            "battery": "review",
            "workspace": str(workspace),
            "status": "queued",
            "created_at": datetime.datetime.now(datetime.timezone.utc).isoformat(),
        }
        self._start(record, "review", workspace, None)
        self._send_json(202, {
            "scan_id": scan_id,
            "event": event_type,
            "status": "enqueued",
            "status_url": f"/api/v1/scans/{scan_id}",
        })


def is_loopback(host: str) -> bool:
    if host == "localhost":
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def configure(token: Optional[str] = None, webhook_secret: Optional[str] = None,
              max_running: Optional[int] = None) -> bool:
    """Set the server's credentials. Returns True when the token was generated."""
    global API_TOKEN, WEBHOOK_SECRET, MAX_RUNNING
    token = token if token is not None else os.environ.get("VIGIL_API_TOKEN", "")
    generated = not token
    API_TOKEN = token or secrets.token_urlsafe(32)
    WEBHOOK_SECRET = webhook_secret if webhook_secret is not None else os.environ.get("VIGIL_WEBHOOK_SECRET", "")
    if max_running is None:
        try:
            max_running = int(os.environ.get("VIGIL_API_MAX_SCANS", "2"))
        except ValueError:
            max_running = 2
    MAX_RUNNING = max(1, max_running)
    return generated


def run_server(host: str = "127.0.0.1", port: int = 8080) -> None:
    generated = configure()
    if not is_loopback(host) and generated:
        print("Refusing to listen on a non-loopback address without VIGIL_API_TOKEN set.", file=sys.stderr)
        sys.exit(2)
    server = ThreadingHTTPServer((host, port), VigilAPIHandler)
    print("══════════════════════════════════════════════════════════════════════")
    print(f"  Vigil REST API Server listening on http://{host}:{port}")
    print(f"  Workspace root:               {workspace_root()}")
    print(f"  Swagger OpenAPI Documentation: http://{host}:{port}/docs")
    print(f"  Health Check:                 http://{host}:{port}/api/v1/health")
    if generated:
        print(f"  API token (generated for this run): {API_TOKEN}")
    print(f"  Webhooks: {'enabled' if WEBHOOK_SECRET else 'disabled (set VIGIL_WEBHOOK_SECRET)'}")
    print("══════════════════════════════════════════════════════════════════════")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down Vigil REST API Server.")
        server.shutdown()


def main() -> None:
    parser = argparse.ArgumentParser(description="Vigil REST API & Webhook Service")
    parser.add_argument("--host", default=os.environ.get("VIGIL_API_HOST", "127.0.0.1"),
                        help="Host interface to bind (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8080, help="Port to listen on")
    args = parser.parse_args()
    run_server(host=args.host, port=args.port)


if __name__ == "__main__":
    main()
