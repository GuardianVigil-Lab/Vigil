"""REST API: authentication, input validation, workspace confinement and
webhook signatures. Standard library only; the scan worker is stubbed."""

from __future__ import annotations

import hashlib
import hmac
import http.client
import json
import os
import sys
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from http.server import ThreadingHTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "engine" / "api"))
import server  # noqa: E402

TOKEN = "test-token-123"
SECRET = "webhook-secret-456"


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory()
        cls.root = Path(cls.tmp.name) / "root"
        (cls.root / "repo").mkdir(parents=True)
        cls.outside = Path(cls.tmp.name) / "outside"
        cls.outside.mkdir()
        (cls.root / "escape").symlink_to(cls.outside)
        os.environ["VIGIL_WORKSPACE_ROOT"] = str(cls.root)

        cls.started = []
        cls.block = threading.Event()

        def fake_worker(scan_id, battery, workspace, target_url):
            cls.started.append((battery, workspace, target_url))
            cls.block.wait(5)
            with server.SCANS_LOCK:
                if scan_id in server.SCANS:
                    server.SCANS[scan_id]["status"] = "completed"

        server._real_worker = server.execute_scan_worker
        server.execute_scan_worker = fake_worker
        cls.httpd = ThreadingHTTPServer(("127.0.0.1", 0), server.VigilAPIHandler)
        cls.base = f"http://127.0.0.1:{cls.httpd.server_address[1]}"
        threading.Thread(target=cls.httpd.serve_forever, daemon=True).start()

    @classmethod
    def tearDownClass(cls):
        cls.block.set()
        cls.httpd.shutdown()
        cls.tmp.cleanup()
        os.environ.pop("VIGIL_WORKSPACE_ROOT", None)

    def setUp(self):
        server.configure(token=TOKEN, webhook_secret=SECRET, max_running=2)
        self.block.set()
        with server.SCANS_LOCK:
            server.SCANS.clear()
        self.started.clear()

    def request(self, method, path, body=None, headers=None, raw=None):
        data = raw if raw is not None else (json.dumps(body).encode() if body is not None else None)
        req = urllib.request.Request(self.base + path, data=data, method=method, headers=headers or {})
        try:
            with urllib.request.urlopen(req, timeout=5) as r:
                return r.status, dict(r.headers), r.read()
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read()

    def scan(self, body, token=TOKEN, content_type="application/json"):
        headers = {"Content-Type": content_type}
        if token:
            headers["Authorization"] = f"Bearer {token}"
        return self.request("POST", "/api/v1/scan", body, headers)

    # --- authentication -----------------------------------------------------

    def test_health_is_open(self):
        status, _, _ = self.request("GET", "/api/v1/health")
        self.assertEqual(status, 200)

    def test_scan_requires_token(self):
        self.assertEqual(self.scan({"battery": "fast"}, token=None)[0], 401)
        self.assertEqual(self.scan({"battery": "fast"}, token="wrong")[0], 401)
        self.assertEqual(self.started, [])

    def test_scan_results_require_token(self):
        status, _, body = self.scan({"battery": "fast", "workspace": "repo"})
        self.assertEqual(status, 202)
        scan_id = json.loads(body)["scan_id"]
        for suffix in ("", "/sarif", "/report"):
            self.assertEqual(self.request("GET", f"/api/v1/scans/{scan_id}{suffix}")[0], 401)
        status, _, _ = self.request("GET", f"/api/v1/scans/{scan_id}",
                                    headers={"Authorization": f"Bearer {TOKEN}"})
        self.assertEqual(status, 200)

    def test_no_cors_headers(self):
        _, headers, _ = self.request("GET", "/api/v1/health")
        self.assertNotIn("Access-Control-Allow-Origin", headers)

    def test_simple_form_post_is_refused(self):
        # A browser can send text/plain cross-origin without a preflight.
        self.assertEqual(self.scan({"battery": "fast"}, content_type="text/plain")[0], 415)
        self.assertEqual(self.started, [])

    # --- input validation ---------------------------------------------------

    def test_unknown_battery(self):
        self.assertEqual(self.scan({"battery": "fast; rm -rf /"})[0], 400)

    def test_workspace_traversal(self):
        self.assertEqual(self.scan({"battery": "fast", "workspace": "../outside"})[0], 403)

    def test_workspace_absolute_outside_root(self):
        self.assertEqual(self.scan({"battery": "fast", "workspace": str(self.outside)})[0], 403)

    def test_workspace_symlink_escape(self):
        self.assertEqual(self.scan({"battery": "fast", "workspace": "escape"})[0], 403)

    def test_workspace_missing_is_not_created(self):
        self.assertEqual(self.scan({"battery": "fast", "workspace": "nope"})[0], 400)
        self.assertFalse((self.root / "nope").exists())

    def test_target_url_scheme(self):
        self.assertEqual(self.scan({"battery": "vapt", "workspace": "repo", "target_url": "file:///etc/passwd"})[0], 400)

    def test_body_too_large(self):
        # Declared length only: the server must refuse before reading a byte.
        conn = http.client.HTTPConnection(self.base.split("//")[1], timeout=5)
        conn.putrequest("POST", "/api/v1/scan")
        conn.putheader("Content-Type", "application/json")
        conn.putheader("Authorization", f"Bearer {TOKEN}")
        conn.putheader("Content-Length", str(server.MAX_BODY_BYTES + 1))
        conn.endheaders()
        self.assertEqual(conn.getresponse().status, 413)
        conn.close()

    def test_valid_scan_runs_inside_root(self):
        status, _, _ = self.scan({"battery": "fast", "workspace": "repo"})
        self.assertEqual(status, 202)
        self.assertEqual(self.started[0][1], str((self.root / "repo").resolve()))

    def test_concurrency_limit(self):
        self.block.clear()
        try:
            self.assertEqual(self.scan({"battery": "fast", "workspace": "repo"})[0], 202)
            self.assertEqual(self.scan({"battery": "fast", "workspace": "repo"})[0], 202)
            self.assertEqual(self.scan({"battery": "fast", "workspace": "repo"})[0], 429)
        finally:
            self.block.set()

    # --- webhooks -----------------------------------------------------------

    def webhook(self, body: bytes, headers):
        return self.request("POST", "/api/v1/webhook", raw=body, headers=headers)

    def test_webhook_disabled_without_secret(self):
        server.configure(token=TOKEN, webhook_secret="")
        self.assertEqual(self.webhook(b"{}", {"X-GitHub-Event": "push"})[0], 503)

    def test_webhook_unsigned(self):
        self.assertEqual(self.webhook(b"{}", {"X-GitHub-Event": "push"})[0], 401)
        self.assertEqual(self.started, [])

    def test_webhook_bad_signature(self):
        self.assertEqual(self.webhook(b"{}", {"X-GitHub-Event": "push", "X-Hub-Signature-256": "sha256=" + "0" * 64})[0], 401)

    def test_webhook_signature_over_other_body(self):
        sig = "sha256=" + hmac.new(SECRET.encode(), b"{}", hashlib.sha256).hexdigest()
        self.assertEqual(self.webhook(b'{"x":1}', {"X-GitHub-Event": "push", "X-Hub-Signature-256": sig})[0], 401)

    def test_webhook_github_signed(self):
        body = json.dumps({"repository": {"name": "demo"}}).encode()
        sig = "sha256=" + hmac.new(SECRET.encode(), body, hashlib.sha256).hexdigest()
        self.assertEqual(self.webhook(body, {"X-GitHub-Event": "push", "X-Hub-Signature-256": sig})[0], 202)
        self.assertEqual(len(self.started), 1)

    def test_webhook_github_ping(self):
        sig = "sha256=" + hmac.new(SECRET.encode(), b"{}", hashlib.sha256).hexdigest()
        self.assertEqual(self.webhook(b"{}", {"X-GitHub-Event": "ping", "X-Hub-Signature-256": sig})[0], 200)
        self.assertEqual(self.started, [])

    def test_webhook_gitlab_token(self):
        self.assertEqual(self.webhook(b"{}", {"X-Gitlab-Event": "Push Hook", "X-Gitlab-Token": "nope"})[0], 401)
        self.assertEqual(self.webhook(b"{}", {"X-Gitlab-Event": "Push Hook", "X-Gitlab-Token": SECRET})[0], 202)


class WorkerTest(unittest.TestCase):
    """An unreadable or missing report is "not counted", never zero findings."""

    def run_worker(self, sarif_text):
        real = server.__dict__.get("_real_worker") or server.execute_scan_worker
        with tempfile.TemporaryDirectory() as tmp:
            ws = Path(tmp)
            (ws / "reports").mkdir()
            if sarif_text is not None:
                (ws / "reports" / "vigil.sarif").write_text(sarif_text)
            with server.SCANS_LOCK:
                server.SCANS["w"] = {"scan_id": "w", "status": "queued"}
            orig_run = server.subprocess.run
            server.subprocess.run = lambda *a, **k: type("P", (), {"returncode": 0, "stdout": "", "stderr": ""})()
            try:
                real("w", "fast", str(ws), None)
            finally:
                server.subprocess.run = orig_run
            with server.SCANS_LOCK:
                return dict(server.SCANS.pop("w"))

    def test_missing_report_is_not_zero(self):
        scan = self.run_worker(None)
        self.assertIsNone(scan["blockers"])
        self.assertIn("no SARIF", scan["findings_error"])

    def test_corrupt_report_is_not_zero(self):
        scan = self.run_worker("{not json")
        self.assertIsNone(scan["findings_summary"])
        self.assertIn("could not be read", scan["findings_error"])

    def test_report_is_counted(self):
        sarif = {"runs": [{"results": [{"properties": {"severity": "P0"}}, {"properties": {"severity": "P2"}}]}]}
        scan = self.run_worker(json.dumps(sarif))
        self.assertEqual(scan["blockers"], 1)
        self.assertEqual(scan["advisories"], 1)
        self.assertIsNone(scan["findings_error"])


class StartupTest(unittest.TestCase):
    def test_loopback_detection(self):
        for host in ("127.0.0.1", "::1", "localhost"):
            self.assertTrue(server.is_loopback(host), host)
        for host in ("0.0.0.0", "10.0.0.5", "example.com"):
            self.assertFalse(server.is_loopback(host), host)

    def test_token_generated_when_unset(self):
        os.environ.pop("VIGIL_API_TOKEN", None)
        self.assertTrue(server.configure(webhook_secret=""))
        self.assertGreaterEqual(len(server.API_TOKEN), 32)

    def test_public_bind_without_token_refused(self):
        os.environ.pop("VIGIL_API_TOKEN", None)
        with self.assertRaises(SystemExit) as cm:
            server.run_server(host="0.0.0.0", port=0)
        self.assertEqual(cm.exception.code, 2)


if __name__ == "__main__":
    unittest.main()
