"""Anti-fabrication detector: self-check, project settings and the full sweep."""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

DETECTOR = Path(__file__).resolve().parent.parent / "engine" / "anti_fabrication" / "detector.py"

FABRICATED = "export const SAMPLE_FEED = [{ ip: '198.51.100.7' }];\n"


def run(cwd, *args):
    p = subprocess.run([sys.executable, str(DETECTOR), *args], cwd=cwd,
                       capture_output=True, text=True, timeout=60)
    return p.returncode, p.stdout + p.stderr


class DetectorTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.repo = Path(self.tmp.name)
        (self.repo / "src").mkdir()

    def tearDown(self):
        self.tmp.cleanup()

    def settings(self, data):
        (self.repo / ".vigil").mkdir(exist_ok=True)
        (self.repo / ".vigil" / "fabrication.json").write_text(json.dumps(data))

    def test_self_check(self):
        code, out = run(self.repo, "--self-check")
        self.assertEqual(code, 0, out)

    def test_clean_repo_full_sweep_writes_json(self):
        # Regression: --json-out crashed (json not imported), and a full sweep
        # reported exemptions belonging to another project as stale findings.
        (self.repo / "src" / "ok.ts").write_text("export const x = 1;\n")
        code, out = run(self.repo, "--json-out=out/report.json")
        self.assertEqual(code, 0, out)
        self.assertEqual(json.loads((self.repo / "out" / "report.json").read_text()), [])

    def test_finding_is_reported(self):
        (self.repo / "src" / "feed.ts").write_text(FABRICATED)
        code, out = run(self.repo, "--json-out=r.json")
        self.assertEqual(code, 1, out)
        rules = {f["rule"] for f in json.loads((self.repo / "r.json").read_text())}
        self.assertIn("demo-named-data", rules)

    def test_exemption_with_reason(self):
        (self.repo / "src" / "feed.ts").write_text(FABRICATED)
        self.settings({"exempt": [
            {"path": "src/feed.ts", "rule": "demo-named-data", "reason": "an example shown as an example"},
            {"path": "src/feed.ts", "rule": "documentation-address", "reason": "same example"},
        ]})
        code, out = run(self.repo)
        self.assertEqual(code, 0, out)

    def test_stale_exemption_fails_full_sweep(self):
        (self.repo / "src" / "ok.ts").write_text("export const x = 1;\n")
        self.settings({"exempt": [{"path": "src/gone.ts", "rule": "demo-named-data", "reason": "was here"}]})
        code, out = run(self.repo)
        self.assertEqual(code, 1, out)
        self.assertIn("stale-exemption", out)

    def test_known_debt_needs_issue(self):
        self.settings({"known_debt": [{"path": "src/a.ts", "rule": "r", "reason": "later"}]})
        code, out = run(self.repo)
        self.assertEqual(code, 2, out)

    def test_unknown_settings_key(self):
        self.settings({"exempts": []})
        code, out = run(self.repo)
        self.assertEqual(code, 2, out)
        self.assertIn("unknown key", out)

    def test_explicit_missing_config(self):
        code, _ = run(self.repo, "--config=nope.json")
        self.assertEqual(code, 2)

    def test_score_owner_is_opt_in(self):
        (self.repo / "src" / "enrich.ts").write_text("result.reputation = computed;\n")
        self.assertEqual(run(self.repo)[0], 0)
        self.settings({"score_owners": ["src/scoring.ts"]})
        code, out = run(self.repo)
        self.assertEqual(code, 1, out)
        self.assertIn("score-outside-scoring", out)

    def test_model_wrapper_pattern(self):
        prompt = ('import { generate } from "@/lib/llm";\n'
                  'generate({ prompt: `Return JSON: { "verdict": "Malicious" | "Clean" }` });\n')
        (self.repo / "src" / "triage.ts").write_text(prompt)
        self.assertEqual(run(self.repo)[0], 0)
        self.settings({"model_call_patterns": [r"@/lib/llm"]})
        code, out = run(self.repo)
        self.assertEqual(code, 1, out)
        self.assertIn("prompt-invents-finding", out)


if __name__ == "__main__":
    unittest.main()
