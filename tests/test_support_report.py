import json
import sqlite3
import tempfile
import unittest
from pathlib import Path

from network_diagnostics import environment_snapshot
from obman import Store
from support_report import build_support_report, compare_runs


class SupportReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "obman.db"

    def test_old_database_migration_retains_history(self):
        with sqlite3.connect(self.path) as conn:
            conn.execute("CREATE TABLE runs (id INTEGER PRIMARY KEY, timestamp TEXT NOT NULL, score INTEGER NOT NULL, summary TEXT NOT NULL, results_json TEXT NOT NULL)")
            conn.execute("INSERT INTO runs VALUES (1,'2026-10-28T12:00:00+03:00',50,'old','[]')")
        store = Store(self.path)
        self.assertEqual(store.recent_runs()[0]["environment"], {})
        store.save_run(100, "new", [], environment_snapshot({}, {}))
        rows = Store(self.path).recent_runs()
        self.assertEqual([r["summary"] for r in rows], ["new", "old"])
        self.assertIsNone(build_support_report(rows[1], "0.4")["environment"])

    def test_report_omits_free_text_addresses_and_unknown_fields(self):
        run = {"timestamp": "2026-10-29", "score": 100,
               "summary": "secret summary", "environment": {
                   "variables_present": {"HTTPS_PROXY": True, "password": "secret"},
                   "python_proxy_configured": {"https": "https://user:secret@proxy", "http": True},
                   "secret": "credential"},
               "results": [{"name": "DNS: claude.ai", "kind": "dns", "ok": True,
                            "detail": "192.0.2.5", "secret": "credential"},
                           {"name": "HTTPS: https://claude.ai/", "kind": "https", "ok": True,
                            "status": "access_denied", "http_status": 403, "duration_ms": 12,
                            "detail": "secret"},
                           {"name": "secret-host", "kind": "https", "ok": True}]}
        report = build_support_report(run, "0.4")
        text = json.dumps(report)
        for private in ("secret", "192.0.2.5", "credential", "password"):
            self.assertNotIn(private, text)
        self.assertEqual(report["checks"][1]["http_status"], 403)
        self.assertEqual(report["environment"]["variables_present"], {"HTTPS_PROXY": True})

    def test_compare_http_outcomes_even_when_score_unchanged(self):
        before = {"results": [{"name": "HTTPS: https://claude.ai/", "kind": "https", "ok": True,
                                "status": "response_received", "http_status": 200}]}
        after = {"results": [{"name": "HTTPS: https://claude.ai/", "kind": "https", "ok": True,
                               "status": "access_denied", "http_status": 403}]}
        change, = compare_runs(after, before)
        self.assertEqual(change["before"]["http_status"], 200)
        self.assertEqual(change["after"]["http_status"], 403)

    def test_compare_ignores_dns_addresses_and_duration(self):
        before = {"results": [{"name": "DNS: claude.ai", "kind": "dns", "ok": True,
                                "detail": "192.0.2.1", "duration_ms": 10}]}
        after = {"results": [{"name": "DNS: claude.ai", "kind": "dns", "ok": True,
                               "detail": "192.0.2.2", "duration_ms": 20}]}
        self.assertEqual(compare_runs(after, before), [])

    def test_run_snapshot_is_preserved_after_restart_and_exports(self):
        store = Store(self.path)
        snapshot = environment_snapshot({"HTTPS_PROXY": "private"}, {"https": "private"})
        store.save_run(50, "run", [{"name": "DNS: claude.ai", "kind": "dns", "ok": False}], snapshot)
        run, = Store(self.path).recent_runs()
        report = build_support_report(run, "0.4")
        self.assertTrue(report["environment"]["variables_present"]["HTTPS_PROXY"])
        target = Path(self.temp.name) / "report.json"
        target.write_text(json.dumps(report, ensure_ascii=False), encoding="utf-8")
        self.assertEqual(json.loads(target.read_text(encoding="utf-8")), report)


if __name__ == "__main__":
    unittest.main()
