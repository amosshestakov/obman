import sqlite3
import tempfile
import unittest
from pathlib import Path

from obman import Store, calculate_network_score


class ReportTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.path = Path(self.temp.name) / "obman.db"
        self.store = Store(self.path)

    def test_history_survives_restart_and_preserves_zero(self):
        self.store.save_coffee_report(" 2001:db8::1 ", "Регион 1", "0", "ASN 123")
        self.store.save_coffee_report("192.0.2.1", "Регион 2", "", "")
        rows = Store(self.path).recent_coffee_reports()
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0][1:4], ("192.0.2.1", "Регион 2", None))
        self.assertEqual(rows[1][1:], ("2001:db8::1", "Регион 1", 0, "ASN 123"))

    def test_invalid_inputs_do_not_create_reports(self):
        for ip, score in (("not an ip", "50"), ("192.0.2.1", "-1"),
                          ("192.0.2.1", "101"), ("192.0.2.1", "12.5")):
            with self.subTest(ip=ip, score=score), self.assertRaises(ValueError):
                self.store.save_coffee_report(ip, "", score, "")
        self.assertEqual(self.store.recent_coffee_reports(), [])

    def test_existing_diagnostics_are_preserved(self):
        self.store.event("diagnostic", "OK", "Existing event")
        results = [{"kind": "https", "ok": True}]
        score, summary = calculate_network_score(results)
        self.store.save_run(score, summary, results)
        self.store.save_coffee_report("192.0.2.1", "", "5", "")
        reopened = Store(self.path)
        self.assertEqual(reopened.recent_events()[0][3], "Existing event")
        with sqlite3.connect(self.path) as conn:
            self.assertEqual(conn.execute("SELECT score FROM runs").fetchone()[0], 100)


if __name__ == "__main__":
    unittest.main()
