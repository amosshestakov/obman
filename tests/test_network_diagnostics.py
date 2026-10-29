import io
import json
import queue
import socket
import ssl
import subprocess
import sys
import unittest
import urllib.error
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from network_diagnostics import check_https, environment_snapshot
from obman import ObmanApp, Store


class NetworkTests(unittest.TestCase):
    def test_diagnostic_failure_notifies_ui_without_exception_details(self):
        worker = SimpleNamespace(events_queue=queue.Queue(),
                                 _collect_diagnostics=MagicMock(side_effect=OSError("private detail")))
        ObmanApp._diagnostic_worker(worker)
        kind, message = worker.events_queue.get_nowait()
        self.assertEqual(kind, "error")
        self.assertNotIn("private detail", message)

    @patch("obman.check_dns", return_value={"ok": True})
    @patch("obman.check_https", return_value={"ok": True, "status": "access_denied"})
    def test_http_denial_does_not_produce_ok_event(self, https, dns):
        worker = SimpleNamespace(events_queue=queue.Queue(), store=MagicMock(spec=Store))
        ObmanApp._collect_diagnostics(worker)
        self.assertEqual(worker.store.save_run.call_args.args[0], 100)
        self.assertEqual(worker.store.event.call_args.args[1], "WARN")
        self.assertEqual(worker.events_queue.qsize(), 5)

    @patch("network_diagnostics.urllib.request.urlopen")
    def test_http_failures_are_not_account_ban_verdicts(self, open_url):
        for code, status in ((401, "authentication_required"), (403, "access_denied"),
                             (429, "rate_limited"), (503, "server_error"), (404, "http_error")):
            with self.subTest(code=code):
                body = io.BytesIO(b"not needed")
                open_url.side_effect = urllib.error.HTTPError("https://claude.ai/", code, "error", {}, body)
                result = check_https("https://claude.ai/")
                self.assertTrue(result["ok"])
                self.assertEqual(result["status"], status)
                self.assertEqual(result["http_status"], code)
                self.assertTrue(body.closed)

    @patch("network_diagnostics.urllib.request.urlopen")
    def test_success_has_no_account_access_claim(self, open_url):
        response = MagicMock()
        response.__enter__.return_value.getcode.return_value = 200
        open_url.return_value = response
        result = check_https("https://claude.ai/")
        self.assertEqual(result["status"], "response_received")
        self.assertIn("не проверен", result["detail"])
        self.assertEqual(open_url.call_args.kwargs["timeout"], 7)

    @patch("network_diagnostics.urllib.request.urlopen")
    def test_transport_failures_and_no_credential_leaks(self, open_url):
        cases = ((socket.gaierror("dns"), "dns_error"), (TimeoutError(), "timeout"),
                 (ssl.SSLCertVerificationError("certificate"), "tls_error"),
                 (OSError("https://user:secret@proxy.test"), "connection_error"))
        for reason, status in cases:
            with self.subTest(status=status):
                open_url.side_effect = urllib.error.URLError(reason)
                result = check_https("https://claude.ai/")
                self.assertFalse(result["ok"])
                self.assertEqual(result["status"], status)
                self.assertNotIn("secret", json.dumps(result))

    def test_environment_contains_presence_only(self):
        report = environment_snapshot(
            {"HTTPS_PROXY": "https://user:secret@private.test", "ANTHROPIC_API_KEY": "secret", "NO_PROXY": "private.test"},
            {"https": "https://user:secret@private.test", "no": "private.test"},
        )
        self.assertTrue(report["variables_present"]["HTTPS_PROXY"])
        self.assertFalse(report["route_verified"])
        text = json.dumps(report)
        for value in ("secret", "private.test", "ANTHROPIC_API_KEY"):
            self.assertNotIn(value, text)

    @patch("network_diagnostics.urllib.request.urlopen")
    def test_proxy_denial_is_not_origin_response(self, open_url):
        for code, status in ((403, "proxy_access_denied"), (407, "proxy_authentication_required")):
            with self.subTest(code=code):
                open_url.side_effect = urllib.error.URLError(OSError(f"Tunnel connection failed: {code} Forbidden"))
                result = check_https("https://claude.ai/")
                self.assertFalse(result["ok"])
                self.assertIsNone(result["http_status"])
                self.assertEqual(result["proxy_status"], code)
                self.assertEqual(result["status"], status)

    @patch("network_diagnostics.urllib.request.urlopen")
    def test_direct_proxy_auth_response_is_not_success(self, open_url):
        open_url.side_effect = urllib.error.HTTPError("https://claude.ai/", 407, "proxy auth", {}, io.BytesIO())
        result = check_https("https://claude.ai/")
        self.assertFalse(result["ok"])
        self.assertEqual(result["status"], "proxy_authentication_required")

    def test_cli_snapshot_without_network(self):
        script = Path(__file__).resolve().parents[1] / "network_diagnostics.py"
        result = subprocess.run([sys.executable, str(script)], capture_output=True, text=True, check=True)
        report = json.loads(result.stdout)
        self.assertEqual(report["checks"], [])
        self.assertFalse(report["environment"]["route_verified"])


if __name__ == "__main__":
    unittest.main()
