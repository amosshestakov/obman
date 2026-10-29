import json
import subprocess
import unittest
from unittest.mock import patch

from happ_detection import classify_evidence, detect_happ, is_loopback_proxy, read_processes, read_tunnel_candidates


class HappTests(unittest.TestCase):
    def test_loopback_proxy_parsing(self):
        for address in ("127.0.0.1:1080", "http=localhost:8080;https=127.0.0.1:8080", "[::1]:1080"):
            with self.subTest(address=address):
                self.assertTrue(is_loopback_proxy(address))
        for address in ("", "https://user:secret@localhost:8080", "remote.test:8080", "127.0.0.1:bad"):
            with self.subTest(address=address):
                self.assertFalse(is_loopback_proxy(address))

    def test_classification_is_never_a_verified_route(self):
        for running, proxy_enabled, tunnels, mode in (
            (True, True, 0, "proxy_candidate"), (True, False, 1, "tun_candidate"),
            (True, True, 1, "mixed_candidate"), (False, True, 1, "unknown"),
            (True, False, 0, "unknown"), (None, True, 1, "unknown"),
        ):
            with self.subTest(mode=mode, running=running):
                result = classify_evidence(running, {"enabled": proxy_enabled, "pac_configured": False}, tunnels)
                self.assertEqual(result["mode"], mode)
                self.assertFalse(result["route_verified"])

    def test_pac_is_not_misclassified_as_tun_only(self):
        result = classify_evidence(True, {"enabled": False, "pac_configured": True}, 1)
        self.assertEqual(result["mode"], "mixed_candidate")

    def test_partial_evidence_remains_unknown(self):
        self.assertEqual(classify_evidence(True, None, 1)["mode"], "unknown")
        self.assertEqual(classify_evidence(True, {"enabled": True}, None)["mode"], "unknown")

    @patch("happ_detection.run_command", return_value='"Happ.exe","123","Console"\n"xray.exe","124","Console"')
    def test_process_csv(self, command):
        self.assertTrue(read_processes())
        command.return_value = '"other-happ.exe","123"\n"xray.exe","124"'
        self.assertFalse(read_processes())

    @patch("happ_detection.run_command")
    def test_adapter_output_validation(self, command):
        command.return_value = "2"
        self.assertEqual(read_tunnel_candidates(), 2)
        for value in ('"private adapter name"', 'true', '-1', '{"secret":"value"}'):
            with self.subTest(value=value), self.assertRaises(ValueError):
                command.return_value = value
                read_tunnel_candidates()

    @patch("happ_detection.os.name", "nt")
    @patch("happ_detection.read_tunnel_candidates", side_effect=subprocess.TimeoutExpired("private", 8))
    @patch("happ_detection.read_proxy_settings", side_effect=PermissionError("private settings"))
    @patch("happ_detection.read_processes", return_value=True)
    def test_failed_probes_keep_partial_result_without_error_strings(self, processes, proxy, adapters):
        result = detect_happ()
        self.assertEqual(result["mode"], "unknown")
        self.assertTrue(result["happ_running"])
        self.assertNotIn("private", json.dumps(result))

    @patch("happ_detection.os.name", "posix")
    @patch("happ_detection.read_processes")
    def test_linux_does_not_guess_windows_state(self, processes):
        result = detect_happ()
        self.assertEqual(result["mode"], "unknown")
        processes.assert_not_called()


if __name__ == "__main__":
    unittest.main()
