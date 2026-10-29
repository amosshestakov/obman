import unittest
from obman import calculate_network_score


class ScoreTests(unittest.TestCase):
    def test_all_pass(self):
        results = [
            {"kind": "dns", "ok": True},
            {"kind": "https", "ok": True},
        ]
        self.assertEqual(calculate_network_score(results)[0], 100)

    def test_half_pass(self):
        results = [
            {"kind": "dns", "ok": True},
            {"kind": "https", "ok": False},
        ]
        self.assertEqual(calculate_network_score(results)[0], 50)

    def test_no_relevant_checks(self):
        self.assertEqual(calculate_network_score([{"kind": "other", "ok": True}])[0], 0)


if __name__ == "__main__":
    unittest.main()
