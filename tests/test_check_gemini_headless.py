import unittest

from scripts.check_gemini_headless import AUTH_PROMPT, classify_probe


class CheckGeminiHeadlessTest(unittest.TestCase):
    def test_classify_probe_detects_interactive_auth(self):
        result = classify_probe(f"{AUTH_PROMPT} Do you want to continue? [Y/n]:", returncode=None, timed_out=False)
        self.assertEqual(result.status, "interactive_auth_required")

    def test_classify_probe_detects_success(self):
        result = classify_probe("OK", returncode=0, timed_out=False)
        self.assertEqual(result.status, "ok")

    def test_classify_probe_detects_timeout(self):
        result = classify_probe("", returncode=None, timed_out=True)
        self.assertEqual(result.status, "timeout")

    def test_classify_probe_detects_missing_cli(self):
        result = classify_probe("", returncode=127, timed_out=False)
        self.assertEqual(result.status, "missing_cli")


if __name__ == "__main__":
    unittest.main()
