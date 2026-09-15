import json
import tempfile
import unittest
from pathlib import Path

from scripts.lookup_curated_cve import choose_best_match, load_matches


class LookupCuratedCVETest(unittest.TestCase):
    def test_load_matches_finds_selected_and_shortlist(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "recent.json"
            path.write_text(
                json.dumps(
                    {
                        "selected": [{"cve": "CVE-2026-23231", "fix_commit": "abc"}],
                        "shortlist": [{"cve": "CVE-2026-31504", "fix_commit": "def"}],
                    }
                ),
                encoding="utf-8",
            )

            selected = load_matches(path, "CVE-2026-23231")
            shortlist = load_matches(path, "CVE-2026-31504")

        self.assertEqual(selected[0]["fix_commit"], "abc")
        self.assertEqual(shortlist[0]["fix_commit"], "def")

    def test_choose_best_match_prefers_complete_entry(self):
        match = choose_best_match(
            [
                {"cve": "CVE-2026-23231", "fix_commit": "", "function": "fn", "file": "a.c"},
                {"cve": "CVE-2026-23231", "fix_commit": "abc", "function": "fn", "file": "a.c"},
            ]
        )
        self.assertEqual(match["fix_commit"], "abc")


if __name__ == "__main__":
    unittest.main()
