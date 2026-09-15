import json
import os
import subprocess
import tempfile
import unittest
from datetime import date
from pathlib import Path

from scripts.build_recent_cve_targets import (
    extract_published_date,
    iter_recent_records,
    render_output,
    select_diverse_entries,
    subtract_calendar_months,
)


def _write_cve_json(root: Path, year: str, cve_id: str, payload: dict):
    out = root / "cve" / "published" / year / f"{cve_id}.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(payload), encoding="utf-8")
    return out


def _git(args, cwd: Path, extra_env: dict | None = None):
    env = os.environ.copy()
    env.update(
        {
            "GIT_AUTHOR_NAME": "Test User",
            "GIT_AUTHOR_EMAIL": "test@example.com",
            "GIT_COMMITTER_NAME": "Test User",
            "GIT_COMMITTER_EMAIL": "test@example.com",
        }
    )
    if extra_env:
        env.update(extra_env)
    subprocess.run(["git", *args], cwd=cwd, check=True, env=env, capture_output=True)


class BuildRecentCVETargetsTest(unittest.TestCase):
    def test_iter_recent_records_filters_window_and_maps_prebuilt(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_cve_json(
                root,
                "2026",
                "CVE-2026-23231",
                {
                    "cveMetadata": {
                        "cveID": "CVE-2026-23231",
                        "datePublished": "2026-03-04T00:00:00Z",
                    },
                    "containers": {
                        "cna": {
                            "title": "netfilter: nf_tables: fix use-after-free in nf_tables_addchain()",
                            "descriptions": [
                                {"lang": "en", "value": "A use-after-free in nf_tables_addchain() allows corruption."}
                            ],
                            "affected": [
                                {"programFiles": ["net/netfilter/nf_tables_api.c"]}
                            ],
                            "references": [
                                {"url": "https://git.kernel.org/stable/c/0123456789abcdef0123"}
                            ],
                        }
                    },
                },
            )
            _write_cve_json(
                root,
                "2025",
                "CVE-2025-99999",
                {
                    "cveMetadata": {
                        "cveID": "CVE-2025-99999",
                        "datePublished": "2025-01-01T00:00:00Z",
                    },
                    "containers": {
                        "cna": {
                            "title": "old issue",
                            "descriptions": [{"lang": "en", "value": "Out of window"}],
                            "affected": [{"programFiles": ["net/core/skbuff.c"]}],
                        }
                    },
                },
            )

            entries = list(
                iter_recent_records(
                    root,
                    date(2025, 11, 7),
                    date(2026, 5, 7),
                )
            )

        self.assertEqual(len(entries), 1)
        entry = entries[0]
        self.assertEqual(entry.cve, "CVE-2026-23231")
        self.assertEqual(entry.prebuilt_idx, 7)
        self.assertEqual(entry.callfile_template, "sendmsg$nl_netfilter")
        self.assertEqual(entry.fix_commit, "0123456789abcdef0123")
        self.assertEqual(entry.checkout_commit, "0123456789abcdef0123~1")
        self.assertEqual(entry.function, "nf_tables_addchain")
        self.assertIn("UAF", entry.kinds)

    def test_render_output_preserves_shortlist_and_selected(self):
        entries = []
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_cve_json(
                root,
                "2026",
                "CVE-2026-31700",
                {
                    "cveMetadata": {
                        "cveID": "CVE-2026-31700",
                        "datePublished": "2026-05-01T00:00:00Z",
                    },
                    "containers": {
                        "cna": {
                            "title": "net/packet: fix TOCTOU race in tpacket_snd()",
                            "descriptions": [{"lang": "en", "value": "TOCTOU race in tpacket_snd()."}],
                            "affected": [{"programFiles": ["net/packet/af_packet.c"]}],
                        }
                    },
                },
            )
            entries = list(iter_recent_records(root, date(2025, 11, 7), date(2026, 5, 7)))

        payload = render_output(entries, date(2025, 11, 7), date(2026, 5, 7), selected_count=1)
        self.assertEqual(payload["_shortlist_count"], 1)
        self.assertEqual(len(payload["selected"]), 1)
        self.assertEqual(payload["selected"][0]["cve"], "CVE-2026-31700")

    def test_extract_published_date_falls_back_to_git_history(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            json_path = _write_cve_json(
                root,
                "2026",
                "CVE-2026-40000",
                {
                    "cveMetadata": {
                        "cveID": "CVE-2026-40000",
                    },
                    "containers": {
                        "cna": {
                            "title": "net: fix null pointer dereference in demo_fn()",
                            "descriptions": [{"lang": "en", "value": "Null pointer dereference."}],
                            "affected": [{"programFiles": ["net/core/demo.c"]}],
                        }
                    },
                },
            )

            _git(["init"], cwd=root)
            _git(["add", "."], cwd=root)
            _git(
                ["commit", "-m", "add cve"],
                cwd=root,
                extra_env={
                    "GIT_AUTHOR_DATE": "2026-02-15T12:00:00Z",
                    "GIT_COMMITTER_DATE": "2026-02-15T12:00:00Z",
                },
            )

            payload = json.loads(json_path.read_text(encoding="utf-8"))
            published = extract_published_date(root, json_path, payload)

        self.assertEqual(published, date(2026, 2, 15))

    def test_subtract_calendar_months_keeps_exact_six_month_window(self):
        self.assertEqual(subtract_calendar_months(date(2026, 5, 7), 6), date(2025, 11, 7))
        self.assertEqual(subtract_calendar_months(date(2026, 3, 31), 1), date(2026, 2, 28))

    def test_select_diverse_entries_caps_file_and_prebuilt_bias(self):
        entries = [
            type("Entry", (), {
                "cve": "CVE-1",
                "file_path": "net/a.c",
                "prebuilt_idx": 7,
            })(),
            type("Entry", (), {
                "cve": "CVE-2",
                "file_path": "net/a.c",
                "prebuilt_idx": 7,
            })(),
            type("Entry", (), {
                "cve": "CVE-3",
                "file_path": "net/b.c",
                "prebuilt_idx": 7,
            })(),
            type("Entry", (), {
                "cve": "CVE-4",
                "file_path": "net/c.c",
                "prebuilt_idx": 3,
            })(),
        ]

        chosen = select_diverse_entries(entries, shortlist_count=3, max_per_file=1, max_per_prebuilt=1)

        self.assertEqual([entry.cve for entry in chosen], ["CVE-1", "CVE-4", "CVE-2"])

    def test_iter_recent_records_prefers_last_fix_reference(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            _write_cve_json(
                root,
                "2026",
                "CVE-2026-50000",
                {
                    "cveMetadata": {
                        "cveID": "CVE-2026-50000",
                        "datePublished": "2026-04-01T00:00:00Z",
                    },
                    "containers": {
                        "cna": {
                            "title": "net: fix use-after-free in demo()",
                            "descriptions": [{"lang": "en", "value": "Use-after-free in demo()."}],
                            "affected": [{"programFiles": ["net/core/skbuff.c"]}],
                            "references": [
                                {"url": "https://git.kernel.org/stable/c/11111111111111111111"},
                                {"url": "https://git.kernel.org/stable/c/22222222222222222222"},
                            ],
                        }
                    },
                },
            )

            entries = list(iter_recent_records(root, date(2025, 11, 7), date(2026, 5, 7)))

        self.assertEqual(entries[0].fix_commit, "22222222222222222222")
        self.assertEqual(entries[0].checkout_commit, "22222222222222222222~1")


if __name__ == "__main__":
    unittest.main()
