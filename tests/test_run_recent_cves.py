import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from scripts.run_recent_cves import build_command, load_items, select_items


class RunRecentCVEsTest(unittest.TestCase):
    def test_load_and_select_items(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "recent.json"
            path.write_text(
                json.dumps(
                    {
                        "selected": [
                            {
                                "cve": "CVE-2026-23231",
                                "function": "nf_tables_addchain",
                                "file": "net/netfilter/nf_tables_api.c",
                                "fix_commit": "auto-resolve",
                                "checkout_commit": "auto-resolve",
                                "prebuilt_idx": 7,
                            },
                            {
                                "cve": "CVE-2026-31774",
                                "function": "io_bundle_nbufs",
                                "file": "io_uring/net.c",
                                "fix_commit": "deadbeefdead",
                                "checkout_commit": "deadbeefdead~1",
                                "prebuilt_idx": None,
                            },
                        ]
                    }
                ),
                encoding="utf-8",
            )
            items = load_items(path, "selected")

        self.assertEqual(len(items), 2)
        args = SimpleNamespace(cve=["CVE-2026-23231"], only_prebuilt=True, limit=0, run_tag="", linux_template="")
        selected = select_items(items, args)
        self.assertEqual([item.cve for item in selected], ["CVE-2026-23231"])

    def test_build_command_adds_verify_patch_env(self):
        item = load_items_from_payload(
            {
                "cve": "CVE-2026-31774",
                "function": "io_bundle_nbufs",
                "file": "io_uring/net.c",
                "fix_commit": "deadbeefdead",
                "checkout_commit": "deadbeefdead~1",
                "prebuilt_idx": None,
            }
        )
        args = SimpleNamespace(
            hours=2,
            jobs=4,
            agent_rounds=6,
            from_stage="target",
            verify_patch=True,
            run_tag="gemini-smoke",
            linux_template="/tmp/linux-template",
        )

        item.run_tag = args.run_tag
        item.linux_template = args.linux_template
        cmd, env = build_command(item, args)

        self.assertEqual(cmd[-4:], ["CVE-2026-31774", "2", "4", "6"])
        self.assertEqual(env["FROM_STAGE"], "target")
        self.assertEqual(env["RUN_TAG"], "gemini-smoke")
        self.assertEqual(env["SYZDIRECT_LINUX_TEMPLATE"], "/tmp/linux-template")
        self.assertEqual(env["FUNC_OVERRIDE"], "io_bundle_nbufs")
        self.assertEqual(env["FILE_OVERRIDE"], "io_uring/net.c")
        self.assertEqual(env["COMMIT_OVERRIDE"], "deadbeefdead")
        self.assertEqual(env["VERIFY_PATCH"], "1")

    def test_build_command_adds_commit_override_without_verify_patch(self):
        item = load_items_from_payload(
            {
                "cve": "CVE-2026-23231",
                "function": "nf_tables_addchain",
                "file": "net/netfilter/nf_tables_api.c",
                "fix_commit": "2a6586ecfa4ce1413daaafee250d2590e05f1a33",
                "checkout_commit": "2a6586ecfa4ce1413daaafee250d2590e05f1a33~1",
                "prebuilt_idx": 7,
            }
        )
        args = SimpleNamespace(
            hours=1,
            jobs=8,
            agent_rounds=10,
            from_stage="",
            verify_patch=False,
            run_tag="",
            linux_template="",
        )

        cmd, env = build_command(item, args)

        self.assertEqual(cmd[-4:], ["CVE-2026-23231", "1", "8", "10"])
        self.assertEqual(env["COMMIT_OVERRIDE"], "2a6586ecfa4ce1413daaafee250d2590e05f1a33~1")
        self.assertNotIn("VERIFY_PATCH", env)


def load_items_from_payload(payload: dict):
    return load_items_from_json({"selected": [payload]})[0]


def load_items_from_json(payload: dict):
    with tempfile.TemporaryDirectory() as tmp:
        path = Path(tmp) / "recent.json"
        path.write_text(json.dumps(payload), encoding="utf-8")
        return load_items(path, "selected")


if __name__ == "__main__":
    unittest.main()
