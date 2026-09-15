import json
import tempfile
import unittest
from pathlib import Path

from scripts.prepare_gemini_rerun import (
    build_launch_command,
    prepare_one,
    sanitize_entries,
    write_plan_artifacts,
)


class PrepareGeminiRerunTest(unittest.TestCase):
    def test_sanitize_entries_drops_generic_exact_calls_when_variants_exist(self):
        entries = [
            {
                "Target": "sendmsg$NFT_BATCH",
                "Relate": ["sendmsg$nl_netfilter", "write", "bind", "socket"],
            }
        ]
        sanitized = sanitize_entries(entries)
        self.assertEqual(
            sanitized,
            [{"Target": "sendmsg$NFT_BATCH", "Relate": ["sendmsg$nl_netfilter"]}],
        )

    def test_prepare_one_rewrites_callfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            runtime_root = Path(tmp)
            path = runtime_root / "cve_2026_23231" / "fuzzinps" / "case_0" / "inp_0.json"
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(
                json.dumps(
                    [{"Target": "sendmsg$NFT_BATCH", "Relate": ["sendmsg$nl_netfilter", "write"]}]
                ),
                encoding="utf-8",
            )
            _, changed, _ = prepare_one(runtime_root, "CVE-2026-23231", dry_run=False)
            rewritten = json.loads(path.read_text(encoding="utf-8"))

        self.assertTrue(changed)
        self.assertEqual(rewritten[0]["Relate"], ["sendmsg$nl_netfilter"])

    def test_build_launch_command_sets_gemini_env(self):
        class Args:
            gemini_model = "gemini-2.5-pro"
            from_stage = "fuzz"
            hours = 1
            jobs = 8
            agent_rounds = 10

        cmd, env = build_launch_command("CVE-2026-23277", Args())
        self.assertEqual(env["SYZDIRECT_LLM_BACKEND"], "gemini")
        self.assertEqual(env["FROM_STAGE"], "fuzz")
        self.assertEqual(cmd[-4:], ["CVE-2026-23277", "1", "8", "10"])

    def test_write_plan_artifacts_outputs_manifest_and_callfile(self):
        with tempfile.TemporaryDirectory() as tmp:
            plan_dir = Path(tmp) / "plans"
            source_callfile = Path(tmp) / "inp_0.json"
            source_callfile.write_text("[]", encoding="utf-8")
            out_dir = write_plan_artifacts(
                plan_dir,
                "CVE-2026-23231",
                source_callfile,
                [{"Target": "sendmsg$NFT_BATCH", "Relate": ["sendmsg$nl_netfilter"]}],
                ["launch.sh", "CVE-2026-23231", "1", "8", "10"],
                {"SYZDIRECT_LLM_BACKEND": "gemini", "FROM_STAGE": "fuzz"},
            )

            manifest = json.loads((out_dir / "manifest.json").read_text(encoding="utf-8"))
            rerun_script = (out_dir / "rerun.sh").read_text(encoding="utf-8")
            callfile = json.loads((out_dir / "inp_0.sanitized.json").read_text(encoding="utf-8"))

        self.assertEqual(manifest["cve"], "CVE-2026-23231")
        self.assertIn("SYZDIRECT_LLM_BACKEND=gemini", rerun_script)
        self.assertEqual(callfile[0]["Target"], "sendmsg$NFT_BATCH")


if __name__ == "__main__":
    unittest.main()
