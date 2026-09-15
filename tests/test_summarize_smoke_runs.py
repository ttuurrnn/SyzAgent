import tempfile
import unittest
from pathlib import Path

from scripts.summarize_smoke_runs import classify_crash, summarize_run


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class SummarizeSmokeRunsTest(unittest.TestCase):
    def test_classify_memcg_oom_as_infra_despite_ubsan_title(self):
        with tempfile.TemporaryDirectory() as tmp:
            crash_dir = Path(tmp) / "crash"
            _write(crash_dir / "description", "UBSAN: invalid-load in corrupted\n")
            _write(
                crash_dir / "report0",
                "Memory cgroup out of memory: Killed process 1234 (syz-executor.1)\n"
                "UBSAN: invalid-load in mm/memcontrol.c:1932:27\n",
            )

            crash = classify_crash(crash_dir)

        self.assertEqual(crash["bucket"], "infra")

    def test_classify_kasan_without_infra_as_candidate(self):
        with tempfile.TemporaryDirectory() as tmp:
            crash_dir = Path(tmp) / "crash"
            _write(crash_dir / "description", "BUG: KASAN: slab-out-of-bounds in target_func\n")
            _write(crash_dir / "report0", "Call Trace:\n target_func+0x10/0x20\n")

            crash = classify_crash(crash_dir)

        self.assertEqual(crash["bucket"], "candidate")

    def test_summarize_run_parses_last_status_and_counts(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "afalg_smoke_20260624"
            _write(
                run_dir / "logs" / "manager.log",
                "2026/06/24 10:00:00 VMs 1, executed 10, cover 2, signal 1/2, crashes 0, repro 0, dist 2010/4010\n"
                "2026/06/24 10:00:10 VMs 2, executed 200, cover 20, signal 10/20, crashes 1, repro 0, dist 2010/4010\n",
            )
            crash_dir = run_dir / "workdir" / "crashes" / "abc"
            _write(crash_dir / "description", "WARNING: kernel/signal.c:LINE at do_notify_parent, CPU: syz-executor\n")
            _write(crash_dir / "report0", "WARNING: kernel/signal.c:2174 at do_notify_parent+0x1/0x2\n")

            summary = summarize_run(run_dir)

        self.assertEqual(summary["status"]["vms"], 2)
        self.assertEqual(summary["status"]["executed"], 200)
        self.assertEqual(summary["crash_counts"]["total"], 1)
        self.assertEqual(summary["crash_counts"]["infra"], 1)
        self.assertEqual(summary["crash_counts"]["candidate"], 0)

    def test_summarize_run_treats_shutdown_after_status_as_stopped(self):
        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "afalg_smoke_20260624"
            _write(
                run_dir / "logs" / "manager.log",
                "2026/06/24 10:00:10 VMs 2, executed 200, cover 20, signal 10/20, crashes 0, repro 0, dist 2010/4010\n"
                "SIGINT: shutting down...\n",
            )

            summary = summarize_run(run_dir)

        self.assertFalse(summary["running"])
        self.assertTrue(summary["status"]["shutting_down"])


if __name__ == "__main__":
    unittest.main()
