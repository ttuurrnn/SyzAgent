import json
import tempfile
import unittest
from pathlib import Path

from scripts.summarize_cve_runs import load_relevant_call_names, summarize_case


def _write(path: Path, text: str):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


class SummarizeCVERunsTest(unittest.TestCase):
    def test_relevant_call_names_skip_generic_bases_for_variants(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "cve_2026_23231"
            _write(
                case_dir / "fuzzinps" / "case_0" / "inp_0.json",
                json.dumps([{"Target": "sendmsg$NFT_BATCH", "Relate": ["sendmsg$nl_netfilter", "write", "bind", "socket"]}]),
            )
            names = load_relevant_call_names(case_dir)

        self.assertIn("sendmsg$nft_batch", names)
        self.assertIn("sendmsg$nl_netfilter", names)
        self.assertNotIn("sendmsg", names)
        self.assertNotIn("write", names)
        self.assertNotIn("bind", names)
        self.assertNotIn("socket", names)

    def test_summarize_case_detects_distance_stall(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "cve_2026_23231"
            _write(
                case_dir / "fuzzinps" / "case_0" / "inp_0.json",
                json.dumps([{"Target": "sendmsg$nl_netfilter", "Relate": ["socket$nl_netfilter", "bind"]}]),
            )
            _write(
                case_dir / "fuzzres" / "case_0" / "xidx_0" / "agent_round_1" / "logs_x0" / "metrics.jsonl",
                "\n".join(
                    [
                        json.dumps({"timestamp": 1, "exec_total": 10, "corpus_cover": 5, "crashes": 0, "dist_min": 120}),
                        json.dumps({"timestamp": 20, "exec_total": 2000, "corpus_cover": 40, "crashes": 0, "dist_min": 120}),
                    ]
                ),
            )
            _write(
                case_dir / "fuzzres" / "case_0" / "xidx_0" / "agent_round_1" / "logs_x0" / "manager.log",
                "DIST_STALL_TIMEOUT: dist_min stuck at 120 for 600s (limit=600s)\n",
            )
            _write(
                case_dir / "fuzzres" / "case_0" / "xidx_0" / "agent_round_1" / "crash_summary.json",
                json.dumps({"counts": {"total": 0, "target_related": 0, "incidental_unknown": 0}}),
            )

            summary = summarize_case(case_dir)

        self.assertEqual(summary["classification"], "distance_stall")
        self.assertEqual(summary["best_distance"], 120)
        self.assertEqual(summary["round_count"], 1)
        self.assertEqual(summary["xidx"]["xidx_0"]["classification"], "distance_stall")

    def test_summarize_case_detects_target_crash(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "cve_2026_31700"
            _write(
                case_dir / "fuzzinps" / "case_0" / "inp_0.json",
                json.dumps([{"Target": "sendto$packet", "Relate": ["socket$packet", "bind$packet"]}]),
            )
            _write(
                case_dir / "fuzzres" / "case_0" / "xidx_1" / "agent_round_1" / "logs_x0" / "metrics.jsonl",
                "\n".join(
                    [
                        json.dumps({"timestamp": 1, "exec_total": 10, "corpus_cover": 5, "crashes": 0, "dist_min": 30}),
                        json.dumps({"timestamp": 20, "exec_total": 1000, "corpus_cover": 50, "crashes": 1, "dist_min": 12}),
                    ]
                ),
            )
            _write(case_dir / "fuzzres" / "case_0" / "xidx_1" / "agent_round_1" / "logs_x0" / "manager.log", "")
            _write(
                case_dir / "fuzzres" / "case_0" / "xidx_1" / "agent_round_1" / "crash_summary.json",
                json.dumps({"counts": {"total": 1, "target_related": 1, "incidental_unknown": 0}}),
            )

            summary = summarize_case(case_dir)

        self.assertEqual(summary["classification"], "target_hit")
        self.assertEqual(summary["target_related_crashes"], 1)
        self.assertEqual(summary["best_distance"], 12)
        self.assertEqual(summary["xidx"]["xidx_1"]["classification"], "target_hit")

    def test_summarize_case_demotes_historical_memcg_oom_target_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "zday_825f2764919f_io_register_zcrx"
            round_dir = case_dir / "fuzzres" / "case_0" / "xidx_0" / "agent_round_1"
            crash_dir = round_dir / "workdir_x0" / "crashes" / "51f907a4"
            report = crash_dir / "report0"
            _write(
                case_dir / "fuzzinps" / "case_0" / "inp_0.json",
                json.dumps([{"Target": "io_uring_register", "Relate": ["io_uring_setup"]}]),
            )
            _write(
                round_dir / "logs_x0" / "metrics.jsonl",
                "\n".join(
                    [
                        json.dumps({"timestamp": 1, "exec_total": 10, "corpus_cover": 5, "crashes": 0, "dist_min": 30}),
                        json.dumps({"timestamp": 20, "exec_total": 1000, "corpus_cover": 50, "crashes": 1, "dist_min": 12}),
                    ]
                ),
            )
            _write(round_dir / "logs_x0" / "manager.log", "")
            _write(crash_dir / "description", "UBSAN: invalid-load in corrupted\n")
            _write(
                report,
                "Memory cgroup out of memory: Killed process 126832 (syz-executor.1)\n"
                "UBSAN: invalid-load in <runtime>/mm/memcontrol.c:1932:27\n",
            )
            _write(
                round_dir / "crash_summary.json",
                json.dumps(
                    {
                        "counts": {"total": 1, "target_related": 1, "incidental_unknown": 0},
                        "crashes": [
                            {
                                "bucket": "target_related",
                                "description": "UBSAN: invalid-load in corrupted",
                                "paths": {"report": str(report)},
                            }
                        ],
                    }
                ),
            )

            summary = summarize_case(case_dir)

        self.assertEqual(summary["classification"], "incidental_crash")
        self.assertEqual(summary["target_related_crashes"], 0)
        self.assertEqual(summary["rounds"][0]["infra_crashes"], 1)

    def test_summarize_case_demotes_historical_lockdep_target_hit(self):
        with tempfile.TemporaryDirectory() as tmp:
            case_dir = Path(tmp) / "cve_2026_43084"
            round_dir = case_dir / "fuzzres" / "case_0" / "xidx_0" / "agent_round_1"
            crash_dir = round_dir / "workdir_x0" / "crashes" / "6e89ce80"
            report = crash_dir / "report0"
            _write(
                round_dir / "logs_x0" / "metrics.jsonl",
                "\n".join(
                    [
                        json.dumps({"timestamp": 1, "exec_total": 10, "corpus_cover": 5, "crashes": 0, "dist_min": 100}),
                        json.dumps({"timestamp": 20, "exec_total": 1000, "corpus_cover": 50, "crashes": 1, "dist_min": 90}),
                    ]
                ),
            )
            _write(round_dir / "logs_x0" / "manager.log", "")
            _write(crash_dir / "description", "BUG: MAX_LOCKDEP_KEYS too low!\n")
            _write(report, "BUG: MAX_LOCKDEP_KEYS too low!\nCall Trace:\n register_lock_class+0x2ab/0x2e0\n")
            _write(
                round_dir / "crash_summary.json",
                json.dumps(
                    {
                        "counts": {"total": 1, "target_related": 1, "incidental_unknown": 0},
                        "crashes": [
                            {
                                "bucket": "target_related",
                                "description": "BUG: MAX_LOCKDEP_KEYS too low!",
                                "paths": {"report": str(report)},
                            }
                        ],
                    }
                ),
            )

            summary = summarize_case(case_dir)

        self.assertEqual(summary["classification"], "incidental_crash")
        self.assertEqual(summary["target_related_crashes"], 0)
        self.assertEqual(summary["rounds"][0]["infra_crashes"], 1)


if __name__ == "__main__":
    unittest.main()
