import sys
import unittest
from pathlib import Path


RUNNER_DIR = Path(__file__).resolve().parents[1] / "source" / "syzdirect" / "Runner"
if str(RUNNER_DIR) not in sys.path:
    sys.path.insert(0, str(RUNNER_DIR))

from llm_enhance import _json_only_contract, _sanitize_syscall_entries  # pylint: disable=import-error


class LLMEnhanceContractsTest(unittest.TestCase):
    def test_json_only_contract_includes_hard_rules(self):
        contract = _json_only_contract('{"syscalls": []}', extra_rules=["Include 1-3 entries."])
        self.assertIn("Return ONLY one valid JSON object.", contract)
        self.assertIn("Do not use markdown fences.", contract)
        self.assertIn("Include 1-3 entries.", contract)

    def test_sanitize_syscall_entries_normalizes_and_dedupes(self):
        entries = [
            {
                "Target": "socket",
                "Relate": ["sendmsg", "sendmsg", "", "socket"],
            },
            {
                "Target": "socket",
                "Relate": ["sendmsg"],
            },
        ]
        sanitized = _sanitize_syscall_entries(entries, "net/netfilter/nf_tables_api.c", min_entries=1, max_entries=4)
        self.assertEqual(len(sanitized), 1)
        self.assertEqual(sanitized[0]["Target"], "socket")
        self.assertEqual(sanitized[0]["Relate"], ["sendmsg"])

    def test_sanitize_syscall_entries_drops_invalid_targets(self):
        entries = [{"Target": "", "Relate": ["socket"]}, {"Target": "definitely_not_a_syscall", "Relate": []}]
        sanitized = _sanitize_syscall_entries(entries, "net/netfilter/nf_tables_api.c", min_entries=1, max_entries=4)
        self.assertEqual(sanitized, [])


if __name__ == "__main__":
    unittest.main()
