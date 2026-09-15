import sys
import unittest
from pathlib import Path
from unittest import mock


RUNNER_DIR = Path(__file__).resolve().parents[1] / "source" / "syzdirect" / "Runner"
if str(RUNNER_DIR) not in sys.path:
    sys.path.insert(0, str(RUNNER_DIR))

import llm_enhance  # pylint: disable=import-error


class CodexBackendTest(unittest.TestCase):
    def test_codex_command_uses_output_file_and_stdin_prompt(self):
        with mock.patch.object(llm_enhance, "_CODEX_CMD", "codex"), \
             mock.patch.object(llm_enhance, "_CODEX_MODEL", "gpt-5.4"), \
             mock.patch.object(llm_enhance, "_CODEX_SANDBOX", "read-only"):
            args = llm_enhance._codex_command("/tmp/last_message.txt")

        self.assertEqual(
            args,
            [
                "codex",
                "exec",
                "--model",
                "gpt-5.4",
                "--sandbox",
                "read-only",
                "--skip-git-repo-check",
                "--ephemeral",
                "--color",
                "never",
                "--output-last-message",
                "/tmp/last_message.txt",
                "-",
            ],
        )

    def test_call_codex_llm_prefers_output_file(self):
        with mock.patch.object(llm_enhance, "_call_subprocess_llm", return_value="noisy stdout") as call_llm:
            def fake_exists(path):
                return path.endswith("last_message.txt")

            mocked_open = mock.mock_open(read_data="clean final answer\n")
            with mock.patch("llm_enhance.os.path.exists", side_effect=fake_exists), \
                 mock.patch("builtins.open", mocked_open):
                result = llm_enhance._call_codex_llm("prompt", 15)

        self.assertEqual(result, "clean final answer")
        call_llm.assert_called_once()


if __name__ == "__main__":
    unittest.main()
