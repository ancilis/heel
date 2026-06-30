import importlib.util
import subprocess
import unittest
from pathlib import Path


def load_runner():
    path = Path(__file__).resolve().parents[1] / "scripts/codex/local_queue_runner.py"
    spec = importlib.util.spec_from_file_location("local_queue_runner", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


class TestLocalCodexQueueRunner(unittest.TestCase):
    def test_exec_command_uses_saved_codex_auth(self):
        runner = load_runner()

        cmd = runner.build_codex_command(
            repo_root=Path("/repo"),
            mode="exec",
            sandbox="workspace-write",
            approval_policy="never",
            output_path=Path("codex-output.md"),
        )

        self.assertEqual(cmd, [
            "codex",
            "exec",
            "--cd",
            "/repo",
            "--sandbox",
            "workspace-write",
            "--output-last-message",
            "codex-output.md",
            "-",
        ])
        self.assertNotIn("OPENAI_API_KEY", cmd)
        self.assertNotIn("CODEX_API_KEY", cmd)

    def test_tui_command_opens_interactive_codex_session(self):
        runner = load_runner()

        cmd = runner.build_codex_command(
            repo_root=Path("/repo"),
            mode="tui",
            sandbox="workspace-write",
            approval_policy="on-request",
            output_path=Path("codex-output.md"),
        )

        self.assertEqual(cmd, [
            "codex",
            "--cd",
            "/repo",
            "--sandbox",
            "workspace-write",
            "--ask-for-approval",
            "on-request",
        ])

    def test_filter_open_queue_prs_requires_codex_queue_label(self):
        runner = load_runner()
        prs = [
            {
                "number": 1,
                "url": "https://example.test/1",
                "labels": [{"name": "codex-queue"}],
            },
            {
                "number": 2,
                "url": "https://example.test/2",
                "labels": [{"name": "needs-human-review"}],
            },
        ]

        self.assertEqual(runner.filter_queue_prs(prs), [prs[0]])

    def test_completed_text_includes_stderr_for_codex_login_status(self):
        runner = load_runner()
        result = subprocess.CompletedProcess(
            args=["codex", "login", "status"],
            returncode=0,
            stdout="",
            stderr="Logged in using ChatGPT\n",
        )

        self.assertEqual(runner.completed_text(result), "Logged in using ChatGPT\n")


if __name__ == "__main__":
    unittest.main()
