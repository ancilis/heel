"""Structural security policy for the privileged Claude reviewer workflow.

The reviewer job holds write-capable pull-request/issue/OIDC permissions and
conditionally hands an OAuth secret to third-party action code, so every
action it executes must be an immutable full-length commit reference. actionlint
validates workflow structure but accepts mutable tags, so this policy runs in
ordinary CI. Each rule is also exercised against private, mutated copies of the
workflow so a regression in the checker itself cannot pass silently.
"""
from __future__ import annotations

from pathlib import Path
import re
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]
WORKFLOW = ROOT / ".github/workflows/claude-review.yml"

_USES_LINE = re.compile(r"^[ \t]*(?:-[ \t]+)?uses:[ \t]*(\S+)(?:[ \t]+#.*)?[ \t]*$", re.MULTILINE)
_USES_KEY = re.compile(r"uses\s*:")
_PINNED = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_./-]+)?@[0-9a-f]{40}")

_JOB_GUARD = (
    "    if: >\n"
    "      github.event_name == 'workflow_dispatch' ||\n"
    "      (github.event.pull_request.draft == false &&\n"
    "       github.event.pull_request.head.repo.full_name == github.repository)\n"
)
_PERMISSIONS = (
    "\npermissions:\n"
    "  contents: read\n"
    "  pull-requests: write\n"
    "  issues: write\n"
    "  id-token: write\n"
    "  actions: read\n\n"
)
_REQUIRED_FRAGMENTS = (
    _JOB_GUARD,
    _PERMISSIONS,
    "    types: [opened, ready_for_review, synchronize, reopened]\n",
    "      - name: Skip until Claude OAuth token is configured\n"
    "        if: steps.claude_auth.outputs.enabled != 'true'\n",
    "      - name: Run Claude reviewer\n"
    "        if: steps.claude_auth.outputs.enabled == 'true'\n"
    "        id: claude\n",
    "          claude_code_oauth_token: ${{ secrets.CLAUDE_CODE_OAUTH_TOKEN }}\n",
    "        if: always() && steps.claude_auth.outputs.enabled == 'true' && steps.claude.outcome == 'success'\n",
    "          STRUCTURED_OUTPUT: ${{ steps.claude.outputs.structured_output }}\n",
    "          SESSION_ID: ${{ steps.claude.outputs.session_id }}\n",
    "        if: steps.claude_auth.outputs.enabled == 'true' && (failure() || steps.claude.outcome != 'success')\n",
)
_FORBIDDEN_FRAGMENTS = ("pull_request_target", "workflow_run")


def policy_violations(text: str) -> list[str]:
    """Return every violation of the reviewer workflow's security policy."""
    violations: list[str] = []
    references = _USES_LINE.findall(text)
    if len(references) != len(_USES_KEY.findall(text)):
        violations.append("a uses: key is not in the plain block form this policy can verify")
    if not references:
        violations.append("no action references found")
    for reference in references:
        if not _PINNED.fullmatch(reference.strip("'\"")) or reference != reference.strip("'\""):
            violations.append(f"mutable or unverifiable action reference: {reference}")
    for fragment in _REQUIRED_FRAGMENTS:
        if fragment not in text:
            violations.append(f"required guard missing: {fragment.strip().splitlines()[0]}")
    for fragment in _FORBIDDEN_FRAGMENTS:
        if fragment in text:
            violations.append(f"forbidden trigger present: {fragment}")
    return violations


def _pinned_lines(text: str) -> list[str]:
    return [match.group(0) for match in _USES_LINE.finditer(text)]


class ReviewWorkflowSecurityTest(unittest.TestCase):
    def setUp(self):
        self.source = WORKFLOW.read_text(encoding="utf-8")

    def _check_fixture(self, text: str) -> list[str]:
        with tempfile.TemporaryDirectory(prefix="heel-review-workflow-") as directory:
            fixture = Path(directory) / "claude-review.yml"
            fixture.write_text(text, encoding="utf-8")
            return policy_violations(fixture.read_text(encoding="utf-8"))

    def test_checked_in_workflow_satisfies_policy(self):
        self.assertEqual(policy_violations(self.source), [])
        references = _USES_LINE.findall(self.source)
        self.assertEqual(
            sorted(reference.split("@", 1)[0] for reference in references),
            ["actions/checkout", "anthropics/claude-code-action"],
        )

    def test_mutable_or_malformed_references_are_rejected(self):
        lines = _pinned_lines(self.source)
        self.assertEqual(len(lines), 2)
        mutations = (
            "@v1", "@v6", "@v6.1.0", "@main", "@releases/v6", "@{short}", "@{short40}",
            "@{upper}", "@{long}", "@{sha} extra", "@",
        )
        for line in lines:
            prefix, sha = line.rsplit("@", 1)
            sha = sha.split()[0]
            for template in mutations:
                replacement = template.format(
                    short=sha[:7], short40=sha[:39], upper=sha.upper(), long=sha + "0", sha=sha)
                mutated = self.source.replace(line, prefix + replacement, 1)
                with self.subTest(line=line, replacement=replacement):
                    self.assertTrue(mutated != self.source, "mutation did not apply")
                    self.assertTrue(self._check_fixture(mutated))

    def test_quoted_flow_or_extra_unpinned_references_are_rejected(self):
        line = _pinned_lines(self.source)[0]
        indent, reference = line.split("uses:", 1)
        reference = reference.split()[0]
        cases = {
            "quoted": self.source.replace(line, f'{indent}uses: "{reference}"', 1),
            "flow-mapping": self.source.replace(
                "      - name: Resolve PR number\n",
                "      - {uses: actions/setup-node@v4}\n      - name: Resolve PR number\n", 1),
            "extra-step": self.source.replace(
                "      - name: Resolve PR number\n",
                "      - uses: actions/setup-node@v4\n      - name: Resolve PR number\n", 1),
            "local-action": self.source.replace(line, f"{indent}uses: ./.github/actions/review", 1),
            "docker-tag": self.source.replace(line, f"{indent}uses: docker://alpine:3", 1),
        }
        for name, mutated in cases.items():
            with self.subTest(name):
                self.assertTrue(mutated != self.source, "mutation did not apply")
                self.assertTrue(self._check_fixture(mutated))

    def test_a_pinned_reference_with_version_comment_is_accepted(self):
        line = _pinned_lines(self.source)[0]
        mutated = self.source.replace(line, line.split(" #", 1)[0] + "  # any-label", 1)
        self.assertEqual(self._check_fixture(mutated), [])
        bare = self.source.replace(line, line.split(" #", 1)[0], 1)
        self.assertEqual(self._check_fixture(bare), [])

    def test_fork_draft_manual_and_auth_guards_are_required(self):
        cases = {
            "fork-guard": ("       github.event.pull_request.head.repo.full_name == github.repository)\n",
                           "       true)\n"),
            "draft-guard": ("github.event.pull_request.draft == false", "true"),
            "manual-dispatch": ("github.event_name == 'workflow_dispatch'", "false"),
            "permission-widened": ("  contents: read\n  pull-requests", "  contents: write\n  pull-requests"),
            "auth-skip": ("        if: steps.claude_auth.outputs.enabled != 'true'\n", ""),
            "auth-run-gate": ("        if: steps.claude_auth.outputs.enabled == 'true'\n        id: claude\n",
                              "        id: claude\n"),
            "structured-output": ("steps.claude.outputs.structured_output", "steps.claude.outputs.result"),
            "target-trigger": ("  pull_request:\n", "  pull_request_target:\n"),
        }
        for name, (old, new) in cases.items():
            with self.subTest(name):
                self.assertIn(old, self.source)
                self.assertTrue(self._check_fixture(self.source.replace(old, new, 1)))


if __name__ == "__main__":
    unittest.main()
