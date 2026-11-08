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
_TOP_LEVEL_PERMISSIONS = (
    (2, "contents", "read"),
    (2, "pull-requests", "write"),
    (2, "issues", "write"),
    (2, "id-token", "write"),
    (2, "actions", "read"),
)

# The accepted document shape is deliberately narrow; it is not a YAML parser.
# Outside block scalars, every non-blank, non-comment line must be one plain
# mapping key, optionally as a block-sequence item, with a single-line value.
# Anything else (quoted/explicit/tagged keys, anchors, aliases, flow mappings,
# multi-line quoted values, document markers, tabs, CR, non-ASCII) is rejected,
# so a key the policy cannot see cannot reach GitHub's parser unnoticed.
_KEY_LINE = re.compile(r"(?P<indent> *)(?P<dash>- +)?(?P<key>[A-Za-z_][A-Za-z0-9_-]*):(?: +(?P<value>.*))?")
_BLOCK_SCALAR = re.compile(r"[|>][-+]?(?: +#.*)?")
_PLAIN_VALUE = re.compile(r"""[^\s\-?:,\[\]{}#&*!|>'"%@`].*|-[^\s].*""")
_QUOTED_VALUE = re.compile(r"""(?:"(?:[^"\\]|\\.)*"|'(?:[^']|'')*')(?: +#.*)?""")
_FLOW_SEQUENCE = re.compile(r"\[[A-Za-z0-9_, -]*\](?: +#.*)?")
_SUPPORTED_CHARACTERS = re.compile(r"[\x20-\x7e\n]*")


def _structure(text: str) -> tuple[list[tuple[int, int, str, str, str]], list[str]]:
    """Return (line, indent, key, value, raw) for every structural key, plus unsupported lines."""
    entries: list[tuple[int, int, str, str, str]] = []
    unsupported: list[str] = []
    if not _SUPPORTED_CHARACTERS.fullmatch(text):
        unsupported.append("tab, carriage return or non-ASCII character")
    block_floor: int | None = None
    block_indent: int | None = None
    for number, raw in enumerate(text.split("\n"), 1):
        indent = len(raw) - len(raw.lstrip(" "))
        if block_floor is not None:
            if not raw.strip():
                continue
            if block_indent is None and indent > block_floor:
                block_indent = indent
            if block_indent is not None and indent >= block_indent:
                continue
            block_floor = block_indent = None
        if not raw.strip() or raw[indent:].startswith("#"):
            continue
        match = _KEY_LINE.fullmatch(raw)
        if match is None:
            unsupported.append(f"line {number}: {raw.strip()[:60]}")
            continue
        value = match["value"] or ""
        if _BLOCK_SCALAR.fullmatch(value):
            block_floor = indent + len(match["dash"] or "")
        elif value and not value.startswith("#") and not (
                _PLAIN_VALUE.fullmatch(value) or _QUOTED_VALUE.fullmatch(value)
                or _FLOW_SEQUENCE.fullmatch(value)):
            unsupported.append(f"line {number}: unsupported value form {value[:40]}")
        entries.append((number, len(match["indent"]) + len(match["dash"] or ""), match["key"], value, raw))
    return entries, unsupported


def _permission_violations(entries: list[tuple[int, int, str, str, str]]) -> list[str]:
    positions = [i for i, entry in enumerate(entries) if entry[2].lower() == "permissions"]
    if len(positions) != 1 or entries[positions[0]][1:4] != (0, "permissions", ""):
        return ["permissions must be exactly the top-level block, with no job or other override"]
    block = []
    for entry in entries[positions[0] + 1:]:
        if entry[1] == 0:
            break
        block.append(entry[1:4])
    if tuple(block) != _TOP_LEVEL_PERMISSIONS:
        return ["top-level permissions block differs from the accepted entries"]
    return []


def policy_violations(text: str) -> list[str]:
    """Return every violation of the reviewer workflow's security policy."""
    violations: list[str] = []
    entries, unsupported = _structure(text)
    violations.extend(f"unsupported workflow shape: {item}" for item in unsupported)
    violations.extend(_permission_violations(entries))
    uses_lines = [raw for _, _, key, _, raw in entries if key.lower() == "uses"]
    references = [match.group(1) for match in map(_USES_LINE.fullmatch, uses_lines) if match]
    if len(references) != len(uses_lines) or len(references) != len(_USES_KEY.findall(text)):
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

    def _variant(self, old: str, new: str) -> str:
        self.assertEqual(self.source.count(old), 1, f"anchor is not unique: {old!r}")
        mutated = self.source.replace(old, new, 1)
        self.assertNotEqual(mutated, self.source, "mutation did not apply")
        return mutated

    def test_independent_review_counterexamples_are_rejected(self):
        for name, (old, new) in _REVIEW_COUNTEREXAMPLES.items():
            with self.subTest(name):
                self.assertTrue(self._check_fixture(self._variant(old, new)))

    def test_quoted_or_unsupported_uses_keys_are_rejected(self):
        for name, (old, new) in _UNSUPPORTED_USES_KEYS.items():
            with self.subTest(name):
                self.assertTrue(self._check_fixture(self._variant(old, new)))

    def test_permission_overrides_and_widening_are_rejected(self):
        for name, (old, new) in _PERMISSION_OVERRIDES.items():
            with self.subTest(name):
                self.assertTrue(self._check_fixture(self._variant(old, new)))
        second_job = self.source + (
            "\n  extra:\n    permissions: write-all\n    runs-on: ubuntu-latest\n"
            "    steps:\n      - run: echo extra\n")
        self.assertTrue(self._check_fixture(second_job))

    def test_unsupported_document_shapes_fail_closed(self):
        for name, (old, new) in _UNSUPPORTED_SHAPES.items():
            with self.subTest(name):
                self.assertTrue(self._check_fixture(self._variant(old, new)))

    def test_supported_shape_variants_are_accepted(self):
        for name, (old, new) in _ACCEPTED_VARIANTS.items():
            with self.subTest(name):
                self.assertEqual(self._check_fixture(self._variant(old, new)), [])


_RESOLVE = "      - name: Resolve PR number\n"
_RUNS_ON = "    runs-on: ubuntu-latest\n"
_CHECKOUT_PREFIX = "      - uses: actions/checkout@"

# Byte-for-byte the independent review's two valid-YAML counterexamples (actionlint 1.7.8 exit 0).
_REVIEW_COUNTEREXAMPLES = {
    "quoted-uses-key": (_RESOLVE, '      - "uses": actions/setup-node@v4\n' + _RESOLVE),
    "job-permission-override": (_RUNS_ON, "    permissions: write-all\n" + _RUNS_ON),
}
_UNSUPPORTED_USES_KEYS = {
    "single-quoted": (_RESOLVE, "      - 'uses': actions/setup-node@v4\n" + _RESOLVE),
    "quoted-with-pinned-ref": (
        _RESOLVE, '      - "uses": actions/setup-node@' + "0123456789abcdef" * 2 + "01234567\n" + _RESOLVE),
    "quoted-existing-key": (_CHECKOUT_PREFIX, '      - "uses": actions/checkout@'),
    "escaped-quoted": (_RESOLVE, '      - "u\\x73es": actions/setup-node@v4\n' + _RESOLVE),
    "space-before-colon": (_RESOLVE, "      - uses : actions/setup-node@v4\n" + _RESOLVE),
    "explicit-key": (_RESOLVE, "      - ? uses\n        : actions/setup-node@v4\n" + _RESOLVE),
    "capitalized": (_RESOLVE, "      - Uses: actions/setup-node@v4\n" + _RESOLVE),
}
_PERMISSION_OVERRIDES = {
    "job-mapping": (_RUNS_ON, "    permissions:\n      contents: write\n" + _RUNS_ON),
    "job-read-all": (_RUNS_ON, "    permissions: read-all\n" + _RUNS_ON),
    "quoted-job-key": (_RUNS_ON, '    "permissions": write-all\n' + _RUNS_ON),
    "capitalized-job-key": (_RUNS_ON, "    Permissions: write-all\n" + _RUNS_ON),
    "top-level-entry-after-blank": ("  actions: read\n\n", "  actions: read\n\n  checks: write\n\n"),
    "top-level-entry-replaced": ("  issues: write\n", "  checks: write\n"),
}
_UNSUPPORTED_SHAPES = {
    "tab-indent": (_RESOLVE, "\t- uses: actions/setup-node@v4\n" + _RESOLVE),
    # read_text() maps CR/CRLF to "\n" as YAML does; NEL is a YAML 1.1 break Python does not split on.
    "next-line-break": (_RESOLVE, "      - name: Note\x85      uses: actions/setup-node@v4\n" + _RESOLVE),
    "under-indented-block-line": (
        "       github.event.pull_request.head.repo.full_name == github.repository)\n",
        "       github.event.pull_request.head.repo.full_name == github.repository)\n"
        '     "uses": actions/setup-node@v4\n'),
    "anchor": ("    runs-on: ubuntu-latest\n", "    runs-on: &runner ubuntu-latest\n"),
    "flow-mapping-value": ("          fetch-depth: 0\n", "          fetch-depth: {uses: actions/setup-node@v4}\n"),
    "unterminated-quote": ("          fetch-depth: 0\n", '          fetch-depth: "0\n'),
    "document-marker": ("name: Claude reviewer\n", "---\nname: Claude reviewer\n"),
    "non-ascii": ("name: Claude reviewer\n", "name: Claude reviewer \n"),
}
_ACCEPTED_VARIANTS = {
    "quoted-value": ("          fetch-depth: 0\n", '          fetch-depth: "0"\n'),
    "extra-run-step": (_RESOLVE, "      - name: Note\n        run: echo note\n" + _RESOLVE),
    "block-text-mentions-keys": (
        "            ## Output format\n",
        '            "uses": actions/setup-node@v4\n            permissions: write-all\n\n'
        "            ## Output format\n"),
}


if __name__ == "__main__":
    unittest.main()
