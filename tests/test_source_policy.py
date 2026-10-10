"""Sensitivity proofs for scripts/source_policy.py (stdlib unittest only).

Every refusal rule has at least one planted violation that must turn the check
red with that rule's code, and the unmodified repository must stay green.
Planted non-documentation addresses are assembled at run time, so this file
itself never carries one and the repository's own IP scan stays meaningful.
"""

from __future__ import annotations

import ast
import contextlib
import io
import json
import os
import pathlib
import re
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))

import source_policy as policy  # noqa: E402

PRIV = ".github/workflows/lane3-exposure-rehearsal.yml"
POLICY_WF = ".github/workflows/source-policy.yml"
GOOD_SHA = "0123456789abcdef0123456789abcdef01234567"


def _dotted(*parts: int) -> str:
    return ".".join(str(p) for p in parts)


def _coloned(*parts: str) -> str:
    return ":".join(parts)


class PlantCase(unittest.TestCase):
    """Copy the repository's policy inputs into a scratch tree for each test."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.root = pathlib.Path(self._tmp.name)
        for rel in (PRIV, POLICY_WF, policy.GRAMMAR_FILE, "README.md"):
            dest = self.root / rel
            dest.parent.mkdir(parents=True, exist_ok=True)
            shutil.copyfile(REPO / rel, dest)

    def tearDown(self) -> None:
        self._tmp.cleanup()

    def write(self, rel: str, text: str) -> None:
        path = self.root / rel
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")

    def read(self, rel: str) -> str:
        return (self.root / rel).read_text(encoding="utf-8")

    def replace(self, rel: str, old: str, new: str) -> None:
        text = self.read(rel)
        self.assertIn(old, text, f"plant anchor missing in {rel}: {old!r}")
        self.write(rel, text.replace(old, new, 1))

    def assertRefused(self, code: str) -> list[str]:
        errors = policy.policy_errors(self.root)
        self.assertTrue(
            any(e.startswith(code + ":") for e in errors),
            f"expected a {code} refusal, got {errors}",
        )
        return errors

    def assertGreen(self) -> None:
        self.assertEqual(policy.policy_errors(self.root), [])


class ConformingTest(PlantCase):
    def test_unmodified_copy_is_green(self) -> None:
        self.assertGreen()

    def test_repository_itself_is_green(self) -> None:
        self.assertEqual(policy.policy_errors(REPO), [])

    def test_wrapped_job_condition_is_accepted(self) -> None:
        cond = policy.JOB_CONDITION
        self.replace(PRIV, f"if: {cond}", f"if: ${{{{ {cond} }}}}")
        self.assertGreen()

    def test_documentation_and_loopback_addresses_stay_green(self) -> None:
        self.write(
            "docs/examples.md",
            "192.0.2.10 198.51.100.7 203.0.113.250 127.0.0.1 0.0.0.0 "
            "::1 :: 2001:db8::10 version 0.4.0a2 v7.0.1\n",
        )
        self.assertGreen()


class TriggerTest(PlantCase):
    def test_push_trigger(self) -> None:
        self.replace(PRIV, "on:\n  workflow_dispatch:\n", "on:\n  push:\n  workflow_dispatch:\n")
        self.assertRefused("TRIGGER")

    def test_pull_request_target_trigger(self) -> None:
        self.replace(PRIV, "on:\n  workflow_dispatch:\n", "on:\n  pull_request_target:\n  workflow_dispatch:\n")
        self.assertRefused("TRIGGER")

    def test_workflow_call_trigger(self) -> None:
        self.replace(PRIV, "\npermissions: {}\n", "  workflow_call:\n\npermissions: {}\n")
        self.assertRefused("TRIGGER")

    def test_scalar_trigger_list(self) -> None:
        text = self.read(PRIV)
        start = text.index("on:\n")
        end = text.index("\npermissions: {}")
        self.write(PRIV, text[:start] + "on: [workflow_dispatch, schedule]\n" + text[end:])
        self.assertRefused("TRIGGER")

    def test_topology_input(self) -> None:
        self.replace(
            PRIV,
            "      grant_ref:\n",
            "      target:\n        type: string\n      grant_ref:\n",
        )
        self.assertRefused("TRIGGER")


class RunNameTest(PlantCase):
    def test_run_name_drift(self) -> None:
        self.replace(PRIV, "run-name: lane3 starter=", "run-name: lane3  starter=")
        self.assertRefused("RUN_NAME")

    def test_run_name_extra_field(self) -> None:
        self.replace(
            PRIV,
            "candidate=${{ inputs.candidate_version }}\n",
            "candidate=${{ inputs.candidate_version }} grant=${{ inputs.grant_ref }}\n",
        )
        self.assertRefused("RUN_NAME")

    def test_run_name_missing(self) -> None:
        text = self.read(PRIV)
        self.write(PRIV, re.sub(r"^run-name:.*\n", "", text, flags=re.MULTILINE))
        self.assertRefused("RUN_NAME")


class JobShapeTest(PlantCase):
    def test_group_lost(self) -> None:
        self.replace(PRIV, "    runs-on:\n      group: lane3-exposure-protected\n", "    runs-on: ubuntu-latest\n")
        self.assertRefused("JOB_SHAPE")

    def test_group_renamed(self) -> None:
        self.replace(PRIV, "group: lane3-exposure-protected", "group: gate0-issuer-protected")
        self.assertRefused("JOB_SHAPE")

    def test_group_gains_labels(self) -> None:
        self.replace(
            PRIV,
            "      group: lane3-exposure-protected\n",
            "      group: lane3-exposure-protected\n      labels: [self-hosted]\n",
        )
        self.assertRefused("JOB_SHAPE")

    def test_environment_lost(self) -> None:
        self.replace(PRIV, "    environment: lane3-rehearsal-protected\n", "")
        self.assertRefused("JOB_SHAPE")

    def test_environment_renamed(self) -> None:
        self.replace(PRIV, "environment: lane3-rehearsal-protected", "environment: lane3-rehearsal")
        self.assertRefused("JOB_SHAPE")

    def test_condition_lost(self) -> None:
        self.replace(PRIV, f"    if: {policy.JOB_CONDITION}\n", "")
        self.assertRefused("JOB_SHAPE")

    def test_condition_without_main(self) -> None:
        self.replace(PRIV, " && github.ref == 'refs/heads/main'", "")
        self.assertRefused("JOB_SHAPE")

    def test_condition_other_ref(self) -> None:
        self.replace(PRIV, "refs/heads/main'", "refs/heads/dev'")
        self.assertRefused("JOB_SHAPE")

    def test_condition_without_dispatch(self) -> None:
        self.replace(PRIV, "github.event_name == 'workflow_dispatch' && ", "")
        self.assertRefused("JOB_SHAPE")

    def test_job_permission_widened(self) -> None:
        self.replace(PRIV, "      id-token: write\n", "      id-token: write\n      actions: write\n")
        self.assertRefused("JOB_SHAPE")

    def test_job_loses_id_token(self) -> None:
        self.replace(PRIV, "      id-token: write\n", "")
        self.assertRefused("JOB_SHAPE")

    def test_top_permissions_widened(self) -> None:
        self.replace(PRIV, "permissions: {}\n", "permissions: write-all\n")
        self.assertRefused("JOB_SHAPE")

    def test_second_job(self) -> None:
        text = self.read(PRIV)
        self.write(PRIV, text + "  other:\n    runs-on: ubuntu-latest\n    steps:\n      - run: true\n")
        self.assertRefused("JOB_SHAPE")

    def test_job_gains_continue_on_error(self) -> None:
        self.replace(PRIV, "    timeout-minutes: 5\n", "    timeout-minutes: 5\n    continue-on-error: true\n")
        self.assertRefused("JOB_SHAPE")

    def test_privileged_workflow_missing(self) -> None:
        (self.root / PRIV).unlink()
        self.assertRefused("JOB_SHAPE")


class SelfHostedTest(PlantCase):
    def _plant(self, trigger: str, runs_on: str) -> None:
        self.write(
            ".github/workflows/planted.yml",
            f"name: planted\non:\n{trigger}\njobs:\n  probe:\n{runs_on}\n    steps:\n      - run: true\n",
        )

    def test_pull_request_self_hosted_list(self) -> None:
        self._plant("  pull_request:", "    runs-on: [self-hosted, dotmac-control-runner]")
        self.assertRefused("SELF_HOSTED")

    def test_pull_request_target_group(self) -> None:
        self._plant("  pull_request_target:", "    runs-on:\n      group: lane3-exposure-protected")
        self.assertRefused("SELF_HOSTED")

    def test_push_self_hosted_scalar(self) -> None:
        self._plant("  push:\n    branches: [main]", "    runs-on: self-hosted")
        self.assertRefused("SELF_HOSTED")

    def test_workflow_call_labels(self) -> None:
        self._plant("  workflow_call:", "    runs-on:\n      labels: [self-hosted]")
        self.assertRefused("SELF_HOSTED")

    def test_workflow_run_block_list(self) -> None:
        self._plant(
            "  workflow_run:\n    workflows: [x]",
            "    runs-on:\n      - self-hosted\n      - Linux",
        )
        self.assertRefused("SELF_HOSTED")

    def test_pull_request_expression_runner(self) -> None:
        self._plant("  pull_request:", "    runs-on: ${{ github.event.pull_request.title }}")
        self.assertRefused("SELF_HOSTED")

    def test_pull_request_reusable_call_without_runs_on(self) -> None:
        self.write(
            ".github/workflows/planted.yml",
            "on: pull_request\njobs:\n  call:\n    uses: ./.github/workflows/other.yml\n",
        )
        self.assertRefused("SELF_HOSTED")

    def test_existing_policy_workflow_moved_to_self_hosted(self) -> None:
        self.replace(POLICY_WF, "runs-on: ubuntu-latest", "runs-on: [self-hosted]")
        self.assertRefused("SELF_HOSTED")

    def test_privileged_workflow_gains_pull_request(self) -> None:
        self.replace(PRIV, "on:\n  workflow_dispatch:\n", "on:\n  pull_request:\n  workflow_dispatch:\n")
        self.assertRefused("SELF_HOSTED")


class GrammarTest(PlantCase):
    def test_grammar_file_drift(self) -> None:
        self.replace(policy.GRAMMAR_FILE, "{40}", "{7,40}")
        errors = self.assertRefused("GRAMMAR")
        self.assertTrue(any("differs from the regex" in e for e in errors), errors)

    def test_step_grammar_drift(self) -> None:
        self.replace(PRIV, "(?:a|b|rc)", "(?:a|b|rc|dev)")
        errors = self.assertRefused("GRAMMAR")
        self.assertTrue(any("differs from the regex" in e for e in errors), errors)

    def test_grammar_file_missing(self) -> None:
        (self.root / policy.GRAMMAR_FILE).unlink()
        self.assertRefused("GRAMMAR")

    def test_grammar_file_two_lines(self) -> None:
        self.write(policy.GRAMMAR_FILE, self.read(policy.GRAMMAR_FILE) + "extra\n")
        self.assertRefused("GRAMMAR")

    def test_grammar_check_not_first(self) -> None:
        text = self.read(PRIV)
        steps_at = text.index("    steps:\n") + len("    steps:\n")
        refusal_at = text.index("      - name: Refuse until")
        self.write(PRIV, text[:steps_at] + text[refusal_at:] + text[steps_at:refusal_at])
        self.assertRefused("GRAMMAR")

    def test_grammar_step_search_instead_of_fullmatch(self) -> None:
        self.replace(PRIV, "re.fullmatch(GRAMMAR, title)", "re.search(GRAMMAR, title)")
        self.assertRefused("GRAMMAR")

    def test_grammar_step_skipped(self) -> None:
        self.replace(PRIV, "        shell: python3 -I {0}\n", "        if: false\n        shell: python3 -I {0}\n")
        self.assertRefused("GRAMMAR")

    def test_grammar_step_continue_on_error(self) -> None:
        self.replace(
            PRIV, "        shell: python3 -I {0}\n", "        continue-on-error: true\n        shell: python3 -I {0}\n"
        )
        self.assertRefused("GRAMMAR")

    def test_grammar_step_shell_changed(self) -> None:
        self.replace(PRIV, "shell: python3 -I {0}", "shell: python {0}")
        self.assertRefused("GRAMMAR")

    def test_grammar_step_env_reads_grant(self) -> None:
        self.replace(
            PRIV,
            "          CANDIDATE_VERSION: ${{ inputs.candidate_version }}\n",
            "          CANDIDATE_VERSION: ${{ inputs.candidate_version }}\n"
            "          GRANT_REF: ${{ inputs.grant_ref }}\n",
        )
        self.assertRefused("GRAMMAR")


class RefusalOnlyTest(PlantCase):
    def test_discovery_cannot_request_a_token(self):
        self.replace(PRIV, '    sys.exit(0)  # The next step still performs the final refusal.', '    pass')
        self.assertRefused("REFUSAL_ONLY")

    def test_discovery_cannot_print_full_request_url(self):
        self.replace(PRIV, '"oidc_broker_origin": "https://" + request.hostname,', '"oidc_broker_origin": os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"],')
        self.assertRefused("REFUSAL_ONLY")

    def test_proof_config_no_follow_removed(self):
        self.replace(PRIV, " | os.O_NOFOLLOW", "")
        self.assertRefused("REFUSAL_ONLY")

    def test_proof_config_parent_ownership_removed(self):
        self.replace(PRIV, 'refuse("config.parent")', 'pass')
        self.assertRefused("REFUSAL_ONLY")

    def test_proof_step_removed(self) -> None:
        text = self.read(PRIV)
        start = text.index("      - name: Prove the B7 OIDC-to-KV read")
        end = text.index("      - name: Refuse until")
        self.write(PRIV, text[:start] + text[end:])
        self.assertRefused("REFUSAL_ONLY")

    def test_proof_step_after_refusal(self) -> None:
        text = self.read(PRIV)
        start = text.index("      - name: Prove the B7 OIDC-to-KV read")
        end = text.index("      - name: Refuse until")
        self.write(PRIV, text[:start] + text[end:] + text[start:end])
        self.assertRefused("REFUSAL_ONLY")

    def test_proof_step_module_pin_changed(self) -> None:
        self.replace(PRIV, "418c87cf6fdbb56d8d391f9efaf1c0ca7618fff1fcc43261e9266c05268e97a6", "0" * 64)
        self.assertRefused("REFUSAL_ONLY")

    def test_proof_step_commit_changed(self) -> None:
        self.replace(PRIV, 'COMMIT = "9cefdd7578bfb04e1f52203f340b5dffd3572a98"', f'COMMIT = "{GOOD_SHA}"')
        self.assertRefused("REFUSAL_ONLY")

    def test_proof_step_prints_the_record(self) -> None:
        self.replace(PRIV, "    reading = source.read()\n", "    reading = source.read()\n          print(reading.record)\n")
        self.assertRefused("REFUSAL_ONLY")

    def test_proof_step_continue_on_error(self) -> None:
        self.replace(
            PRIV,
            "      - name: Prove the B7 OIDC-to-KV read, value-free\n",
            "      - name: Prove the B7 OIDC-to-KV read, value-free\n        continue-on-error: true\n",
        )
        self.assertRefused("REFUSAL_ONLY")

    def test_checkout_added(self) -> None:
        self.replace(
            PRIV,
            "      - name: Refuse until",
            f"      - uses: actions/checkout@{GOOD_SHA}\n      - name: Refuse until",
        )
        self.assertRefused("REFUSAL_ONLY")

    def test_refusal_step_removed(self) -> None:
        text = self.read(PRIV)
        self.write(PRIV, text[: text.index("      - name: Refuse until")])
        self.assertRefused("REFUSAL_ONLY")

    def test_refusal_step_no_longer_exits(self) -> None:
        self.replace(PRIV, "          exit 1\n", "          exit 0\n")
        self.assertRefused("REFUSAL_ONLY")

    def test_input_interpolated_into_script(self) -> None:
        self.replace(PRIV, ">&2\n          exit 1\n", ">&2\n          echo ${{ inputs.grant_ref }}\n          exit 1\n")
        self.assertRefused("REFUSAL_ONLY")


class SecretsVarsTest(PlantCase):
    def _env(self, value: str) -> None:
        self.replace(
            PRIV,
            "          CANDIDATE_VERSION: ${{ inputs.candidate_version }}\n",
            f"          CANDIDATE_VERSION: ${{{{ inputs.candidate_version }}}}\n          X: {value}\n",
        )

    def test_secret_reference(self) -> None:
        self._env("${{ secrets.RUNNER_QUERY_TOKEN }}")
        self.assertRefused("SECRETS_VARS")

    def test_variable_reference(self) -> None:
        self._env("${{ vars.LANE3_PROBE_HOST }}")
        self.assertRefused("SECRETS_VARS")

    def test_indexed_secret_reference(self) -> None:
        self._env("${{ SECRETS['X'] }}")
        self.assertRefused("SECRETS_VARS")


class IpLiteralTest(PlantCase):
    def test_private_ipv4_in_readme(self) -> None:
        self.write("README.md", self.read("README.md") + f"\nprobe host {_dotted(10, 0, 0, 5)}\n")
        self.assertRefused("IP_LITERAL")

    def test_leading_zero_ipv4(self) -> None:
        self.write("notes.txt", f"addr 0{_dotted(10, 0, 0, 5)}\n")
        self.assertRefused("IP_LITERAL")

    def test_cidr_in_workflow(self) -> None:
        self.write("scripts/extra.py", f'NET = "{_dotted(172, 16, 0, 0)}/12"\n')
        self.assertRefused("IP_LITERAL")

    def test_public_ipv4(self) -> None:
        self.write("notes.txt", f"{_dotted(8, 8, 4, 4)}\n")
        self.assertRefused("IP_LITERAL")

    def test_ula_ipv6(self) -> None:
        self.write("notes.txt", "jump " + _coloned("fd12", "3456", "789a", "", "1") + "\n")
        self.assertRefused("IP_LITERAL")

    def test_ipv4_mapped_ipv6(self) -> None:
        self.write("notes.txt", _coloned("", "", "ffff", _dotted(192, 168, 1, 1)) + "\n")
        self.assertRefused("IP_LITERAL")

    def test_scan_reads_git_tracked_files(self) -> None:
        if shutil.which("git") is None:
            self.skipTest("git not available")
        self.write("tracked.txt", f"{_dotted(10, 1, 2, 3)}\n")
        env = dict(os.environ, GIT_CONFIG_GLOBAL=os.devnull, GIT_CONFIG_SYSTEM=os.devnull)
        subprocess.run(["git", "init", "-q", str(self.root)], check=True, env=env)
        subprocess.run(["git", "-C", str(self.root), "add", "-A"], check=True, env=env)
        errors = self.assertRefused("IP_LITERAL")
        self.assertTrue(any("tracked.txt" in e for e in errors), errors)


class ActionPinTest(PlantCase):
    def test_tag_pinned_action(self) -> None:
        self.replace(
            POLICY_WF,
            "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1",
            "actions/checkout@v7",
        )
        self.assertRefused("ACTION_PIN")


class YamlSubsetTest(PlantCase):
    def test_flow_mapping_refused(self) -> None:
        self.replace(
            PRIV,
            "    runs-on:\n      group: lane3-exposure-protected\n",
            "    runs-on: {group: lane3-exposure-protected}\n",
        )
        self.assertRefused("YAML")

    def test_anchor_refused(self) -> None:
        self.replace(PRIV, "permissions: {}\n", "permissions: &none {}\n")
        self.assertRefused("YAML")

    def test_tab_refused(self) -> None:
        self.replace(PRIV, "    timeout-minutes: 5\n", "\ttimeout-minutes: 5\n")
        self.assertRefused("YAML")

    def test_duplicate_key_refused(self) -> None:
        self.replace(PRIV, "    timeout-minutes: 5\n", "    timeout-minutes: 5\n    environment: other\n")
        self.assertRefused("YAML")

    def test_second_document_refused(self) -> None:
        self.write(PRIV, self.read(PRIV) + "---\non: push\n")
        self.assertRefused("YAML")

    def test_multiline_plain_scalar_refused(self) -> None:
        with self.assertRaises(policy.YamlSubsetError):
            policy.parse_yaml_subset("a: one\n  two\n")

    def test_reader_basics(self) -> None:
        doc = policy.parse_yaml_subset(
            "# c\nk: 'v' # trailing\nl: [a, \"b\"]\nm:\n  - x: 1\n    y: |\n      line\n  - plain\ne: {}\n"
        )
        self.assertEqual(doc, {"k": "v", "l": ["a", "b"], "m": [{"x": "1", "y": "line\n"}, "plain"], "e": {}})


class FirstStepBehaviourTest(unittest.TestCase):
    """Run the first step's actual script against good and bad dispatch inputs."""

    @classmethod
    def setUpClass(cls) -> None:
        workflow = policy.parse_yaml_subset((REPO / PRIV).read_text(encoding="utf-8"))
        cls.script = workflow["jobs"]["rehearse"]["steps"][0]["run"]
        cls.grammar = (REPO / policy.GRAMMAR_FILE).read_text(encoding="utf-8")[:-1]

    def run_step(self, starter: str, candidate: str) -> int:
        with tempfile.NamedTemporaryFile("w", suffix=".py", delete=False) as handle:
            handle.write(self.script)
        try:
            env = {"STARTER_REVISION": starter, "CANDIDATE_VERSION": candidate, "PATH": os.environ.get("PATH", "")}
            return subprocess.run(
                [sys.executable, "-I", handle.name], env=env, capture_output=True, check=False
            ).returncode
        finally:
            os.unlink(handle.name)

    def test_cases_agree_with_grammar(self) -> None:
        sha = "ef1c114ecd11c59b08a2be18f20efc57e70ac9f4"
        cases = [
            (sha, "0.4.0a2", 0),
            (sha, "0.4.0", 0),
            (sha, "10.20.30rc11", 0),
            (sha.upper(), "0.4.0a2", 1),
            (sha[:-1], "0.4.0a2", 1),
            (sha + "0", "0.4.0a2", 1),
            (sha, "0.4", 1),
            (sha, _dotted(0, 4, 0, 1), 1),
            (sha, "0.4.0dev1", 1),
            (sha, "0.4.0a2 ", 1),
            (sha, "0.4.0a2\n", 1),
            (sha, "٠.4.0", 1),
            (sha + " candidate=0.4.0", "0.4.0", 1),
            ("", "", 1),
        ]
        for starter, candidate, expected in cases:
            with self.subTest(starter=starter, candidate=candidate):
                self.assertEqual(self.run_step(starter, candidate), expected)
                title = f"lane3 starter={starter} candidate={candidate}"
                self.assertEqual(re.fullmatch(self.grammar, title) is None, bool(expected))




class BrokerDiscoveryBehavior(unittest.TestCase):
    def execute_discovery(self, request_url):
        with tempfile.TemporaryDirectory() as folder:
            tree = ast.parse(policy.PROOF_STEP_SCRIPT)
            for node in tree.body:
                if isinstance(node, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "CONFIG" for t in node.targets):
                    node.value = ast.parse("pathlib.Path(" + repr(str(pathlib.Path(folder) / "absent.json")) + ")", mode="eval").body
            ast.fix_missing_locations(tree)
            out = io.StringIO()
            env = {} if request_url is None else {"ACTIONS_ID_TOKEN_REQUEST_URL": request_url}
            with mock.patch.dict(os.environ, env, clear=True), contextlib.redirect_stdout(out), mock.patch("urllib.request.urlopen", side_effect=AssertionError("network forbidden")), mock.patch("tempfile.mkdtemp", side_effect=AssertionError("module work forbidden")):
                with self.assertRaises(SystemExit) as stopped:
                    exec(compile(tree, "reviewed-proof", "exec"), {})
            return stopped.exception.code, out.getvalue()

    def test_discovery_reports_only_origin_without_token_or_network(self):
        status, output = self.execute_discovery("https://example.actions.githubusercontent.com/private/idtoken?api-version=2.0")
        self.assertEqual(status, 0)
        value = json.loads(output)
        self.assertEqual(value, {"lane3_oidc_broker_discovery": "OBSERVED", "oidc_broker_origin": "https://example.actions.githubusercontent.com", "token_requested": False, "kv_read_attempted": False})
        self.assertNotIn("private", output)
        self.assertNotIn("api-version", output)

    def test_discovery_refuses_unapproved_domain(self):
        status, output = self.execute_discovery("https://evil.example/idtoken?api-version=2.0")
        self.assertEqual(status, 1)
        self.assertNotIn("OBSERVED", output)

    def test_discovery_refuses_userinfo(self):
        status, _ = self.execute_discovery("https://user@example.actions.githubusercontent.com/idtoken")
        self.assertEqual(status, 1)

    def test_discovery_requires_actions_metadata(self):
        status, _ = self.execute_discovery(None)
        self.assertEqual(status, 1)


class ReadFailureDisclosure(unittest.TestCase):
    # Exception shape from lane3_topology_source at pinned 9cefdd7578bf.
    # args contains the formatted sentence; reason owns the source category.
    class SourceError(RuntimeError):
        def __init__(self, reason):
            super().__init__(f"Lane 3 topology record unavailable: {reason}")
            self.reason = reason

    def project(self, error):
        tree = ast.parse(policy.PROOF_STEP_SCRIPT)
        handler = next(node for node in ast.walk(tree) if isinstance(node, ast.ExceptHandler)
                       and any(isinstance(n, ast.Constant) and n.value == "unclassified" for n in ast.walk(node)))
        module = ast.Module(body=handler.body, type_ignores=[])
        out = []
        source_module = type("SourceModule", (), {"TopologySourceUnavailable": self.SourceError})
        exec(compile(ast.fix_missing_locations(module), "failure-projection", "exec"),
             {"exc": error, "source_module": source_module, "refuse": out.append})
        return out

    def test_source_reason_survives_formatted_args(self):
        for label in ("transport.wireguard", "oidc.request", "transport.request", "auth.response", "deadline", "kv.metadata"):
            error = self.SourceError(label)
            self.assertNotEqual(error.args[0], label)
            self.assertEqual(self.project(error), ["read." + label])

    def test_unknown_reason_payloads_are_never_disclosed(self):
        for payload in ("private-value-example", "Bearer example", {"credential": "example"}, None):
            self.assertEqual(self.project(self.SourceError(payload)), ["read.unclassified"])

    def test_foreign_exception_and_impersonating_class_are_hidden(self):
        self.assertEqual(self.project(ValueError("oidc.request")), ["read.unclassified"])
        impostor = type("TopologySourceUnavailable", (RuntimeError,), {})
        error = impostor("oidc.request")
        error.reason = "oidc.request"
        self.assertEqual(self.project(error), ["read.unclassified"])

if __name__ == "__main__":
    unittest.main()
