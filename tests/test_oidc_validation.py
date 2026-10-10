"""Hosted-only synthetic consumers of the exact immutable proof script.

These fixtures replace the protected installation boundary with reviewed fake
modules; they never request OIDC, use WireGuard, or read OpenBao. Starter owns
the real bootstrap/socket/transport integration fixtures.
"""
import ast
import contextlib
import io
import hashlib
import json
import os
import pathlib
import sys
import types
import unittest
from unittest import mock

REPO = pathlib.Path(__file__).resolve().parents[1]
sys.path.insert(0, str(REPO / "scripts"))
import source_policy as policy


class HandoffProofTest(unittest.TestCase):
    ORIGIN = "https://synthetic.actions.githubusercontent.com"
    URL = ORIGIN + "/private-path-marker/idtoken?api-version=2.0"
    TOKEN = "private-token-marker"

    def execute(self, *, handoff_error=None, bootstrap_error=None, mutate=None, url=None, started_error=None, transport_error=None, proof_error=None, guard_error_at=None):
        events = []
        pinned = types.SimpleNamespace(origin=self.ORIGIN)
        class SourceError(RuntimeError):
            reason = "oidc.request"
        def obtain(**kwargs):
            events.append(("handoff", kwargs))
            if handoff_error:
                raise handoff_error
            events.append(("consumed", None))
            return pinned
        def token_started():
            events.append(("token-started", None))
            if started_error:
                raise started_error
        def record_proof(outcome):
            events.append(("proof", outcome))
            if proof_error:
                raise proof_error
        guard_calls = []
        def wireguard_check(config_digest):
            guard_calls.append(config_digest)
            events.append(("wireguard-check", config_digest))
            if len(guard_calls) == guard_error_at:
                raise RuntimeError("private-root-check-marker")
        def construct(**kwargs):
            events.append(("source", kwargs))
            if kwargs.get("oidc_pinned") is not pinned or kwargs.get("require_pinned") is not True:
                raise AssertionError("required pinned source missing")
            if kwargs.get("wireguard_guard") is not wireguard_check:
                raise AssertionError("mandatory root broker callback missing")
            projection = {key: kwargs[key] for key in (
                "endpoint_address", "source_address", "interface",
                "expected_local_public_key", "expected_peer_public_key")}
            digest = hashlib.sha256(json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
            # Synthetic transport seam only. Starter tests own real adapter guard
            # boundaries; here we prove the exact launcher-provided callback works.
            kwargs["wireguard_guard"](digest)
            def read():
                kwargs["wireguard_guard"](digest)
                kwargs["wireguard_guard"](digest)
                kwargs["oidc_request_started"]()
                events.append(("http", None))
                if transport_error:
                    raise transport_error
                events.append(("kv", None))
                return types.SimpleNamespace(kv_version=1, record={})
            return types.SimpleNamespace(read=read)
        modules = {
            "lane3_handoff_client": types.SimpleNamespace(
                LocalExpectation=lambda **kw: types.SimpleNamespace(**kw),
                HandoffClient=lambda **kw: types.SimpleNamespace(obtain_from_launch=obtain,
                    token_request_started=token_started, record_proof=record_proof,
                    wireguard_check=wireguard_check)),
            "lane3_topology_source": types.SimpleNamespace(
                wireguard_github_openbao_source=construct, TopologySourceUnavailable=SourceError),
            "lane3_topology": types.SimpleNamespace(parse_topology_record=lambda r:
                types.SimpleNamespace(structure=lambda: {"hosts": 0})),
            "lane3_github_oidc": types.SimpleNamespace(MAX_RESPONSE=65536),
        }
        installation = {"admission_digest": "a" * 64, "supplier_digest": "b" * 64}
        def verified_fixture():
            events.append(("verified", None))
            if bootstrap_error:
                raise bootstrap_error
            return "c" * 32, 1234, installation, {}, modules
        config = dict.fromkeys(("endpoint_address", "source_address", "interface",
            "expected_local_public_key", "expected_peer_public_key", "oidc_broker_origin"), "synthetic")
        # Conflicting installed broker value must not override the finite-policy grant.
        config["oidc_broker_origin"] = "https://obsolete.actions.githubusercontent.com"
        tree = ast.parse(policy.PROOF_STEP_SCRIPT)
        for node in tree.body:
            if isinstance(node, ast.FunctionDef) and node.name in ("verified_supplier", "read_config"):
                name = "verified_fixture" if node.name == "verified_supplier" else "config_fixture"
                node.body = ast.parse("return " + name + "()").body
        ast.fix_missing_locations(tree)
        source = ast.unparse(tree)
        if mutate:
            old, new = mutate
            self.assertIn(old, source)
            source = source.replace(old, new, 1)
        class Metadata(dict):
            def get(self, key, default=None):
                if key == "ACTIONS_ID_TOKEN_REQUEST_TOKEN":
                    events.append(("token", None))
                return super().get(key, default)
            def __getitem__(self, key):
                if key == "ACTIONS_ID_TOKEN_REQUEST_TOKEN":
                    events.append(("token", None))
                return super().__getitem__(key)
        env = Metadata(STARTER_REVISION="8625c4defd22f223d103fc94cbb74064804fe065",
            GITHUB_REPOSITORY_ID="12", GITHUB_RUN_ID="34", GITHUB_RUN_ATTEMPT="1",
            GITHUB_WORKFLOW_SHA="d" * 40, ACTIONS_ID_TOKEN_REQUEST_URL=url or self.URL,
            ACTIONS_ID_TOKEN_REQUEST_TOKEN=self.TOKEN)
        output = io.StringIO()
        namespace = {"verified_fixture": verified_fixture, "config_fixture": lambda: config}
        with mock.patch.object(os, "environ", env), contextlib.redirect_stdout(output):
            try:
                exec(compile(source, "immutable-proof", "exec"), namespace)
                status = 0
            except SystemExit as stopped:
                status = stopped.code
        return status, output.getvalue(), events, pinned

    def test_exact_script_parity(self):
        workflow = policy.parse_yaml_subset((REPO / ".github/workflows/lane3-exposure-rehearsal.yml").read_text())
        self.assertEqual(workflow["jobs"]["rehearse"]["steps"][1], policy.PROOF_STEP)

    def test_success_consumes_before_token_and_real_source_call(self):
        status, output, events, pinned = self.execute()
        self.assertEqual(status, 0)
        names = [item[0] for item in events]
        self.assertLess(names.index("verified"), names.index("handoff"))
        self.assertLess(names.index("consumed"), names.index("token"))
        self.assertLess(names.index("consumed"), names.index("source"))
        self.assertLess(names.index("source"), names.index("wireguard-check"))
        self.assertLess(names.index("wireguard-check"), names.index("token-started"))
        self.assertLess(names.index("token-started"), names.index("http"))
        self.assertLess(names.index("kv"), names.index("proof"))
        self.assertEqual(events[names.index("proof")][1], "BOUNDED_PROOF")
        handoff = next(value for name, value in events if name == "handoff")
        expectation = handoff["expectation"]
        self.assertEqual(handoff["request_url"], self.URL)
        self.assertEqual(expectation.admission_digest, "a" * 64)
        self.assertEqual(expectation.supplier_digest, "b" * 64)
        self.assertFalse(hasattr(expectation, "job_id"))
        source = next(value for name, value in events if name == "source")
        self.assertTrue(callable(source["wireguard_guard"]))
        checks = [value for name, value in events if name == "wireguard-check"]
        self.assertEqual(len(checks), 3)
        projection = dict.fromkeys(("endpoint_address", "source_address", "interface",
            "expected_local_public_key", "expected_peer_public_key"), "synthetic")
        digest = hashlib.sha256(json.dumps(projection, sort_keys=True, separators=(",", ":")).encode()).hexdigest()
        self.assertEqual(checks, [digest] * 3)
        self.assertIs(source["oidc_pinned"], pinned)
        self.assertIs(source["require_pinned"], True)
        self.assertEqual(source["oidc_broker_origin"], self.ORIGIN)
        self.assertEqual(source["jwt_request_url"], self.URL)
        self.assertEqual(source["jwt_request_token"], self.TOKEN)
        self.assertFalse(json.loads(output)["gate0_accepted"])
        self.assertNotIn("private-", output)

    def test_timeout_denial_and_bootstrap_failure_stop_before_token_or_supplier(self):
        for field in ("handoff_error", "bootstrap_error"):
            for error in (TimeoutError("private-timeout-marker"), RuntimeError(self.URL + self.TOKEN)):
                with self.subTest(field=field, error=type(error).__name__):
                    status, output, events, _ = self.execute(**{field: error})
                    self.assertEqual(status, 1)
                    self.assertFalse({"token", "source", "kv"} & {n for n, _ in events})
                    self.assertNotIn("private-", output)
                    self.assertNotIn(self.URL, output)

    def test_full_request_validation_stops_before_constructor(self):
        for url in (self.URL + "&audience=private-query-marker", self.URL + "#private-fragment-marker"):
            status, output, events, _ = self.execute(url=url)
            self.assertEqual(status, 1)
            self.assertNotIn("source", [n for n, _ in events])
            self.assertNotIn("private-", output)

    def test_order_canary_is_sensitive_to_token_before_grant(self):
        # The normal path above proves order; this deliberate mutation violates it.
        status, output, events, _ = self.execute(mutate=(
            'request_url = os.environ[\'ACTIONS_ID_TOKEN_REQUEST_URL\']',
            'os.environ[\'ACTIONS_ID_TOKEN_REQUEST_TOKEN\']\n    request_url = os.environ[\'ACTIONS_ID_TOKEN_REQUEST_URL\']'))
        names = [n for n, _ in events]
        self.assertLess(names.index("token"), names.index("consumed"))

    def test_pin_canary_is_sensitive_to_legacy_fallback(self):
        status, output, events, _ = self.execute(mutate=("require_pinned=True", "require_pinned=False"))
        self.assertEqual(status, 1)
        self.assertNotIn("kv", [n for n, _ in events])

    def test_callback_failure_prevents_http_and_refuses_without_claiming_no_issuance(self):
        status, output, events, _ = self.execute(started_error=RuntimeError("private-callback-marker"))
        self.assertEqual(status, 1)
        self.assertNotIn("http", [n for n, _ in events])
        self.assertIn(("proof", "REFUSED"), events)
        self.assertNotIn("private-", output)
        self.assertNotIn("BOUNDED_PROOF", output)

    def test_transport_failure_records_refused_and_success_record_failure_cannot_pass(self):
        status, output, events, _ = self.execute(transport_error=RuntimeError("private-http-marker"))
        self.assertEqual(status, 1)
        self.assertIn(("proof", "REFUSED"), events)
        self.assertNotIn(("proof", "BOUNDED_PROOF"), events)
        self.assertNotIn("private-", output)
        status, output, events, _ = self.execute(proof_error=RuntimeError("private-record-marker"))
        self.assertEqual(status, 1)
        self.assertIn("proof.record", output)
        self.assertNotIn('"PASS"', output)


    def test_missing_or_replaced_root_callback_refuses_before_token_or_http(self):
        for replacement in ("None", "lambda digest: None"):
            with self.subTest(replacement=replacement):
                status, output, events, _ = self.execute(mutate=(
                    "wireguard_guard=client.wireguard_check", "wireguard_guard=" + replacement))
                self.assertEqual(status, 1)
                self.assertFalse({"token-started", "http", "kv"} & {n for n, _ in events})
                self.assertNotIn("private-", output)

    def test_fresh_root_callback_failure_refuses_at_every_synthetic_boundary(self):
        for boundary in (1, 2, 3):
            with self.subTest(boundary=boundary):
                status, output, events, _ = self.execute(guard_error_at=boundary)
                self.assertEqual(status, 1)
                self.assertEqual(sum(n == "wireguard-check" for n, _ in events), boundary)
                self.assertFalse({"token-started", "http", "kv"} & {n for n, _ in events})
                self.assertNotIn("private-", output)

    def test_exact_launcher_has_no_job_command_or_local_privilege_path(self):
        tree = ast.parse(policy.PROOF_STEP_SCRIPT)
        imported = {alias.name for node in ast.walk(tree) if isinstance(node, ast.Import) for alias in node.names}
        self.assertFalse({"subprocess", "pty"} & imported)
        forbidden = {"system", "popen", "spawnv", "execv", "execl"}
        self.assertFalse(any(isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
            and node.func.attr in forbidden for node in ast.walk(tree)))



class LocatorBoundaryTest(unittest.TestCase):
    def test_untrusted_locator_refuses_before_descriptor_open(self):
        tree = ast.parse(policy.PROOF_STEP_SCRIPT)
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "verified_supplier")
        namespace = {"os": os, "re": __import__("re"), "RUN_ROOT": pathlib.Path("/run/dotmac-lane3-handoff"),
                     "protected_directory": mock.Mock(side_effect=AssertionError("must not open"))}
        exec(compile(ast.Module(body=[function], type_ignores=[]), "locator", "exec"), namespace)
        for lease, locator in (("../bad", "/run/supplier"), ("c" * 32, "/tmp/supplier"),
                ("c" * 32, "/run/dotmac-lane3-handoff/" + "c" * 32 + "/../supplier"),
                ("c" * 32, "/run//dotmac-lane3-handoff/" + "c" * 32 + "/supplier")):
            with self.subTest(locator=locator), mock.patch.dict(os.environ,
                    DOTMAC_LANE3_LEASE_ID=lease, DOTMAC_LANE3_SUPPLIER_DIR=locator):
                with self.assertRaises(ValueError):
                    namespace["verified_supplier"]()
        namespace["protected_directory"].assert_not_called()


class BootstrapBoundaryTest(unittest.TestCase):
    class ExecutionReached(RuntimeError):
        pass

    def execute_boundary(self, case=None, weaken=False):
        import hashlib
        tree = ast.parse(policy.PROOF_STEP_SCRIPT)
        function = next(n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "verified_supplier")
        constants = {n.targets[0].id: ast.literal_eval(n.value) for n in tree.body
            if isinstance(n, ast.Assign) and isinstance(n.targets[0], ast.Name)
            and n.targets[0].id in ("MODULES", "COMMIT", "BOOTSTRAP_DIGEST")}
        # Every case starts from a coherent synthetic installation. The sentinel
        # proves all remaining checks pass; no real bootstrap or supplier runs.
        valid_bytes = b"# synthetic reviewed bootstrap fixture\n"
        constants["BOOTSTRAP_DIGEST"] = hashlib.sha256(valid_bytes).hexdigest()
        constants["MODULES"]["lane3_handoff_bootstrap.py"] = constants["BOOTSTRAP_DIGEST"]
        manifest = {"modules": dict(constants["MODULES"]), "starter_commit": constants["COMMIT"]}
        if case == "missing-bootstrap":
            manifest["modules"].pop("lane3_handoff_bootstrap.py")
        if case == "commit":
            manifest["starter_commit"] = "e" * 40
        files = {"supplier-installation.json": json.dumps(manifest).encode(),
                 "lane3_handoff_bootstrap.py": (b"private-wrong-byte-marker" if case == "hash" else valid_bytes),
                 "launch.json": b"{}"}
        lease = "c" * 32
        directory = "/run/dotmac-lane3-handoff/" + lease + "/supplier"
        info = lambda fd: types.SimpleNamespace(st_mode=(0o750 if fd == 1 else
            0o770 if case == "directory-mode" else 0o550),
            st_gid=(999 if fd == 2 and case == "group" else 1234))
        fake_os = types.SimpleNamespace(environ={"DOTMAC_LANE3_LEASE_ID": lease,
            "DOTMAC_LANE3_SUPPLIER_DIR": directory}, fstat=info, close=mock.Mock(),
            listdir=lambda fd: list(constants["MODULES"]) + ["supplier-installation.json"])
        compile_guard = mock.Mock(side_effect=self.ExecutionReached())
        namespace = {**constants, "os": fake_os, "re": __import__("re"),
            "RUN_ROOT": pathlib.Path("/run/dotmac-lane3-handoff"),
            "stat": __import__("stat"), "hashlib": hashlib,
            "protected_directory": lambda path: 2 if path.endswith("/supplier") else 1,
            "protected_file": lambda fd, name, mode, gid: files[name],
            "strict_record": json.loads, "types": types,
            "sys": types.SimpleNamespace(modules={}), "compile": compile_guard}
        if weaken:
            # Weaken only the failing predicate, leaving every other check intact.
            guard = {
                "hash": "hashlib.sha256(raw).hexdigest() != BOOTSTRAP_DIGEST",
                "missing-bootstrap": "manifest.get('modules') != MODULES",
                "commit": "manifest.get('starter_commit') != COMMIT",
                "directory-mode": "stat.S_IMODE(dinfo.st_mode) != 360",
                "group": "dinfo.st_gid != gid",
            }[case]
            source = ast.unparse(function)
            self.assertIn(guard, source)
            function = ast.parse(source.replace(guard, "False", 1)).body[0]
        exec(compile(ast.Module(body=[function], type_ignores=[]), "bootstrap-boundary", "exec"), namespace)
        return namespace["verified_supplier"], compile_guard

    def test_valid_baseline_reaches_exact_bootstrap_execution_boundary(self):
        execute, compile_guard = self.execute_boundary()
        with self.assertRaises(self.ExecutionReached):
            execute()
        compile_guard.assert_called_once()

    def test_each_boundary_refuses_and_its_own_weakening_reaches_execution(self):
        for case in ("hash", "missing-bootstrap", "commit", "directory-mode", "group"):
            with self.subTest(case=case):
                execute, compile_guard = self.execute_boundary(case)
                with self.assertRaises(ValueError):
                    execute()
                compile_guard.assert_not_called()
                execute, compile_guard = self.execute_boundary(case, weaken=True)
                with self.assertRaises(self.ExecutionReached):
                    execute()
                compile_guard.assert_called_once()


if __name__ == "__main__":
    unittest.main()
