"""Synthetic, network-free checks for value-free OIDC validation diagnostics."""

import ast
import contextlib
import importlib
import io
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


class OidcValidationTest(unittest.TestCase):
    ORIGIN = "https://synthetic.actions.githubusercontent.com"
    URL = ORIGIN + "/private/idtoken?api-version=2.0"
    TOKEN = "synthetic-credential-marker"

    @classmethod
    def setUpClass(cls):
        cls.tree = ast.parse(policy.PROOF_STEP_SCRIPT)
        helper = next(n for n in cls.tree.body if isinstance(n, ast.FunctionDef)
                      and n.name == "oidc_validation_category")
        namespace = {}
        exec(compile(ast.Module(body=[helper], type_ignores=[]), "validation", "exec"), namespace)
        cls.validate = staticmethod(namespace["oidc_validation_category"])
        helper = next(n for n in cls.tree.body if isinstance(n, ast.FunctionDef)
                      and n.name == "oidc_origin_mismatch_metadata")
        exec(compile(ast.Module(body=[helper], type_ignores=[]), "metadata", "exec"), namespace)
        cls.metadata = staticmethod(namespace["oidc_origin_mismatch_metadata"])

    def category(self, url=None, token=None, origin=None):
        return self.validate(self.URL if url is None else url,
                             self.TOKEN if token is None else token,
                             self.ORIGIN if origin is None else origin, 65536)

    def test_valid_request_and_credential_boundary(self):
        self.assertIsNone(self.category())
        self.assertIsNone(self.category(token="x" * 65536))
        self.assertIsNone(self.category(url=self.ORIGIN + "/idtoken?api-version=v%202"))

    def test_configured_origin_approved_shape(self):
        for origin in (self.ORIGIN + "/", self.ORIGIN + "?private=marker",
                       self.ORIGIN + "#marker", self.ORIGIN + ":443",
                       "http://synthetic.actions.githubusercontent.com",
                       "https://user@synthetic.actions.githubusercontent.com",
                       "https://synthetic.example"):
            with self.subTest(origin=origin):
                self.assertEqual(self.category(origin=origin), "oidc.validation.configured_origin")

    def test_valid_origin_with_bad_request_scheme(self):
        self.assertEqual(self.category(url=self.URL.replace("https:", "http:")),
                         "oidc.validation.scheme")

    def test_request_netloc_exact_match(self):
        self.assertEqual(self.category(origin="https://rotated.actions.githubusercontent.com"),
                         "oidc.validation.netloc")
        for netloc in ("rotated.actions.githubusercontent.com",
                       "synthetic.actions.githubusercontent.com:443",
                       "private-user-marker@synthetic.actions.githubusercontent.com"):
            with self.subTest(netloc=netloc):
                self.assertEqual(self.category(url="https://" + netloc + "/idtoken?api-version=2.0"),
                                 "oidc.validation.netloc")

    def test_path_fragment_and_whitespace(self):
        for url in (self.ORIGIN + "/wrong?api-version=2.0", self.URL + "#marker",
                    self.URL + " ", "\t" + self.URL, self.URL.replace("private", "pri\nvate")):
            with self.subTest(url=url):
                self.assertEqual(self.category(url=url), "oidc.validation.path")

    def test_query_is_exactly_one_nonempty_api_version(self):
        for query in ("", "api-version=", "audience=marker", "api-version=2&audience=marker",
                      "api-version=2&api-version=3", "api-version", "api-version=2&broken"):
            with self.subTest(query=query):
                self.assertEqual(self.category(url=self.ORIGIN + "/idtoken?" + query),
                                 "oidc.validation.query")

    def test_malformed_url_and_origin_are_shape(self):
        for value in ("https://[marker", object()):
            self.assertEqual(self.category(url=value), "oidc.validation.shape")
            self.assertEqual(self.category(origin=value), "oidc.validation.shape")

    def test_nonstring_urls_and_missing_credential_fail_closed(self):
        for value in (None, b"https://synthetic.actions.githubusercontent.com", {}, 42):
            self.assertEqual(self.validate(value, self.TOKEN, self.ORIGIN, 65536),
                             "oidc.validation.shape")
            self.assertEqual(self.validate(self.URL, self.TOKEN, value, 65536),
                             "oidc.validation.shape")
        self.assertEqual(self.validate(self.URL, None, self.ORIGIN, 65536),
                         "oidc.validation.credential")

    def test_credential_rules(self):
        for token in ("", "x" * 65537, "secret marker", "secret\nmarker", 42):
            self.assertEqual(self.category(token=token), "oidc.validation.credential")

    def test_validation_order(self):
        self.assertEqual(self.category(url=self.URL + "#marker", token="", origin=self.ORIGIN + "/"),
                         "oidc.validation.configured_origin")
        self.assertEqual(self.category(url="http://rotated.actions.githubusercontent.com/wrong", token=""),
                         "oidc.validation.scheme")
        self.assertEqual(self.category(url="https://rotated.actions.githubusercontent.com/wrong", token=""),
                         "oidc.validation.netloc")
        self.assertEqual(self.category(url=self.URL + "#marker", token=""), "oidc.validation.path")
        self.assertEqual(self.category(url=self.URL + "&audience=marker", token=""),
                         "oidc.validation.query")

    def test_workflow_and_policy_script_match_exactly(self):
        workflow = policy.parse_yaml_subset((REPO / ".github/workflows/lane3-exposure-rehearsal.yml").read_text())
        self.assertEqual(workflow["jobs"]["rehearse"]["steps"][1]["run"], policy.PROOF_STEP_SCRIPT)

    def execute_source_step(self, url):
        class SourceError(RuntimeError):
            reason = "oidc.request"
        read = mock.Mock(side_effect=SourceError("private-response-marker"))
        construct = mock.Mock(return_value=types.SimpleNamespace(read=read))
        modules = {
            "lane3_topology_source": types.SimpleNamespace(
                wireguard_github_openbao_source=construct, TopologySourceUnavailable=SourceError),
            "lane3_topology": types.SimpleNamespace(),
            "lane3_github_oidc": types.SimpleNamespace(MAX_RESPONSE=65536),
        }
        block = next(n for n in self.tree.body if isinstance(n, ast.Try)
                     and any(isinstance(x, ast.Assign) and any(isinstance(t, ast.Name) and t.id == "source_module"
                                                               for t in x.targets) for x in n.body))
        out = io.StringIO()
        def refuse(stage):
            print("::error::Lane 3 OIDC-to-KV read proof refused at " + stage)
            raise SystemExit(1)
        namespace = {"os": os, "importlib": importlib, "json": json, "refuse": refuse,
                     "oidc_origin_mismatch_metadata": self.metadata,
                     "EXPECTED_VERSION": 1, "oidc_validation_category": self.validate,
                     "config": dict.fromkeys(("oidc_broker_origin", "endpoint_address", "source_address",
                                              "interface", "expected_local_public_key", "expected_peer_public_key"), "marker")}
        namespace["config"]["oidc_broker_origin"] = self.ORIGIN
        with mock.patch.dict(os.environ, {"ACTIONS_ID_TOKEN_REQUEST_URL": url,
                                         "ACTIONS_ID_TOKEN_REQUEST_TOKEN": self.TOKEN}, clear=True), \
             mock.patch("importlib.import_module", side_effect=modules.__getitem__), \
             contextlib.redirect_stdout(out), self.assertRaises(SystemExit):
            exec(compile(ast.Module(body=[block], type_ignores=[]), "source-step", "exec"), namespace)
        return out.getvalue(), construct, read

    def test_invalid_request_stops_before_constructor_without_reflection(self):
        output, construct, read = self.execute_source_step(self.URL + "&audience=private-query-marker")
        self.assertEqual(output, "::error::Lane 3 OIDC-to-KV read proof refused at oidc.validation.query\n")
        construct.assert_not_called()
        read.assert_not_called()

    def test_origin_mismatch_diagnostics_do_not_reflect_request_values(self):
        for url, category in (
            (self.URL.replace("https:", "http:"), "scheme"),
            ("https://rotated.actions.githubusercontent.com/private/idtoken?api-version=private-query-marker", "netloc"),
            ("https://synthetic.actions.githubusercontent.com:443/private/idtoken?api-version=private-query-marker", "netloc"),
            ("https://private-user-marker@synthetic.actions.githubusercontent.com/private/idtoken?api-version=private-query-marker", "netloc"),
        ):
            with self.subTest(category=category):
                output, construct, read = self.execute_source_step(url)
                lines = output.splitlines()
                if category == "netloc":
                    self.assertEqual(len(lines), 2)
                    self.assertEqual(json.loads(lines[0]), {
                        "lane3_oidc_origin_mismatch": "OBSERVED",
                        **self.metadata(url, self.ORIGIN),
                    })
                else:
                    self.assertEqual(len(lines), 1)
                self.assertEqual(lines[-1], "::error::Lane 3 OIDC-to-KV read proof refused at oidc.validation." + category)
                self.assertNotIn("private-query-marker", output)
                self.assertNotIn("private-user-marker", output)
                self.assertNotIn(self.TOKEN, output)
                construct.assert_not_called()
                read.assert_not_called()

    def test_metadata_fixed_schema_and_port_flags(self):
        for authority, host, explicit, is_443, userinfo in (
            ("synthetic.actions.githubusercontent.com", "synthetic", False, False, False),
            ("rotated.actions.githubusercontent.com", "rotated", False, False, False),
            ("synthetic.actions.githubusercontent.com:443", "synthetic", True, True, False),
            ("synthetic.actions.githubusercontent.com:8443", "synthetic", True, False, False),
            ("private-user-marker:private-password-marker@synthetic.actions.githubusercontent.com:443",
             "synthetic", True, True, True),
        ):
            with self.subTest(authority=authority):
                url = "https://" + authority + "/private-path-marker/idtoken?private-query-marker#private-fragment-marker"
                result = self.metadata(url, self.ORIGIN)
                self.assertEqual(result, {
                    "observed_origin": "https://" + host + ".actions.githubusercontent.com",
                    "hostname_matches_configured": host == "synthetic",
                    "explicit_port_present": explicit,
                    "port_is_443": is_443,
                    "userinfo_present": userinfo,
                })
                self.assertNotIn("private-", json.dumps(result))

    def test_metadata_rejects_forbidden_hosts_and_malformed_inputs(self):
        unavailable = {
            "observed_origin": None,
            "hostname_matches_configured": False,
            "explicit_port_present": False,
            "port_is_443": False,
            "userinfo_present": False,
        }
        forbidden_hosts = (
            "private-host-marker.example", "actions.githubusercontent.com",
            "synthetic.actions.githubusercontent.com.evil.example",
            "synthetic.actions.githubusercontent.com.", "private_marker.actions.githubusercontent.com",
            ".actions.githubusercontent.com", "synthetic..actions.githubusercontent.com",
            "x" * 64 + ".actions.githubusercontent.com",
            ".".join(["x" * 63] * 4) + ".actions.githubusercontent.com",
            "synthetic%2eactions.githubusercontent.com", "syntheticé.actions.githubusercontent.com",
            "-synthetic.actions.githubusercontent.com", "synthetic-.actions.githubusercontent.com",
        )
        malformed = (
            None, object(), b"private-bytes-marker", 42,
            "https://[private-parse-marker", "http://synthetic.actions.githubusercontent.com",
            self.ORIGIN + ":private-port-marker/idtoken", self.ORIGIN + ":65536/idtoken",
            self.ORIGIN + ":/idtoken", self.ORIGIN + ":-1/idtoken",
            "https://synthetic.actions.githubuserconten\nt.com/idtoken",
            " " + self.URL, "https:///private-missing-host-marker",
        )
        for value in (*malformed, *("https://" + h + "/idtoken" for h in forbidden_hosts)):
            with self.subTest(value=value):
                self.assertEqual(self.metadata(value, self.ORIGIN), unavailable)
                self.assertEqual(self.metadata(self.URL, value), unavailable)

    def test_unavailable_netloc_metadata_still_refuses_before_constructor(self):
        for url in ("https://private-host-marker.example/private-path-marker/idtoken?private-query-marker",
                    self.ORIGIN + ":private-port-marker/idtoken?private-query-marker"):
            with self.subTest(url=url):
                output, construct, read = self.execute_source_step(url)
                lines = output.splitlines()
                self.assertEqual(len(lines), 2)
                self.assertEqual(json.loads(lines[0]), {
                    "lane3_oidc_origin_mismatch": "UNAVAILABLE",
                    "observed_origin": None,
                    "hostname_matches_configured": False,
                    "explicit_port_present": False,
                    "port_is_443": False,
                    "userinfo_present": False,
                })
                self.assertEqual(lines[1], "::error::Lane 3 OIDC-to-KV read proof refused at oidc.validation.netloc")
                self.assertNotIn("private-", output)
                construct.assert_not_called()
                read.assert_not_called()

    def test_valid_preflight_retains_fixed_read_failure(self):
        output, construct, read = self.execute_source_step(self.URL)
        self.assertEqual(output, "::error::Lane 3 OIDC-to-KV read proof refused at read.oidc.request\n")
        construct.assert_called_once()
        read.assert_called_once()
        self.assertEqual(construct.call_args.kwargs["jwt_request_url"], self.URL)
        self.assertEqual(construct.call_args.kwargs["jwt_request_token"], self.TOKEN)


if __name__ == "__main__":
    unittest.main()
