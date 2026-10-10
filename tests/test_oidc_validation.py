"""Synthetic, network-free checks for value-free OIDC validation diagnostics."""

import ast
import contextlib
import importlib
import io
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

    def category(self, url=None, token=None, origin=None):
        return self.validate(self.URL if url is None else url,
                             self.TOKEN if token is None else token,
                             self.ORIGIN if origin is None else origin, 65536)

    def test_valid_request_and_credential_boundary(self):
        self.assertIsNone(self.category())
        self.assertIsNone(self.category(token="x" * 65536))
        self.assertIsNone(self.category(url=self.ORIGIN + "/idtoken?api-version=v%202"))

    def test_origin_exact_match_and_approved_shape(self):
        for origin in ("https://rotated.actions.githubusercontent.com",
                       self.ORIGIN + "/", self.ORIGIN + "?private=marker",
                       self.ORIGIN + "#marker", self.ORIGIN + ":443",
                       "http://synthetic.actions.githubusercontent.com",
                       "https://user@synthetic.actions.githubusercontent.com",
                       "https://synthetic.example"):
            with self.subTest(origin=origin):
                self.assertEqual(self.category(origin=origin), "oidc.validation.origin")
        self.assertEqual(self.category(url=self.URL.replace("https:", "http:")),
                         "oidc.validation.origin")

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
                         "oidc.validation.origin")
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
        namespace = {"os": os, "importlib": importlib, "refuse": refuse,
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

    def test_valid_preflight_retains_fixed_read_failure(self):
        output, construct, read = self.execute_source_step(self.URL)
        self.assertEqual(output, "::error::Lane 3 OIDC-to-KV read proof refused at read.oidc.request\n")
        construct.assert_called_once()
        read.assert_called_once()
        self.assertEqual(construct.call_args.kwargs["jwt_request_url"], self.URL)
        self.assertEqual(construct.call_args.kwargs["jwt_request_token"], self.TOKEN)


if __name__ == "__main__":
    unittest.main()
