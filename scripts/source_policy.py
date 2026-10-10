"""Source policy for the Lane 3 exposure launcher (stdlib only).

This check runs on a GitHub-hosted runner for every pull request and every
push to ``main``. It refuses, with a named reason, when the source of this
repository drifts from the refusal-only launcher contract in Starter's
``docs/LANE3_EXECUTION_TOPOLOGY.md`` (sections 2, 3, 6 and 9).

What this check is not
----------------------
It lives in the same repository as the files it checks, so one pull request
can change the workflow, this checker and its tests together. It catches
accidental drift and makes a deliberate change visible in review. It is not an
independently enforced security control, it admits no runner, and a green
result is never admission evidence. Admission is the live read-back and
negative scheduling evidence of the design's section 7.

How YAML is read, and why not by exact text
-------------------------------------------
PyYAML is not in the standard library, and nothing is vendored. Two options
remained: pin each workflow byte for byte (as ``gate0-issuer-execution`` does)
or read a strict YAML subset and check the specific keys. This file reads a
strict subset, because the rules here must hold for every workflow,
including workflows that do not exist yet ("no job selects a self-hosted
runner from a pull_request trigger"). An exact-text pin can only say "this
file changed". It cannot say whether a new workflow is safe. Exact text is
still used where it is the stronger tool: the first step's script, the
refusal step and ``run-name`` are compared exactly.

The reader (``parse_yaml_subset``) fails closed. It accepts only:

- block mappings and block sequences, indented with spaces;
- plain, single-quoted and double-quoted scalars on one line;
- flow sequences of plain or quoted scalars with no nesting (``[a, b]``);
- the empty flow mapping ``{}`` and the empty flow sequence ``[]``;
- literal and folded block scalars (``|``, ``|-``, ``>`` and so on);
- full-line comments and trailing `` #`` comments.

It raises ``YamlSubsetError``, which becomes a policy refusal, on anything
else: tabs in indentation, anchors, aliases, tags, merge keys, complex keys,
directives, more than one document, non-empty flow mappings, nested flow
collections, plain scalars that continue onto another line, and duplicate
keys. A workflow that GitHub would accept but that uses one of these
constructs is therefore refused here. That is deliberate.

Known limits of the reader: every scalar is kept as a string, with no YAML 1.1
or 1.2 type resolution. Double-quoted escapes are decoded with ``json``, which
is close to YAML but not identical. Block scalar chomping and folding are not
reproduced exactly: the checker only needs the literal text of ``run:``
scripts, and those are compared after removing their common indentation. The
reader is not a validator of GitHub's workflow schema. It reads only enough
structure to apply the rules below.

What it refuses
---------------
Each rule has a stable code that the tests assert:

- ``TRIGGER``: the privileged workflow has a trigger other than
  ``workflow_dispatch``, or inputs other than the three admitted ones.
- ``RUN_NAME``: ``run-name`` differs from the dispatch grammar's format.
- ``JOB_SHAPE``: the privileged job loses its runner group, its Environment
  or its ``main``/dispatch condition, or gains a key, job or permission the
  contract does not admit.
- ``SELF_HOSTED``: a job outside the privileged workflow selects anything but
  a GitHub-hosted label, which covers every ``pull_request*``, ``push``,
  ``workflow_call`` and ``workflow_run`` workflow. The privileged workflow
  itself is held to ``workflow_dispatch`` by ``TRIGGER``.
- ``GRAMMAR``: ``dispatch-grammar.txt`` differs from the regex the first step
  enforces, or the first step is not the exact grammar check.
- ``REFUSAL_ONLY``: the privileged job runs anything after the grammar check
  except the pinned OIDC-to-KV read proof step and then the pinned refusal
  step, uses an action, or interpolates an expression into a script.
- ``IP_LITERAL``: a tracked file contains an IP literal outside loopback,
  unspecified and documentation ranges.
- ``SECRETS_VARS``: the privileged workflow references ``secrets`` or
  ``vars``.
- ``ACTION_PIN``: an action is not pinned by a full commit SHA.
- ``YAML``: a workflow is outside the subset the reader accepts.
"""

from __future__ import annotations

import ipaddress
import json
import pathlib
import re
import subprocess
import sys
import textwrap
from typing import Any

PRIVILEGED_WORKFLOW = "lane3-exposure-rehearsal.yml"
GRAMMAR_FILE = "dispatch-grammar.txt"

RUN_NAME_FORMAT = (
    "lane3 starter=${{ inputs.starter_revision }} "
    "candidate=${{ inputs.candidate_version }}"
)
ADMITTED_INPUTS = ("starter_revision", "candidate_version", "grant_ref")
RUNNER_GROUP = "lane3-exposure-protected"
ENVIRONMENT = "lane3-rehearsal-protected"
JOB_ID = "rehearse"
JOB_CONDITION = "github.event_name == 'workflow_dispatch' && github.ref == 'refs/heads/main'"
ADMITTED_TOP_KEYS = {"name", "run-name", "on", "permissions", "jobs"}
ADMITTED_JOB_KEYS = {
    "name",
    "if",
    "runs-on",
    "environment",
    "permissions",
    "timeout-minutes",
    "steps",
}
JOB_PERMISSIONS = {"contents": "read", "id-token": "write"}

GRAMMAR_STEP_SHELL = "python3 -I {0}"
GRAMMAR_STEP_ENV = {
    "STARTER_REVISION": "${{ inputs.starter_revision }}",
    "CANDIDATE_VERSION": "${{ inputs.candidate_version }}",
}
GRAMMAR_STEP_KEYS = {"name", "shell", "env", "run"}
#: The first step's script, exactly, with ``{grammar}`` standing for the
#: contents of ``dispatch-grammar.txt``.
GRAMMAR_STEP_SCRIPT = '''\
import os
import re
import sys

GRAMMAR = r"{grammar}"

title = (
    "lane3 starter="
    + os.environ.get("STARTER_REVISION", "")
    + " candidate="
    + os.environ.get("CANDIDATE_VERSION", "")
)
if re.fullmatch(GRAMMAR, title) is None:
    print("::error::dispatch inputs do not match the Lane 3 grammar; refusing")
    sys.exit(1)
print("dispatch grammar accepted: " + title)
'''
PROOF_STEP_NAME = "Prove the B7 OIDC-to-KV read, value-free"
PROOF_STEP_SHELL = "python3 -I {0}"
#: The bounded OIDC-to-KV read proof, exactly. It downloads Starter's reader
#: modules at one pinned commit, checks each SHA-256, reads the B7 topology
#: record through the pinned WireGuard transport and prints only value-free
#: evidence. The job still ends in the refusal step.
PROOF_STEP_SCRIPT = 'import hashlib\nimport importlib\nimport json\nimport os\nimport pathlib\nimport stat\nimport sys\nimport tempfile\nimport urllib.request\n\nCOMMIT = "9cefdd7578bfb04e1f52203f340b5dffd3572a98"\nMODULES = {\n    "lane3_topology": "418c87cf6fdbb56d8d391f9efaf1c0ca7618fff1fcc43261e9266c05268e97a6",\n    "lane3_topology_source": "2cf05c02adb7a4ece3ac00a494abd2569e80641151386025b0c76dac32b76ed1",\n    "lane3_openbao_topology": "2315721bdcaa6f581b26b355c4e65bea0fdf69e5ebfa19431ca8467ea6c3151d",\n    "lane3_github_oidc": "70a0592960863d296ad4e8870030494d997527fd76f1a3a4caf1384a3ead9312",\n    "lane3_wireguard_topology": "b026fc7348c4497f1d6fa5c718dd703a4b119174f44a71fbf8164c4f465acf91",\n}\nCONFIG = pathlib.Path("/etc/dotmac-lane3/openbao-wireguard.json")\nFIELDS = {\n    "endpoint_address",\n    "source_address",\n    "interface",\n    "expected_local_public_key",\n    "expected_peer_public_key",\n    "oidc_broker_origin",\n}\nEXPECTED_VERSION = 1\n\n\ndef refuse(stage):\n    print("::error::Lane 3 OIDC-to-KV read proof refused at " + stage)\n    sys.exit(1)\n\n\ndef oidc_validation_category(request_url, request_token, approved_origin, max_response):\n    # Mirror the pinned supplier\'s checks in order; return fixed labels only.\n    from urllib.parse import parse_qsl, urlsplit\n    if not isinstance(approved_origin, str) or not isinstance(request_url, str):\n        return "oidc.validation.shape"\n    try:\n        origin = urlsplit(approved_origin)\n        request = urlsplit(request_url)\n        if (\n            origin.scheme != "https"\n            or not origin.hostname\n            or not origin.hostname.endswith(".actions.githubusercontent.com")\n            or origin.netloc != origin.hostname\n            or origin.path\n            or origin.query\n            or origin.fragment\n            or origin.username is not None\n            or request.scheme != origin.scheme\n            or request.netloc != origin.netloc\n        ):\n            return "oidc.validation.origin"\n        if (\n            not request.path.startswith("/")\n            or not request.path.endswith("/idtoken")\n            or request.fragment\n            or any(c.isspace() for c in request_url)\n        ):\n            return "oidc.validation.path"\n        try:\n            pairs = parse_qsl(\n                request.query, keep_blank_values=True, strict_parsing=True\n            )\n        except ValueError:\n            return "oidc.validation.query"\n        if len(pairs) != 1 or pairs[0][0] != "api-version" or not pairs[0][1]:\n            return "oidc.validation.query"\n        if (\n            not isinstance(request_token, str)\n            or not request_token\n            or len(request_token) > max_response\n            or any(c.isspace() for c in request_token)\n        ):\n            return "oidc.validation.credential"\n        return None\n    except Exception:\n        return "oidc.validation.shape"\n\n\ndef read_config(path):\n    # Walk from / using pinned directory descriptors; never follow symlinks.\n    directory = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)\n    try:\n        for part in path.parts[1:-1]:\n            child = os.open(part, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,\n                            dir_fd=directory)\n            os.close(directory)\n            directory = child\n            info = os.fstat(directory)\n            if info.st_uid != 0 or info.st_mode & 0o022:\n                refuse("config.parent")\n        descriptor = os.open(path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK,\n                             dir_fd=directory)\n        with os.fdopen(descriptor, "rb") as stream:\n            info = os.fstat(stream.fileno())\n            if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or info.st_mode & 0o022:\n                refuse("config.ownership")\n            raw = stream.read(65537)\n            if len(raw) > 65536:\n                refuse("config.size")\n            return json.loads(raw)\n    finally:\n        os.close(directory)\n\n\n# Approved first stage: no config means metadata observation only.\n# No HTTP request, module download, token read or private tunnel contact.\ntry:\n    CONFIG.lstat()\nexcept FileNotFoundError:\n    from urllib.parse import urlsplit\n    try:\n        request = urlsplit(os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"])\n        if (request.scheme != "https" or not request.hostname\n                or not request.hostname.endswith(".actions.githubusercontent.com")\n                or request.netloc != request.hostname or request.fragment):\n            refuse("discovery.origin")\n    except (KeyError, ValueError):\n        refuse("discovery.origin")\n    print(json.dumps({\n        "lane3_oidc_broker_discovery": "OBSERVED",\n        "oidc_broker_origin": "https://" + request.hostname,\n        "token_requested": False,\n        "kv_read_attempted": False,\n    }, sort_keys=True))\n    sys.exit(0)  # The next step still performs the final refusal.\nexcept OSError:\n    refuse("config.read")\n\ntry:\n    config = read_config(CONFIG)\nexcept (OSError, ValueError):\n    refuse("config.read")\nif not isinstance(config, dict) or set(config) != FIELDS:\n    refuse("config.fields")\n\nwork = pathlib.Path(tempfile.mkdtemp(prefix="lane3-proof-"))\nfor name, digest in MODULES.items():\n    url = "https://raw.githubusercontent.com/michaelayoade/dotmac_starter_mt/" + COMMIT + "/scripts/" + name + ".py"\n    try:\n        with urllib.request.urlopen(url, timeout=15) as response:\n            body = response.read(1048577)\n    except OSError:\n        refuse("module." + name)\n    if len(body) > 1048576 or hashlib.sha256(body).hexdigest() != digest:\n        refuse("module." + name)\n    (work / (name + ".py")).write_bytes(body)\nsys.path.insert(0, str(work))\n\ntry:\n    source_module = importlib.import_module("lane3_topology_source")\n    topology_module = importlib.import_module("lane3_topology")\n    oidc_module = importlib.import_module("lane3_github_oidc")\n    validation = oidc_validation_category(\n        os.environ.get("ACTIONS_ID_TOKEN_REQUEST_URL", ""),\n        os.environ.get("ACTIONS_ID_TOKEN_REQUEST_TOKEN", ""),\n        config["oidc_broker_origin"],\n        oidc_module.MAX_RESPONSE,\n    )\n    if validation is not None:\n        refuse(validation)\n    source = source_module.wireguard_github_openbao_source(\n        expected_version=EXPECTED_VERSION,\n        jwt_request_url=os.environ["ACTIONS_ID_TOKEN_REQUEST_URL"],\n        jwt_request_token=os.environ["ACTIONS_ID_TOKEN_REQUEST_TOKEN"],\n        oidc_broker_origin=config["oidc_broker_origin"],\n        endpoint_address=config["endpoint_address"],\n        source_address=config["source_address"],\n        interface=config["interface"],\n        expected_local_public_key=config["expected_local_public_key"],\n        expected_peer_public_key=config["expected_peer_public_key"],\n    )\n    reading = source.read()\n    topology = topology_module.parse_topology_record(reading.record)\nexcept Exception as exc:\n    # Fixed source-defined categories only; never print exception values.\n    category = "unclassified"\n    allowed = {\n        "transport.wireguard", "oidc.request", "transport.request",\n        "expected_version", "source.consumed", "deadline",\n        "jwt.supplier", "auth.response", "auth.expired",\n        "kv.response", "kv.metadata", "kv.record", "kv.schema",\n        "reader.operation", "response.duplicate_field",\n        "transport.endpoint", "transport.configuration", "transport.operation",\n        "transport.deadline", "transport.status", "transport.response_size",\n        "transport.response_shape",\n    }\n    if type(exc) is source_module.TopologySourceUnavailable:\n        for label in allowed:\n            if exc.reason == label:\n                category = label\n                break\n    refuse("read." + category)\nif reading.kv_version != EXPECTED_VERSION:\n    refuse("version")\nprint(json.dumps({\n    "lane3_oidc_kv_read": "PASS",\n    "kv_version": reading.kv_version,\n    "structure": topology.structure(),\n    "starter_commit": COMMIT,\n}, sort_keys=True))\n'
PROOF_STEP = {"name": PROOF_STEP_NAME, "shell": PROOF_STEP_SHELL, "run": PROOF_STEP_SCRIPT}
REFUSAL_STEP = {
    "name": "Refuse until Lane 3 execution is admitted",
    "shell": "bash",
    "run": (
        'echo "refusal-only launcher: no Gate-3 grant verification, private '
        'delivery or Lane 3 execution exists yet" >&2\n'
        "exit 1\n"
    ),
}

RISKY_TRIGGERS = {"push", "workflow_call", "workflow_run"}
GITHUB_HOSTED = re.compile(r"(ubuntu|windows|macos)-[0-9a-z.-]+")
FULL_SHA_ACTION = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_./-]+@[0-9a-f]{40}")
GRAMMAR_LINE = re.compile(r'^GRAMMAR = r"(?P<grammar>[^"\n]*)"$', re.MULTILINE)
SECRETS_OR_VARS = re.compile(r"\b(secrets|vars)\b", re.IGNORECASE)

ALLOWED_NETWORKS = tuple(
    ipaddress.ip_network(n)
    for n in (
        "127.0.0.0/8",  # loopback
        "0.0.0.0/32",  # unspecified
        "192.0.2.0/24",  # TEST-NET-1 (RFC 5737)
        "198.51.100.0/24",  # TEST-NET-2 (RFC 5737)
        "203.0.113.0/24",  # TEST-NET-3 (RFC 5737)
        "::1/128",  # loopback
        "::/128",  # unspecified
        "2001:db8::/32",  # documentation (RFC 3849)
        "3fff::/20",  # documentation (RFC 9637)
    )
)
# Candidate IPv4 literal: four dot-separated groups of 1-3 digits, not part of
# a longer dotted number. Octets are range-checked by hand, so a leading zero
# ("010") cannot hide an address from ``ipaddress``.
IPV4_CANDIDATE = re.compile(r"(?<![0-9.])((?:[0-9]{1,3}\.){3}[0-9]{1,3})(?![0-9]|\.[0-9])")
# Candidate IPv6 literal: a run of hex digits, colons and dots containing at
# least two colons, not touching a word character. Known false positive: a
# Python slice with an empty start and stop and a numeric step reads as an
# IPv6 address. Avoid that spelling in tracked files.
IPV6_CANDIDATE = re.compile(r"(?<![0-9A-Za-z_:.])([0-9A-Fa-f:.]*:[0-9A-Fa-f.]*:[0-9A-Fa-f:.]*)(?![0-9A-Za-z_:.])")


class YamlSubsetError(ValueError):
    """The text uses YAML outside the subset this reader accepts."""


# --------------------------------------------------------------------------
# Strict YAML subset reader. See the module docstring for what it accepts.
# --------------------------------------------------------------------------

_BLOCK_SCALAR = re.compile(r"[|>][+-]?[1-9]?|[|>][1-9]?[+-]?")
_FORBIDDEN_START = tuple("&*!%@`")


def _strip_comment(text: str) -> str:
    quote = ""
    for index, char in enumerate(text):
        if quote:
            if char == quote:
                quote = ""
        elif char in "\"'" and (index == 0 or text[index - 1] in " \t[,:-"):
            quote = char
        elif char == "#" and (index == 0 or text[index - 1] in " \t"):
            return text[:index].rstrip()
    if quote:
        raise YamlSubsetError(f"unterminated quote in {text!r}")
    return text.rstrip()


def _scalar(text: str, lineno: int) -> Any:
    text = text.strip()
    if text == "{}":
        return {}
    if text == "[]":
        return []
    if text.startswith("{"):
        raise YamlSubsetError(f"line {lineno}: non-empty flow mapping")
    if text.startswith("["):
        if not text.endswith("]"):
            raise YamlSubsetError(f"line {lineno}: unterminated flow sequence")
        inner = text[1:-1]
        if any(c in inner for c in "[]{}"):
            raise YamlSubsetError(f"line {lineno}: nested flow collection")
        return [_scalar(part, lineno) for part in inner.split(",") if part.strip()]
    if text.startswith(_FORBIDDEN_START):
        raise YamlSubsetError(f"line {lineno}: anchor, alias, tag or reserved indicator")
    if text.startswith('"'):
        if len(text) < 2 or not text.endswith('"'):
            raise YamlSubsetError(f"line {lineno}: bad double-quoted scalar")
        try:
            return json.loads(text)
        except ValueError as exc:
            raise YamlSubsetError(f"line {lineno}: unsupported escape") from exc
    if text.startswith("'"):
        if len(text) < 2 or not text.endswith("'"):
            raise YamlSubsetError(f"line {lineno}: bad single-quoted scalar")
        return text[1:-1].replace("''", "'")
    return text


def _split_key(content: str, lineno: int) -> tuple[str, str] | None:
    """Split ``key: value``. Return None when ``content`` is not a mapping entry."""
    if content.startswith(("? ", "<<")) or content == "?":
        raise YamlSubsetError(f"line {lineno}: complex or merge key")
    if content[0] in "\"'":
        end = content.find(content[0], 1)
        if end < 0:
            raise YamlSubsetError(f"line {lineno}: unterminated quoted key")
        key, rest = content[1:end], content[end + 1 :]
        if not (rest == ":" or rest.startswith(": ")):
            raise YamlSubsetError(f"line {lineno}: quoted key without ':'")
        return key, rest[1:]
    match = re.match(r"([^\s:#][^:#]*?):(?:\s|$)", content)
    if match is None:
        return None
    key = match.group(1)
    if key.startswith(_FORBIDDEN_START):
        raise YamlSubsetError(f"line {lineno}: anchor, alias or tag in key")
    return key, content[match.end(1) + 1 :]


class _Reader:
    def __init__(self, text: str) -> None:
        if "\t" in "".join(line[: len(line) - len(line.lstrip())] for line in text.split("\n")):
            raise YamlSubsetError("tab in indentation")
        self.lines = text.split("\n")
        self.pos = 0

    def _skip(self) -> None:
        while self.pos < len(self.lines):
            stripped = self.lines[self.pos].strip()
            if stripped and not stripped.startswith("#"):
                return
            self.pos += 1

    def _peek(self) -> tuple[int, str] | None:
        self._skip()
        if self.pos >= len(self.lines):
            return None
        line = self.lines[self.pos]
        return len(line) - len(line.lstrip(" ")), _strip_comment(line.strip())

    def document(self) -> Any:
        head = self._peek()
        if head is not None and head[1].startswith("%"):
            raise YamlSubsetError("directives are not supported")
        if head is not None and head[1] == "---":
            self.pos += 1
        node = self.block(0)
        rest = self._peek()
        if rest is not None:
            raise YamlSubsetError(f"line {self.pos + 1}: unexpected content {rest[1]!r}")
        return node

    def block(self, min_indent: int) -> Any:
        head = self._peek()
        if head is None or head[0] < min_indent:
            return None
        indent, content = head
        if content in ("---", "...") or content.startswith(("--- ", "... ")):
            raise YamlSubsetError(f"line {self.pos + 1}: more than one document")
        if content == "-" or content.startswith("- "):
            return self.sequence(indent)
        return self.mapping(indent)

    def _value(self, rest: str, indent: int, lineno: int) -> Any:
        rest = rest.strip()
        if rest == "":
            return self.block(indent + 1)
        if _BLOCK_SCALAR.fullmatch(rest):
            return self.block_scalar(indent)
        value = _scalar(rest, lineno)
        nxt = self._peek()
        if nxt is not None and nxt[0] > indent:
            raise YamlSubsetError(f"line {self.pos + 1}: multi-line plain scalar or stray indent")
        return value

    def mapping(self, indent: int) -> dict[str, Any]:
        result: dict[str, Any] = {}
        while True:
            head = self._peek()
            if head is None or head[0] < indent:
                return result
            if head[0] > indent:
                raise YamlSubsetError(f"line {self.pos + 1}: unexpected indentation")
            lineno = self.pos + 1
            content = head[1]
            if content == "-" or content.startswith("- "):
                raise YamlSubsetError(f"line {lineno}: sequence item inside a mapping")
            split = _split_key(content, lineno)
            if split is None:
                raise YamlSubsetError(f"line {lineno}: expected 'key: value', got {content!r}")
            key, rest = split
            if key in result:
                raise YamlSubsetError(f"line {lineno}: duplicate key {key!r}")
            self.pos += 1
            result[key] = self._value(rest, indent, lineno)

    def sequence(self, indent: int) -> list[Any]:
        result: list[Any] = []
        while True:
            head = self._peek()
            if head is None or head[0] < indent:
                return result
            if head[0] > indent:
                raise YamlSubsetError(f"line {self.pos + 1}: unexpected indentation")
            lineno = self.pos + 1
            content = head[1]
            if not (content == "-" or content.startswith("- ")):
                raise YamlSubsetError(f"line {lineno}: mapping entry inside a sequence")
            body = content[1:].lstrip(" ")
            if body == "":
                self.pos += 1
                result.append(self.block(indent + 1))
                continue
            inner = indent + (len(content) - len(body))
            if body.startswith(("- ", "-")) and (body == "-" or body.startswith("- ")):
                raise YamlSubsetError(f"line {lineno}: nested inline sequence")
            if _split_key(body, lineno) is not None:
                # Rewrite "- key: value" as "key: value" one level deeper, and
                # read the item as a mapping at that indentation.
                self.lines[self.pos] = " " * inner + body
                result.append(self.mapping(inner))
            else:
                self.pos += 1
                result.append(self._value(body, indent, lineno))

    def block_scalar(self, indent: int) -> str:
        collected: list[str] = []
        while self.pos < len(self.lines):
            line = self.lines[self.pos]
            if line.strip() and len(line) - len(line.lstrip(" ")) <= indent:
                break
            collected.append(line)
            self.pos += 1
        while collected and not collected[-1].strip():
            collected.pop()
        return textwrap.dedent("\n".join(collected)) + "\n" if collected else ""


def parse_yaml_subset(text: str) -> Any:
    """Read ``text`` as the strict YAML subset described in the module docstring."""
    return _Reader(text).document()


# --------------------------------------------------------------------------
# Policy rules.
# --------------------------------------------------------------------------


def _triggers(workflow: dict[str, Any]) -> dict[str, Any]:
    # GitHub reads the key "on"; a YAML 1.1 reader would see boolean true.
    # This reader keeps keys as text, so only "on" is meaningful here.
    on = workflow.get("on")
    if isinstance(on, str):
        return {on: None}
    if isinstance(on, list):
        return {str(item): None for item in on}
    if isinstance(on, dict):
        return on
    return {}


def _jobs(workflow: dict[str, Any]) -> dict[str, Any]:
    jobs = workflow.get("jobs")
    return jobs if isinstance(jobs, dict) else {}


def _all_strings(node: Any) -> list[str]:
    if isinstance(node, str):
        return [node]
    if isinstance(node, dict):
        return [s for k, v in node.items() for s in [k, *_all_strings(v)]]
    if isinstance(node, list):
        return [s for item in node for s in _all_strings(item)]
    return []


def _github_hosted(runs_on: Any) -> bool:
    if isinstance(runs_on, list) and len(runs_on) == 1:
        runs_on = runs_on[0]
    return isinstance(runs_on, str) and GITHUB_HOSTED.fullmatch(runs_on) is not None


def check_self_hosted(name: str, workflow: dict[str, Any]) -> list[str]:
    triggers = ", ".join(sorted(_triggers(workflow))) or "none"
    if name == PRIVILEGED_WORKFLOW:
        # The one workflow admitted to the group. TRIGGER and JOB_SHAPE hold it
        # to workflow_dispatch; this names the self-hosted exposure as well.
        risky = sorted(t for t in _triggers(workflow) if t in RISKY_TRIGGERS or t.startswith("pull_request"))
        if risky:
            return [f"SELF_HOSTED: {name} selects its runner group under triggers {risky}"]
        return []
    errors = []
    for job_id, job in _jobs(workflow).items():
        runs_on = job.get("runs-on") if isinstance(job, dict) else None
        if runs_on is None:
            errors.append(
                f"SELF_HOSTED: {name} job {job_id!r} has no runs-on (a reusable call "
                f"cannot be checked here) under triggers [{triggers}]"
            )
        elif not _github_hosted(runs_on):
            errors.append(
                f"SELF_HOSTED: {name} job {job_id!r} selects {runs_on!r}, not a "
                f"GitHub-hosted label, under triggers [{triggers}]"
            )
    return errors


def check_action_pins(name: str, workflow: dict[str, Any]) -> list[str]:
    errors = []
    for job_id, job in _jobs(workflow).items():
        if not isinstance(job, dict):
            continue
        uses = [job.get("uses")] if "uses" in job else []
        steps = job.get("steps") if isinstance(job.get("steps"), list) else []
        uses += [s.get("uses") for s in steps if isinstance(s, dict) and "uses" in s]
        for ref in uses:
            if not (isinstance(ref, str) and FULL_SHA_ACTION.fullmatch(ref)):
                errors.append(f"ACTION_PIN: {name} job {job_id!r} uses {ref!r} without a full commit SHA")
    return errors


def read_grammar(root: pathlib.Path) -> tuple[str | None, list[str]]:
    path = root / GRAMMAR_FILE
    if not path.is_file() or path.is_symlink():
        return None, [f"GRAMMAR: {GRAMMAR_FILE} is missing or not a regular file"]
    text = path.read_text(encoding="utf-8")
    if not text.endswith("\n") or text.count("\n") != 1 or "\r" in text:
        return None, [f"GRAMMAR: {GRAMMAR_FILE} must be exactly one line ending in LF"]
    grammar = text[:-1]
    try:
        re.compile(grammar)
    except re.error as exc:
        return None, [f"GRAMMAR: {GRAMMAR_FILE} does not compile: {exc}"]
    return grammar, []


def check_privileged(workflow: Any, raw: str, grammar: str | None) -> list[str]:
    name = PRIVILEGED_WORKFLOW
    if not isinstance(workflow, dict):
        return [f"JOB_SHAPE: {name} is not a mapping"]
    errors: list[str] = []

    if SECRETS_OR_VARS.search(raw):
        errors.append(f"SECRETS_VARS: {name} references secrets or vars")

    extra_top = sorted(set(workflow) - ADMITTED_TOP_KEYS)
    if extra_top:
        errors.append(f"JOB_SHAPE: {name} has unadmitted top-level keys {extra_top}")
    if workflow.get("permissions") != {}:
        errors.append(f"JOB_SHAPE: {name} top-level permissions must be {{}}")

    triggers = _triggers(workflow)
    if list(triggers) != ["workflow_dispatch"]:
        errors.append(f"TRIGGER: {name} triggers {sorted(triggers)} instead of workflow_dispatch only")
    dispatch = triggers.get("workflow_dispatch")
    inputs = dispatch.get("inputs") if isinstance(dispatch, dict) else None
    if not isinstance(inputs, dict) or tuple(inputs) != ADMITTED_INPUTS:
        got = list(inputs) if isinstance(inputs, dict) else inputs
        errors.append(f"TRIGGER: {name} inputs {got} instead of {list(ADMITTED_INPUTS)}")
    if isinstance(dispatch, dict) and set(dispatch) - {"inputs"}:
        errors.append(f"TRIGGER: {name} workflow_dispatch has unadmitted keys")

    if workflow.get("run-name") != RUN_NAME_FORMAT:
        errors.append(f"RUN_NAME: {name} run-name {workflow.get('run-name')!r} != {RUN_NAME_FORMAT!r}")

    jobs = _jobs(workflow)
    if list(jobs) != [JOB_ID]:
        errors.append(f"JOB_SHAPE: {name} jobs {list(jobs)} instead of exactly [{JOB_ID!r}]")
    job = jobs.get(JOB_ID)
    if not isinstance(job, dict):
        errors.append(f"JOB_SHAPE: {name} job {JOB_ID!r} is missing")
        return errors

    extra_job = sorted(set(job) - ADMITTED_JOB_KEYS)
    if extra_job:
        errors.append(f"JOB_SHAPE: {name} job has unadmitted keys {extra_job}")
    if job.get("runs-on") != {"group": RUNNER_GROUP}:
        errors.append(f"JOB_SHAPE: {name} runs-on {job.get('runs-on')!r} != {{group: {RUNNER_GROUP}}}")
    if job.get("environment") != ENVIRONMENT:
        errors.append(f"JOB_SHAPE: {name} environment {job.get('environment')!r} != {ENVIRONMENT!r}")
    condition = job.get("if")
    if condition not in (JOB_CONDITION, "${{ " + JOB_CONDITION + " }}"):
        errors.append(f"JOB_SHAPE: {name} job if {condition!r} is not the main/dispatch condition")
    if job.get("permissions") != JOB_PERMISSIONS:
        errors.append(f"JOB_SHAPE: {name} job permissions {job.get('permissions')!r} != {JOB_PERMISSIONS}")

    steps = job.get("steps")
    if not isinstance(steps, list) or not steps or not all(isinstance(s, dict) for s in steps):
        errors.append(f"GRAMMAR: {name} job has no steps, so its first step is not the grammar check")
        return errors

    for index, step in enumerate(steps):
        if "uses" in step:
            errors.append(f"REFUSAL_ONLY: {name} step {index} uses an action")
        if "${{" in str(step.get("run", "")):
            errors.append(f"REFUSAL_ONLY: {name} step {index} interpolates an expression into its script")

    first = steps[0]
    script = first.get("run")
    found = GRAMMAR_LINE.findall(script) if isinstance(script, str) else []
    if len(found) != 1:
        errors.append(f"GRAMMAR: {name} first step does not define exactly one GRAMMAR literal")
    elif grammar is not None and found[0] != grammar:
        errors.append(f"GRAMMAR: {GRAMMAR_FILE} differs from the regex {name}'s first step enforces")
    if grammar is not None and script != GRAMMAR_STEP_SCRIPT.replace("{grammar}", grammar):
        errors.append(f"GRAMMAR: {name} first step script is not the exact grammar check")
    if set(first) != GRAMMAR_STEP_KEYS:
        errors.append(f"GRAMMAR: {name} first step keys {sorted(first)} != {sorted(GRAMMAR_STEP_KEYS)}")
    if first.get("shell") != GRAMMAR_STEP_SHELL:
        errors.append(f"GRAMMAR: {name} first step shell {first.get('shell')!r} != {GRAMMAR_STEP_SHELL!r}")
    if first.get("env") != GRAMMAR_STEP_ENV:
        errors.append(f"GRAMMAR: {name} first step env is not exactly the two dispatch inputs")

    if steps[1:] != [PROOF_STEP, REFUSAL_STEP]:
        errors.append(
            f"REFUSAL_ONLY: {name} must run only the pinned OIDC-to-KV proof step, then end in the pinned refusal step"
        )
    return errors


def tracked_files(root: pathlib.Path) -> list[pathlib.Path]:
    """Files tracked by git; every file under ``root`` (except .git) outside a repository."""
    if (root / ".git").exists():
        out = subprocess.run(
            ["git", "-C", str(root), "ls-files", "-z"],
            check=True,
            capture_output=True,
        ).stdout
        return [root / p for p in out.decode("utf-8").split("\0") if p]
    return sorted(p for p in root.rglob("*") if p.is_file() and ".git" not in p.relative_to(root).parts)


def _allowed(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return any(address.version == n.version and address in n for n in ALLOWED_NETWORKS)


def ip_literals(text: str) -> list[str]:
    found = []
    for match in IPV4_CANDIDATE.finditer(text):
        octets = [int(o) for o in match.group(1).split(".")]
        if all(o <= 255 for o in octets):
            address = ipaddress.IPv4Address(".".join(map(str, octets)))
            if not _allowed(address):
                found.append(match.group(1))
    for match in IPV6_CANDIDATE.finditer(text):
        try:
            address6 = ipaddress.IPv6Address(match.group(1))
        except ValueError:
            continue
        if not _allowed(address6):
            found.append(match.group(1))
    return found


def check_ip_literals(root: pathlib.Path) -> list[str]:
    errors = []
    for path in tracked_files(root):
        if path.is_symlink() or not path.is_file():
            continue
        text = path.read_bytes().decode("utf-8", errors="replace")
        for literal in ip_literals(text):
            errors.append(f"IP_LITERAL: {path.relative_to(root)} contains {literal}")
    return errors


def policy_errors(root: pathlib.Path) -> list[str]:
    errors: list[str] = []
    grammar, grammar_errors = read_grammar(root)
    errors += grammar_errors

    workflows_dir = root / ".github" / "workflows"
    entries = sorted(workflows_dir.iterdir()) if workflows_dir.is_dir() else []
    seen_privileged = False
    for path in entries:
        if path.is_symlink() or not path.is_file() or path.suffix not in (".yml", ".yaml"):
            errors.append(f"YAML: unexpected workflow entry {path.name}")
            continue
        raw = path.read_text(encoding="utf-8")
        try:
            workflow = parse_yaml_subset(raw)
        except YamlSubsetError as exc:
            errors.append(f"YAML: {path.name}: {exc}")
            continue
        if not isinstance(workflow, dict):
            errors.append(f"YAML: {path.name} is not a mapping")
            continue
        if path.name == PRIVILEGED_WORKFLOW:
            seen_privileged = True
            errors += check_privileged(workflow, raw, grammar)
        errors += check_self_hosted(path.name, workflow)
        errors += check_action_pins(path.name, workflow)
    if not seen_privileged:
        errors.append(f"JOB_SHAPE: .github/workflows/{PRIVILEGED_WORKFLOW} is missing or unreadable")

    errors += check_ip_literals(root)
    return errors


def main() -> int:
    root = pathlib.Path(__file__).resolve().parents[1]
    errors = policy_errors(root)
    for error in errors:
        print(error, file=sys.stderr)
    if not errors:
        print("source policy: conforming")
    return 1 if errors else 0


if __name__ == "__main__":
    sys.exit(main())
