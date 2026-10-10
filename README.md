# lane3-exposure-execution

Organization-owned launcher for Lane 3 of the Dotmac build-once cutover. The
design is Starter's `docs/LANE3_EXECUTION_TOPOLOGY.md` (Starter `main`
`ef1c114e`). This repository is public and holds nothing private: no secret,
variable, address, hostname or other topology value belongs in its files,
logs or artifacts.

## Current state: draft immutable handoff proof, final execution refusal

The privileged workflow remains `workflow_dispatch` only, with its exact
`main` guard, protected runner group and Environment, `contents: read` and
`id-token: write`. Dispatch grammar and the final execution refusal are
unchanged. This draft adds the job-bound broker handoff before the existing
bounded OIDC-to-KV proof. It admits no source revision or operational lease.

The proof requires a root-staged supplier bundle and launch record. The
`DOTMAC_LANE3_LEASE_ID` and `DOTMAC_LANE3_SUPPLIER_DIR` environment variables
only locate the fixed per-lease directory under `/run/dotmac-lane3-handoff`.
The workflow walks descriptors without symlinks and checks root ownership,
parent write protection, exact directory/file modes, group, single links,
size and file stability. It verifies the pinned bootstrap bytes before
executing that bootstrap; the bootstrap itself must appear in the exact
installation module map. There is no module download or fallback.

`load_verified_bundle` checks the complete immutable bundle, installation
manifest, boot identity, launch record, original 45-second metadata budget,
source/admission digests and import closure before any supplier import.
`HandoffClient.obtain_from_launch` then reports, waits, validates and consumes
a grant using that original launch time. A refusal or timeout ends the proof
before reading the request token, constructing the supplier, inspecting
WireGuard or reading KV. The source also requires `wireguard_guard=client.wireguard_check`. The adapter
validates and hashes exactly endpoint address, source address, interface and
the two expected public keys; the retained broker field is excluded. It sends
that canonical five-field digest through the authenticated root socket for a
fresh check at construction, connection and pre-send. Root re-reads the fixed
protected LIVE configuration on each request and compares that digest before
its bounded read-only WireGuard/address/route checks. There is no prepare-time
config journal binding, cached success, job command, sudo or privilege change;
`NoNewPrivileges` and the unprivileged runner remain intact. Missing/failing
root callback refuses with no local guard fallback. Starter hosted tests own
the actual adapter, hardened peer and root-command proofs; launcher fixtures
verify wiring through a synthetic transport seam.

The production supplier callback invokes `client.token_request_started`
before HTTP credential transmission, durably marking issuance UNKNOWN in the
root journal. The workflow records `BOUNDED_PROOF` only after the actual read,
parse and expected-version checks succeed; record failure prevents a public
PASS. Read refusals attempt the fixed `REFUSED` outcome. Interrupted or refused
evidence writes retain UNKNOWN and never imply no issuance.
The original request URL and token pass unchanged
to the supplier after consumption, with `oidc_pinned` and `require_pinned=True`.
The root grant's origin supplies broker authority; the installed configuration
continues supplying its existing endpoint, interface and public-key checks.
Its broker field is retained for configuration compatibility and is not
rewritten or used to expand the finite approved origin policy.

The local expectation checks repository/run/attempt/workflow SHA, exact
supplier source revision and the root installation's full supplier/admission
digests. Numeric job and runner IDs and workflow blob are optional in the
current client contract and are not fabricated from `github.job` or job
self-report. The independent coordinator must establish those values plus
run/Environment/source qualification through authoritative API readback,
and the root controller validates that qualification before launch and grant.
The workflow alone does not prove that external boundary is installed or
correctly configured. Bootstrap and client repeats of digest checks are
consistency checks, not independent admission authority.

The source pin and nine-file module map match the proposed Starter revision
`8625c4defd22f223d103fc94cbb74064804fe065`, including the root-check client
and mandatory callback API. This is draft source matching, not admission.

The source map in this draft pins proposed Starter supplier bytes, including
the bootstrap. It is not a protected-main admission or Gate 0 evidence.
Source review and hosted CI, independently governed launcher admission,
root staging and host lifecycle/rollback proof, and specific human approval
for a future protected Environment run/attempt remain separate gates. Source
merge does not install or activate the host packet. A successful bounded KV
proof still ends in the unchanged final execution refusal and reports
`gate0_accepted=false`.

`dispatch-grammar.txt` must equal Starter's `scripts/lane3_execution.py`
`RUN_NAME` pattern; Starter's cross-repository guard checks this contract.

## Source policy and verification

`.github/workflows/source-policy.yml` runs the stdlib source checker and its
synthetic tests on GitHub-hosted CI. Do not run tests locally. The exact
canonical proof script, step environment, grammar and final refusal must
match the workflow. Sensitivity fixtures plant missing verification/handoff,
early token or KV calls, changed source pins, omitted pins, legacy fallback,
conflicting origin authority and disclosure paths. Synthetic consumer tests
exercise the actual embedded proof with mocked installation, handoff and KV
boundaries; Starter owns the production bootstrap/socket/transport fixtures.
No synthetic test substitutes for the full hosted and controlled-host packet.

The checker and its tests share this repository with the workflow. Changes
to this exact source-policy guard require human review before merge. A green
same-repository check detects drift and admits no runner. The independently
governed checker/admission pins must be separately reviewed as part of the
same delivery packet; this draft does not update or activate them.

## Settings an administrator must apply (packet steps B1, B3, B4, B5)

These are proposals awaiting Michael's ruling (packet decision 8). Each one
is proved by a read-back, not by the change that was meant to cause it.

- **B1, repository and ruleset.** Public, organization-owned. Protected
  `main`: pull request required with zero required approvals, the
  non-privileged `source-policy` check required, admin enforcement, no bypass
  actors, deletion and force push refused. Read back the repository ID, the
  owner ID and the effective ruleset. A direct push to `main` must be refused.
- **B3, Environment `lane3-rehearsal-protected`.** Michael is the required
  reviewer. Deployment branch policy is `main` only. Admin bypass is off and
  read back. This is a one-person human gate, not two-person approval. A
  dispatch from another ref must never reach the job, and the job must wait
  without approval.
- **B4, runner group `lane3-exposure-protected`.** The full tuple:
  `allows_public_repositories=true`, `visibility=selected`,
  `selected_repository_ids=[<this repository's ID>]`,
  `restricted_to_workflows=true`,
  `selected_workflows=[dotmac-tech/lane3-exposure-execution/.github/workflows/lane3-exposure-rehearsal.yml@refs/heads/main]`.
  Nothing else in the group. It is distinct from `gate0-issuer-protected` and
  never shares a runner, base image or SSH CA with it. Read back the group ID
  and compare every field. The group holds no runner until B5.
- **B5, canary scheduling proofs, negative before positive.** On a separately
  authorized isolated VM (not the control runner, not the shared test
  server): same-repository and fork `pull_request` and `pull_request_target`
  runs, a wrong ref, a different workflow and a reusable call all stay
  unassigned. Only then is an approved dispatch from `main` picked up. Record
  run and job IDs, remove the canary, and read the group back empty.

Runners are ephemeral, one job each, registered just in time by a provisioner
outside this repository on a VM recreated from a verified base image.

## Added later, each in its own reviewed change

- Gate-3 grant verification before any OpenBao request.
- Private delivery of topology and short-lived Lane 3 SSH certificates into a
  per-run tmpfs, passed as file paths, never values.
- Checkout of Starter at the dispatched revision after the compare API shows
  it on protected `main`, with `git rev-parse HEAD` required to equal it, then
  that revision's runner against the digest-verified candidate.
- Raw probe evidence published only as an encrypted bundle, with a receipt
  that carries opaque identifiers and the run binding.
