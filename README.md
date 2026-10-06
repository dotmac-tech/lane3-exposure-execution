# lane3-exposure-execution

Organization-owned launcher for Lane 3 of the Dotmac build-once cutover. The
design is Starter's `docs/LANE3_EXECUTION_TOPOLOGY.md` (Starter `main`
`ef1c114e`). This repository is public and holds nothing private: no secret,
variable, address, hostname or other topology value belongs in its files,
logs or artifacts.

## Current state: refusal-only

`.github/workflows/lane3-exposure-rehearsal.yml` is the one privileged
workflow. It is `workflow_dispatch` only. Its one job, `rehearse`, runs only
for a dispatch from `refs/heads/main`, in runner group
`lane3-exposure-protected` and Environment `lane3-rehearsal-protected`, with
`contents: read` and nothing else. It takes three inputs: `starter_revision`,
`candidate_version` and an opaque `grant_ref`. There is no target, slot or
address input.

1. The first step composes `lane3 starter=<starter_revision>
   candidate=<candidate_version>` and refuses unless it fully matches the
   dispatch grammar. This is the same title that `run-name` renders.
2. The second step always refuses: no Gate-3 grant verification, private
   delivery or Lane 3 execution exists yet.

A failed run is not rehearsal evidence. It requests no OIDC token, reads no
secret and connects to nothing.

`dispatch-grammar.txt` holds the grammar as one line. It must equal Starter's
`scripts/lane3_execution.py` `RUN_NAME` pattern, because Starter's release
oracle excludes a run whose title does not parse only on the ground that this
launcher refuses that same grammar first. Starter's cross-repository guard
compares the two.

## Source policy

`.github/workflows/source-policy.yml` runs `scripts/source_policy.py` and its
tests on a GitHub-hosted runner for pull requests and pushes to `main`. The
checker is stdlib-only and reads workflows with a strict YAML subset reader
that refuses constructs it does not understand. See its docstring for the
rules and the reader's limits. Run it locally:

```
python3 -B scripts/source_policy.py
python3 -B -m unittest discover -s tests -v
```

The checker lives in the repository it checks, so one pull request can change
both. It catches drift; it is not an independent security control, and a green
result admits no runner.

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

- `id-token: write` on the protected job and the OIDC exchange with the
  OpenBao JWT role bound to this repository's immutable IDs, Environment,
  `ref`, `workflow_ref` and `event_name`.
- Gate-3 grant verification before any OpenBao request.
- Private delivery of topology and short-lived Lane 3 SSH certificates into a
  per-run tmpfs, passed as file paths, never values.
- Checkout of Starter at the dispatched revision after the compare API shows
  it on protected `main`, with `git rev-parse HEAD` required to equal it, then
  that revision's runner against the digest-verified candidate.
- Raw probe evidence published only as an encrypted bundle, with a receipt
  that carries opaque identifiers and the run binding.
