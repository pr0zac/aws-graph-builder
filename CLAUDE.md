# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

Phase 0 (packaging), Phase 1 (IAM-only structural graph), Phase 2 (policy evaluation engine), and Phase 3 (privesc technique detection) are complete and verified end-to-end against a real AWS account (the Cloudfoxable sandbox). `uv run aws-graph-builder scan` now: scans IAM → builds the structural graph → evaluates every principal's identity policies ∩ permission boundary with explicit-deny-always-wins (`eval/simulator.py`) → materializes `EffectivePermission` edges (including self-targeting ones — a principal CAN have a grant edge to itself) → evaluates every role's trust policy into `CanAssume`/`IdentifiesVia` edges (`eval/trust.py`) → runs the privesc technique catalog (`privesc/engine.py`) against every `EffectivePermission`/`CanAssume` edge, materializing `PrivescPath` edges and a `"findings"` array in the output JSON → writes JSON. `uv run aws-graph-builder permissions` emits the least-privilege IAM policy the scan needs. `scan`/`permissions` accept `--profile`, and `scan` accepts `--verbose` for live progress output.

Policy evaluation works on *patterns*, not enumerated concrete actions (see `eval/simulator.py`'s module docstring for the exact approximations — boundary intersection and deny-vs-allow overlap both use a documented, conservative wildcard-overlap check that fails in the safe direction, i.e. can over-report privilege but not hide it). No SCP or resource-policy evaluation yet (needs the Organizations/S3/Lambda scanners — Phase 4).

The privesc catalog (`privesc/techniques/`) has 6 seed detectors: `create_access_key`, `attach_policy` (the only one that deliberately does NOT exclude self-targeting — self-escalation via attaching a policy to your own identity is the most common real-world case), `create_policy_version`, `update_assume_role_policy`, `add_user_to_group`, `create_login_profile`. Detection is single-hop per principal only — multi-hop chains (e.g. assume role A, which can then attach a policy to role B) are a downstream consumer's job via `networkx.all_simple_paths` over `CanAssume`/`EffectivePermission` edges, not something this phase computes itself. Adding a new technique is just a new module in `privesc/techniques/` decorated with `@register` — no changes needed to `registry.py`/`engine.py`. See `tasks.md` for exact status.

Local dev note: this machine has two AWS CLI profiles usable for manual testing — `default` (SSO-based, needs `aws sso login --profile default` when expired) and `cloudfoxable` (a deliberately-vulnerable sandbox account at `/Users/zac/Development/cloudfoxable`, deployed via Terraform using the `default` profile; its CTF user's static keys live in `~/.aws/credentials` under the `cloudfoxable` profile).

boto3-stubs (scoped to iam/ec2/lambda/s3/sts/organizations) and types-networkx are installed as dev deps so mypy fully type-checks AWS/graph code — don't reach for `# type: ignore[import-untyped]` on those imports.

## Commands

- `uv run aws-graph-builder --help` — list CLI commands (`scan`, `permissions`, `version`)
- `uv run aws-graph-builder scan --output graph.json` — scan the account's IAM (via ambient boto3 credentials) and write the graph
- `uv run aws-graph-builder scan --profile NAME --verbose` — use a named AWS CLI profile, and print each AWS call made and what it finds to stdout as it runs
- `uv run aws-graph-builder permissions` — print the read-only IAM policy a scan needs
- `uv run pytest` — run tests (moto-mocked; no real AWS credentials needed)
- `uv run ruff check .` — lint
- `uv run mypy src` — type check

## Where to pick up

- **`aws-graph-builder.md`** — the architecture and design plan for this project: what it does (an AWS attack-path / privilege-escalation graph builder, similar in spirit to PMapper/BloodHound-for-AWS), the requirements decisions behind it, module layout, node/edge taxonomy, JSON output schema, policy evaluation engine design, privesc detection design, caching design, CLI design, and the phased build order. Read this first to understand *what* is being built and *why* it's structured the way it is.
- **`tasks.md`** — the phase-by-phase checklist tracking implementation progress against `aws-graph-builder.md`'s build order. Check this to see what's already done and what's next. Mark items `[x]` as they're completed; keep it in sync with actual repo state rather than intentions.

If resuming this project in a new session: read `aws-graph-builder.md` for context, check `tasks.md` for current progress, and continue from the first unchecked item in the earliest incomplete phase.

## Notes

- Package manager is `uv` — keep using it for dependency management (`uv add`, `uv run`, etc.).
- This is a defensive security-auditing tool intended to be run by an AWS account owner against their own read-only credentials.
- Network reachability (security groups, NACLs, exposure) is explicitly out of scope for v1 — see `aws-graph-builder.md` for the deferred phase 2 design.
