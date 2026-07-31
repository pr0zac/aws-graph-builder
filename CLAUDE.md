# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

Phase 0 (packaging) and Phase 1 (IAM-only vertical slice) are complete and verified end-to-end against a real AWS account (the Cloudfoxable sandbox): `uv run aws-graph-builder scan` builds a real structural IAM graph (users/groups/roles/policies/boundaries/identity providers/instance profiles) from a live AWS account and writes it as JSON, and `uv run aws-graph-builder permissions` emits the least-privilege IAM policy the scan needs. `scan`/`permissions` accept `--profile` to pick a named AWS CLI profile, falling back to boto3's standard credential chain if omitted. No policy *evaluation* (effective permissions, trust-policy → CanAssume edges) or privesc detection exists yet — that's Phase 2/3. See `tasks.md` for exact status.

Local dev note: this machine has two AWS CLI profiles usable for manual testing — `default` (SSO-based, needs `aws sso login --profile default` when expired) and `cloudfoxable` (a deliberately-vulnerable sandbox account at `/Users/zac/Development/cloudfoxable`, deployed via Terraform using the `default` profile; its CTF user's static keys live in `~/.aws/credentials` under the `cloudfoxable` profile).

boto3-stubs (scoped to iam/ec2/lambda/s3/sts/organizations) and types-networkx are installed as dev deps so mypy fully type-checks AWS/graph code — don't reach for `# type: ignore[import-untyped]` on those imports.

## Commands

- `uv run aws-graph-builder --help` — list CLI commands (`scan`, `permissions`, `version`)
- `uv run aws-graph-builder scan --output graph.json` — scan the account's IAM (via ambient boto3 credentials) and write the graph
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
