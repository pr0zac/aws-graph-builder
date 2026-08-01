# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

**All 6 planned phases (0–5) are complete and verified end-to-end against a real AWS account (the Cloudfoxable sandbox).** `uv run aws-graph-builder scan` now: scans IAM (global) → discovers enabled regions and scans EC2 instances + Lambda functions per region → scans S3 buckets (global) → best-effort Organizations SCP fetch (global) → builds the structural graph → evaluates every principal's identity policies ∩ permission boundary ∩ attached SCPs with explicit-deny-always-wins (`eval/simulator.py`) → materializes `EffectivePermission` edges (including self-targeting ones — a principal CAN have a grant edge to itself) → evaluates every role's trust policy into `CanAssume`/`IdentifiesVia` edges AND every S3/Lambda resource policy into further `EffectivePermission` edges (`eval/trust.py`/`eval/resource_policy.py`, sharing principal-resolution logic) → runs the privesc technique catalog (`privesc/engine.py`) against every `EffectivePermission`/`CanAssume` edge, materializing `PrivescPath` edges and a `"findings"` array in the output JSON → writes JSON plus a companion `*.report.json` (gaps + coverage metadata, `report.py`). `regions_scanned` in the output reflects the real regions scanned (auto-discovered, or narrowed via `--regions`). `uv run aws-graph-builder permissions` emits the least-privilege IAM policy the scan needs, across all 5 scanners. `scan`/`permissions` accept `--profile`, and `scan` accepts `--verbose` for live progress output.

`scan --use-cache` resumes a previous run (reuse anything already cached, only fetch what's missing live). `uv run aws-graph-builder rebuild --account-id ACCOUNT --cache-dir DIR` rebuilds the graph purely from a previous scan's cache — **zero AWS calls, no credentials needed at all** (`--account-id` is required since there's no live session to derive it from; regions are discovered from the cache directory layout itself). Verified: a real scan + `rebuild` from its cache, with every AWS credential env var unset (and, in tests, `botocore`'s API-call path itself blocked), produced byte-identical node/edge/finding ids. `scan` and `rebuild` share one implementation (`cli/_pipeline.py`: build → evaluate → detect → write output/report; `cli/_common.py`: consoles, cache-dir default, JSON serialization) rather than two copies.

`scan/base.py`'s `CachedClient` has two replay modes on top of its normal write-through behavior, sharing one `_replay_entry` helper: `read_only=True` (`rebuild`) answers every call purely from the cache (a miss becomes a `NoCachedData` `ScanGap`, `client` itself can be `None`); `use_cache=True` (`scan --use-cache`) checks the cache first and falls through to a live call on a miss. In both modes, a cached *error* — even one that was originally a credentials-expiry code — always replays as an ordinary gap, never a raised `CredentialsExpiredError`: there's no live credential session to protect during a cache replay, and a stale cached expiry error shouldn't abort a resume.

Policy evaluation works on *patterns*, not enumerated concrete actions (see `eval/simulator.py`'s module docstring for the exact approximations — boundary/SCP intersection and deny-vs-allow overlap all use a documented, conservative wildcard-overlap check that fails in the safe direction, i.e. can over-report privilege but not hide it).

The privesc catalog (`privesc/techniques/`) has 11 detectors: the original 6 IAM-only ones, `pass_role_ec2`/`pass_role_lambda` (Phase 4), plus three post-v1 additions filling gaps against the Rhino Security Labs catalog — `set_default_policy_version`, `pass_role_cloudformation`, and `lambda_update_function_code`. The `pass_role_*` detectors need no new evaluation-engine machinery because `Resource: "*"` grants for `ec2:RunInstances`/`lambda:CreateFunction`/`cloudformation:CreateStack` (the overwhelmingly common real-world case) already match `IamRole` node ARNs via the existing pattern-based `EffectivePermission` materialization. `lambda_update_function_code` is the one detector with a different shape: no `iam:PassRole` involved, since the role is already attached to an existing function — it's found by traversing the `ExecutionRole` edge (`LambdaFunction` -> `IamRole`) rather than checked as an action target. `attach_policy` is the only detector that deliberately does NOT exclude self-targeting — self-escalation via attaching a policy to your own identity is the most common real-world case. Detection is single-hop per principal only — multi-hop chains are a downstream consumer's job via `networkx.all_simple_paths`, not something this phase computes itself. Adding a new technique is just a new module in `privesc/techniques/` decorated with `@register`. See `tasks.md` for exact status. Still not covered from Rhino's list: Glue Dev Endpoint create/update (would need a new Glue resource scanner) and Data Pipeline (same PassRole-pattern shape as the others, but low real-world value since AWS closed Data Pipeline to new customers in 2024).

`CachedClient.call()` has an `ignore_error_codes` kwarg (added in Phase 4): pass botocore error codes that represent a valid empty state rather than a failure (e.g. `lambda:GetPolicy`'s `ResourceNotFoundException` when a function has no resource policy, `s3:GetBucketPolicy`'s `NoSuchBucketPolicy`, `organizations:DescribeOrganization`'s `AWSOrganizationsNotInUseException`) so they're still cached but don't clutter gap reporting.

Local dev note: this machine has two AWS CLI profiles usable for manual testing — `default` (SSO-based, needs `aws sso login --profile default` when expired) and `cloudfoxable` (a deliberately-vulnerable sandbox account at `/Users/zac/Development/cloudfoxable`, deployed via Terraform using the `default` profile; its CTF user's static keys live in `~/.aws/credentials` under the `cloudfoxable` profile).

boto3-stubs (scoped to iam/ec2/lambda/s3/sts/organizations) and types-networkx are installed as dev deps so mypy fully type-checks AWS/graph code — don't reach for `# type: ignore[import-untyped]` on those imports.

## Commands

- `uv run aws-graph-builder --help` — list CLI commands (`scan`, `rebuild`, `permissions`, `version`)
- `uv run aws-graph-builder scan --output graph.json` — scan IAM/EC2/Lambda/S3/Organizations (via ambient boto3 credentials, auto-discovering enabled regions) and write the graph + `graph.report.json`
- `uv run aws-graph-builder scan --profile NAME --regions us-east-1,us-west-2 --verbose` — use a named AWS CLI profile, restrict EC2/Lambda scanning to specific regions, and print each AWS call made and what it finds to stdout as it runs
- `uv run aws-graph-builder scan --use-cache` — resume a previous scan, reusing anything already cached
- `uv run aws-graph-builder rebuild --account-id ACCOUNT_ID --cache-dir DIR` — rebuild the graph from a previous scan's cache with zero AWS calls/credentials
- `uv run aws-graph-builder permissions` — print the read-only IAM policy a scan needs
- `uv run pytest` — run tests (moto-mocked; no real AWS credentials needed)
- `uv run ruff check .` — lint
- `uv run mypy src` — type check

## Where to pick up

- **`aws-graph-builder.md`** — the architecture and design plan for this project: what it does (an AWS attack-path / privilege-escalation graph builder, similar in spirit to PMapper/BloodHound-for-AWS), the requirements decisions behind it, module layout, node/edge taxonomy, JSON output schema, policy evaluation engine design, privesc detection design, caching design, CLI design, and the phased build order. Read this first to understand *what* is being built and *why* it's structured the way it is.
- **`tasks.md`** — the phase-by-phase checklist tracking implementation progress against `aws-graph-builder.md`'s build order. All 6 planned phases are now checked off; check this for the exact verification evidence behind each.
- **`README.md`** — user-facing usage docs (install, `scan`/`rebuild`/`permissions` flags, output format). Update this when CLI-facing behavior changes, since it's what an actual user of the tool reads, not just a future Claude session.

If resuming this project in a new session: read `aws-graph-builder.md` for context, check `tasks.md` for current progress. With v1 complete, "what's next" likely means either the deferred network-reachability phase (see Notes below) or a new, not-yet-planned enhancement — check with the user rather than assuming.

## Notes

- Package manager is `uv` — keep using it for dependency management (`uv add`, `uv run`, etc.).
- This is a defensive security-auditing tool intended to be run by an AWS account owner against their own read-only credentials.
- Network reachability (security groups, NACLs, exposure) is explicitly out of scope for v1 — see `aws-graph-builder.md` for the deferred phase 2 design.
