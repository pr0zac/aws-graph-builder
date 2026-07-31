# aws-graph-builder — Task Tracker

Tracks implementation progress against the phased build order in `aws-graph-builder.md`. Check items off as they land.

## Phase 0 — Packaging groundwork
- [x] Convert to `src/aws_graph_builder/` layout
- [x] Add `[build-system]` (hatchling) + `[project.scripts]` entry point to `pyproject.toml`
- [x] Retire `main.py` stub
- [x] `uv add boto3 networkx typer rich`
- [x] `uv add --dev moto pytest pytest-cov ruff mypy`

## Phase 1 — IAM-only vertical slice (structural graph, no evaluation)
- [x] `session.py` — boto3 Session construction, `sts:GetCallerIdentity` validation, expiry handling
- [x] `cache/store.py` + `cache/keys.py` — content-keyed JSON file cache
- [x] `scan/base.py` — Scanner ABC, ScanGap, CachedClient wrapper
- [x] `scan/iam.py` — users/groups/roles/policies/boundaries/identity providers/instance profiles
- [x] `graph/schema.py` — NodeType/EdgeType enums, Node/Edge dataclasses, ID scheme
- [x] `graph/builder.py` — structural graph builder (IAM types only)
- [x] `graph/export.py` — MultiDiGraph <-> JSON schema
- [x] `cli/app.py` + `cli/scan_cmd.py` (minimal) + `cli/permissions_cmd.py` (IAM-only actions)
- [x] Tests: `tests/scan/test_iam_scanner.py`, `tests/graph/test_builder_iam.py`, `tests/cli/test_scan_cmd_iam_only.py`
- [x] Demo: real/sandbox account → IAM inventory graph → `graph.json` (verified against the Cloudfoxable sandbox account, `--profile cloudfoxable`: 84 nodes / 46 edges)

## Phase 2 — Policy evaluation engine (still IAM-only)
- [x] `eval/policy_document.py` — Statement normalization with evidence pointers
- [x] `eval/matcher.py` — action/resource wildcard + condition matching
- [x] `eval/simulator.py` — deny-wins `resolve_grants()` + boundary-intersection approximation + `PermissionQuery`
- [x] `eval/trust.py` — AssumeRolePolicyDocument → CanAssume/IdentifiesVia edges
- [x] Wire `eval/engine.py` into `scan_cmd.py`
- [x] Tests: deny-beats-allow, wildcard matching, boundary intersection, condition-unresolved flagging (113/113 passing; `NotAction`/`NotResource` explicitly out of scope, documented in `eval/simulator.py`)
- [x] Verified against the Cloudfoxable sandbox: 1993 `EffectivePermission` (including legitimate self-targeting grants — see below) + 35 `CanAssume` + 1 `IdentifiesVia` edges, all coherent (correct service-linked-role trust, correct SAML→SSO-admin-role chain, correct multi-policy evidence merging, zero dangling edge references)
- [x] Fix: self-targeting `EffectivePermission` edges (e.g. "principal can attach a policy to itself") are now materialized rather than excluded — required for Phase 3 to detect self-privesc, the most common real-world technique shape

## Phase 3 — Privesc registry + IAM-only detectors
- [x] `privesc/registry.py` — `TechniqueSpec`, `PrivescFinding`, `@register` decorator, `all_techniques()`
- [x] `privesc/engine.py` — `run_privesc_detection()` runs every detector × every IamUser/IamRole principal, writes `PrivescPath` edges (discriminated by technique_id), returns findings list
- [x] Seed detectors: `create_access_key`, `attach_policy` (Attach/Put family, deliberately includes self-targeting), `create_policy_version`, `update_assume_role_policy`, `add_user_to_group`, `create_login_profile` — all wired into `scan_cmd.py`'s output `"findings"` key
- [x] Tests: 24 new tests (positive/negative/self-exclusion per detector, registry mechanics, multi-technique discriminator case in `test_engine.py`); 137/137 full suite passing
- [x] Sandbox verification: **120 real findings** against the Cloudfoxable sandbox — `attach_policy` 39 (critical), `create_policy_version` 41 (high), `update_assume_role_policy` 35 (high), `create_access_key` 2 (high), `create_login_profile` 2 (high), `add_user_to_group` 1 (medium); 120/120 findings cross-checked against real `PrivescPath` edges in the graph, zero orphans

## Phase 4 — Expand resource scope
- [x] `regions.py` — `discover_enabled_regions()` via `ec2:DescribeRegions`, filtered to opt-in-not-required/opted-in
- [x] `scan/ec2.py` — instances (region-scoped; ARN construction deferred to the graph-building layer)
- [x] `scan/lambda_.py` — functions + resource policy (`ResourceNotFoundException` treated as "no policy", not a gap, via `CachedClient`'s new `ignore_error_codes`)
- [x] `scan/s3.py` — buckets + location + bucket policy (`NoSuchBucketPolicy` ignored) + ACL
- [x] `scan/organizations.py` — best-effort SCP fetch, degrades gracefully to `in_organization=False` when not in an Org or lacking permission
- [x] `graph/schema.py`/`graph/builder.py` extended: `Ec2Instance`/`LambdaFunction`/`S3Bucket`/`ServiceControlPolicy` node types, `ExecutionRole`/`AppliesSCP` edges (`AttachedTo` reused for InstanceProfile→Ec2Instance)
- [x] `eval/resource_policy.py` — S3/Lambda resource policy → `EffectivePermission` edges, reusing principal-resolution logic refactored out of `eval/trust.py` (zero behavior change, all prior trust tests pass unchanged)
- [x] SCP intersection in `eval/simulator.py` — same restrict-only pattern-overlap approximation as permission boundaries, plus SCP explicit-deny support
- [x] New detectors: `pass_role_ec2`, `pass_role_lambda` — exploit the existing pattern-matching behavior (`Resource: "*"` grants for `RunInstances`/`CreateFunction` already match `IamRole` node ARNs) rather than requiring new evaluation-engine machinery
- [x] Extended `cli/permissions_cmd.py` with all 4 new scanners' required actions + `ec2:DescribeRegions`
- [x] `scan_cmd.py` rewritten to orchestrate: IAM (global) → EC2+Lambda (per enabled region, `--regions` override supported) → S3 (global) → Organizations (global) → evaluate → detect; `regions_scanned` in output now reflects real scanned regions; gaps aggregated across every scanner
- [x] Sandbox verification against Cloudfoxable: real S3 buckets (8, including bucket policies), real Lambda functions (5, all with correct `ExecutionRole` edges and 3/5 with real resource policies parsed correctly — public function URLs, SNS triggers), 2310 `EffectivePermission` edges, **188 findings** (up from 120 — `pass_role_ec2`/`pass_role_lambda` alone contributed 34 each), zero dangling edges, 188/188 findings cross-checked against real `PrivescPath` edges

## Phase 5 — Cache/report/rebuild polish
- [x] `report.py` — `ScanReport` (account_id/generated_at/regions_scanned/gaps) + `report_path_for()` (`graph.json` → `graph.report.json`) + `write_scan_report()`, wired into both `scan` and `rebuild`
- [x] `scan/base.py`'s `CachedClient` gained `read_only`/`use_cache` replay modes sharing one `_replay_entry` helper: `read_only` answers purely from cache (`client` can be `None`; a miss becomes a `NoCachedData` gap), `use_cache` checks cache first and falls through to a live call on a miss. Cached errors — even ones that were originally credential-expiry codes — always replay as an ordinary `ScanGap`, never a raised `CredentialsExpiredError` (no live session to protect during replay, and a *stale* cached expiry error shouldn't abort a `--use-cache` resume)
- [x] `cli/rebuild_cmd.py` — cache-only rebuild, `--account-id` required (no live session to derive it from), regions discovered from the cache directory layout itself, zero AWS calls
- [x] `--use-cache` resume flag on `scan`
- [x] Extracted shared `cli/_pipeline.py` (build graph → evaluate → detect → write output/report → print gaps) and `cli/_common.py` (consoles, cache-dir default, json serialization hook) so `scan` and `rebuild` share one implementation instead of two copies
- [x] `README.md` with usage instructions
- [x] Verified `rebuild` reproduces the same graph from cache with zero AWS API calls: real scan against the Cloudfoxable sandbox (111 nodes / 2585 edges / 188 findings) followed by `rebuild` from that cache with **all AWS credential env vars unset** and, in the test suite, `botocore`'s `_make_api_call` itself blocked — node ids, edge ids, and findings all identical between the two runs

## Deferred (not v1)
- [ ] Phase 2 (network): SecurityGroup/Vpc/Subnet/NetworkInterface/LoadBalancer/RouteTable/InternetGateway nodes, AllowsIngress/AllowsEgress/Routes/ExposesToInternet edges
