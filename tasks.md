# aws-graph-builder — Task Tracker

Tracks implementation progress against the phased build order in `aws-graph-builder.md`. Check items off as they land.

## Phase 0 — Packaging groundwork
- [x] Convert to `src/aws_graph_builder/` layout
- [x] Add `[build-system]` (hatchling) + `[project.scripts]` entry point to `pyproject.toml`
- [x] Retire `main.py` stub
- [x] `uv add boto3 networkx typer rich`
- [x] `uv add --dev moto pytest pytest-cov ruff mypy`

## Phase 1 — IAM-only vertical slice (structural graph, no evaluation)
- [ ] `session.py` — boto3 Session construction, `sts:GetCallerIdentity` validation, expiry handling
- [ ] `cache/store.py` + `cache/keys.py` — content-keyed JSON file cache
- [ ] `scan/base.py` — Scanner ABC, ScanGap, CachedClient wrapper
- [ ] `scan/iam.py` — users/groups/roles/policies/boundaries/identity providers/instance profiles
- [ ] `graph/schema.py` — NodeType/EdgeType enums, Node/Edge dataclasses, ID scheme
- [ ] `graph/builder.py` — structural graph builder (IAM types only)
- [ ] `graph/export.py` — MultiDiGraph <-> JSON schema
- [ ] `cli/app.py` + `cli/scan_cmd.py` (minimal) + `cli/permissions_cmd.py` (IAM-only actions)
- [ ] Tests: `tests/scan/test_iam_scanner.py`, `tests/graph/test_builder_iam.py`, `tests/cli/test_scan_cmd_iam_only.py`
- [ ] Demo: real/sandbox account → IAM inventory graph → `graph.json`

## Phase 2 — Policy evaluation engine (still IAM-only)
- [ ] `eval/policy_document.py` — Statement normalization with evidence pointers
- [ ] `eval/matcher.py` — action/resource wildcard + condition matching
- [ ] `eval/simulator.py` — deny-wins resolve() + intersect() combinator + PermissionQuery
- [ ] `eval/trust.py` — AssumeRolePolicyDocument → CanAssume edges
- [ ] Wire `eval/engine.py` into `scan_cmd.py`
- [ ] Tests: deny-beats-allow, wildcard matching, NotAction, boundary intersection, condition-unresolved flagging

## Phase 3 — Privesc registry + IAM-only detectors
- [ ] `privesc/registry.py` — TechniqueSpec + `@register` decorator
- [ ] `privesc/engine.py` — runs detectors, writes PrivescPath edges + findings list
- [ ] Seed detectors: `create_access_key`, `attach_policy` (Attach/Put family), `create_policy_version`, `update_assume_role_policy`, `add_user_to_group`, `create_login_profile`
- [ ] Tests: hand-built small graphs per detector, including explicit-deny negative cases
- [ ] Sandbox verification: confirm a known privesc scenario (e.g. role with `iam:CreateAccessKey` on `*`) surfaces as a finding

## Phase 4 — Expand resource scope
- [ ] `regions.py` — enabled-region discovery
- [ ] `scan/ec2.py` — instances + instance profiles
- [ ] `scan/lambda_.py` — functions + execution role + resource policy
- [ ] `scan/s3.py` — buckets + bucket policy + ACL
- [ ] `scan/organizations.py` — best-effort SCP fetch
- [ ] Extend `graph/builder.py` for new node/edge types
- [ ] `eval/resource_policy.py` — S3/Lambda resource policy → EffectivePermission edges
- [ ] SCP intersection in `eval/simulator.py`
- [ ] New detectors: `pass_role_ec2`, `pass_role_lambda`
- [ ] Extend `cli/permissions_cmd.py` with new required actions
- [ ] Sandbox verification: EC2/Lambda/S3 resources appear with correct trust/resource-policy edges

## Phase 5 — Cache/report/rebuild polish
- [ ] `report.py` — ScanReport/ScanGap + companion `*.report.json` writer
- [ ] `cli/rebuild_cmd.py` — cache-only rebuild, no AWS calls
- [ ] `--use-cache` resume flag on `scan`
- [ ] README with usage instructions
- [ ] Verify `rebuild` reproduces the same graph from cache with zero AWS API calls

## Deferred (not v1)
- [ ] Phase 2 (network): SecurityGroup/Vpc/Subnet/NetworkInterface/LoadBalancer/RouteTable/InternetGateway nodes, AllowsIngress/AllowsEgress/Routes/ExposesToInternet edges
