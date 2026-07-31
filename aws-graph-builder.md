# AWS Attack-Path / Privilege-Escalation Graph Builder

## Context

The repo is currently a bare `uv init` scaffold (`main.py` stub, empty README, no dependencies). The goal is a CLI tool that takes AWS credentials (via boto3's standard credential chain — env vars, STS session tokens, etc.) and scans a single AWS account to build an **attack-path / privilege-escalation graph**: not just an inventory of IAM users/roles/groups/policies/instances/functions/buckets, but an *evaluated* graph of who can actually do what to whom — including known privilege-escalation technique detection (à la PMapper / Rhino Security Labs' catalog) — serialized to a JSON file for a separate, not-yet-built visualization project to consume.

The long-term vision (stated by the user) is a full identity + network attack-path graph, similar in spirit to BloodHound for AWS. **Network reachability (security groups, NACLs, exposure) is explicitly deferred** — v1 is the IAM/privilege graph only, but the schema is designed so network node/edge types can be added later without breaking changes.

This is a defensive security-auditing tool, run by the account owner against their own read-only credentials.

## Key decisions (from requirements discussion)

- **V1 resource scope**: IAM (users, groups, roles, managed + inline policies, permission boundaries, identity providers, instance profiles), EC2 instances, Lambda functions, S3 buckets, SCPs (best-effort via Organizations API), trust policies, resource policies.
- **Evaluation, not just inventory**: statically simulate identity policy ∩ permission boundary ∩ SCP, explicit-deny precedence, trust policy evaluation — producing `EffectivePermission` and `CanAssume` edges, not just "policy attached to X" edges.
- **Privesc detection is first-class**: known technique catalog (CreateAccessKey, Attach/PutPolicy family, CreatePolicyVersion+SetDefaultPolicyVersion, UpdateAssumeRolePolicy, PassRole+RunInstances, PassRole+Lambda, etc.) is detected and annotated in the output, not left to the downstream consumer.
- **Single account per run**, standard boto3 credential chain (so env vars, STS session tokens, profiles all work — no custom credential plumbing).
- **All enabled regions** auto-discovered for region-scoped services; IAM/S3/Organizations scanned once globally.
- **networkx** as the in-memory graph; export to a **JSON node-link schema** (via `networkx.node_link_data`) designed to be easy for a future web visualizer to consume and reloadable via `networkx.node_link_graph`.
- **Disk cache of raw API responses**, enabling a cache-only `rebuild` command that never touches AWS — for large accounts, rate-limit friendliness, and iterating on evaluation logic.
- **CLI**: `scan` (main flow), `rebuild` (cache → graph, no AWS calls), `permissions` (emits the minimal required read-only IAM policy JSON so a scoped principal can be created before running `scan`).
- **Partial failures degrade gracefully**: AccessDenied/throttling on any single API call is logged as a gap and the scan continues, producing a partial graph plus a companion report of what was skipped.
- **Testing**: moto-mocked unit tests per scanner, pure-logic unit tests for the policy evaluation engine (the highest-value test surface), hand-built-graph tests for privesc detectors.
- **Tooling**: keep `uv`; Python 3.14 pin stays as-is.

## Architecture

### Packaging groundwork (do first)
Convert the bare script scaffold into an installable `src/`-layout package:
- `src/aws_graph_builder/` package; add `[build-system]` (hatchling) + `[project.scripts] aws-graph-builder = "aws_graph_builder.cli.app:app"` to `pyproject.toml`.
- Retire `main.py`.
- `uv add boto3 networkx typer rich`; `uv add --dev moto pytest pytest-cov ruff mypy`.

### Module layout
```
src/aws_graph_builder/
  session.py           # boto3 Session construction, sts:GetCallerIdentity validation, expiry handling
  regions.py            # enabled-region discovery via ec2:DescribeRegions
  report.py              # ScanReport/ScanGap dataclasses + companion *.report.json writer

  cli/
    app.py                 # Typer root app
    scan_cmd.py              # scan -> build -> evaluate -> privesc -> export
    rebuild_cmd.py            # cache-only rebuild, no AWS calls
    permissions_cmd.py         # emits required-actions IAM policy JSON

  cache/
    store.py               # content-keyed JSON file cache, read-through/write-through
    keys.py                  # deterministic cache key naming

  scan/
    base.py                 # Scanner ABC, ScanGap, CachedClient wrapper around boto3 client
    iam.py                    # GetAccountAuthorizationDetails-driven + SAML/OIDC/instance profiles
    organizations.py           # best-effort SCP fetch, skip gracefully if not in an Org
    ec2.py, lambda_.py, s3.py   # per-service scanners
    orchestrator.py              # sequences scanners, aggregates ScanGaps

  graph/
    schema.py               # NodeType/EdgeType enums, Node/Edge dataclasses, ID scheme
    builder.py                # raw scan records -> networkx.MultiDiGraph (structural edges)
    export.py                  # MultiDiGraph <-> JSON schema

  eval/
    policy_document.py      # PolicyDocument/Statement normalization, retains evidence pointers
    matcher.py                # action/resource wildcard matching, condition evaluation
    simulator.py                # allow/deny resolution (deny wins), boundary/SCP intersection
    trust.py                     # AssumeRolePolicyDocument -> CanAssume edges
    resource_policy.py            # S3/Lambda resource policies -> EffectivePermission edges
    engine.py                      # orchestrates the above over the structural graph

  privesc/
    registry.py              # TechniqueSpec + @register decorator, detector protocol
    engine.py                  # runs all detectors, writes PrivescPath edges + findings list
    techniques/                 # one file per technique, additive — no core code changes needed
```

### Node/edge taxonomy (v1)
**Nodes**: `Account`, `IamUser`, `IamGroup`, `IamRole`, `ManagedPolicy`, `InlinePolicy`, `IdentityProvider`, `InstanceProfile`, `Ec2Instance`, `LambdaFunction`, `S3Bucket`, `ServiceControlPolicy`, `ExternalPrincipal` (unresolvable/cross-account ARNs referenced in trust/resource policies), `ServicePrincipal`.

Permission boundaries are `ManagedPolicy` nodes referenced via `HasPermissionBoundary`, not a separate node type.

**Edges**: `MemberOf`, `AttachedPolicy`, `HasInlinePolicy`, `HasPermissionBoundary`, `AttachedTo`, `ExecutionRole`, `AppliesSCP`, `IdentifiesVia`, `CanAssume` (from trust-policy evaluation), `EffectivePermission` (actions/resource_pattern/effect/evidence/condition_unresolved), `PrivescPath` (technique_id/severity/required_permissions/evidence_edges).

**Reserved for phase 2 (network)**: `SecurityGroup`, `Vpc`, `Subnet`, `NetworkInterface`, `LoadBalancer`, `RouteTable`, `InternetGateway` nodes; `AllowsIngress`, `AllowsEgress`, `Routes`, `ExposesToInternet` edges. A `schema_version` field plus additive enums mean this doesn't require reworking v1.

Multi-hop reachability (A assumes B assumes C) doesn't need its own detector — it falls out of chained `CanAssume`/`EffectivePermission` edges via `networkx.all_simple_paths`, usable by any downstream consumer.

### JSON output schema
Based on `networkx.node_link_data(G, edges="edges")`:
```json
{
  "schema_version": "1.0",
  "generated_at": "2026-07-31T20:00:00Z",
  "account_id": "111111111111",
  "regions_scanned": ["us-east-1", "us-west-2"],
  "nodes": [
    {"id": "arn:aws:iam::111111111111:user/alice", "type": "IamUser", "name": "alice",
     "arn": "arn:aws:iam::111111111111:user/alice", "properties": {"mfa_enabled": false}}
  ],
  "edges": [
    {"id": "e-1", "type": "CanAssume", "source": "...:user/alice", "target": "...:role/deploy-role",
     "properties": {"requires_mfa": false, "evidence": {"trust_statement_sid": "AllowAlice"}}},
    {"id": "e-3", "type": "PrivescPath", "source": "...:role/deploy-role", "target": "...:user/bob",
     "properties": {"technique_id": "create_access_key", "severity": "high",
       "required_permissions": ["iam:CreateAccessKey"], "evidence_edges": ["e-2"]}}
  ],
  "findings": [
    {"technique_id": "create_access_key", "source": "...:role/deploy-role", "target": "...:user/bob",
     "severity": "high", "edge_id": "e-3"}
  ]
}
```
`findings` denormalizes `PrivescPath` edges for consumers that don't want to filter the edge array. Scan gaps (denied/throttled calls) go in a separate companion `*.report.json`, not the graph file.

### Policy evaluation engine
Small composable, independently testable functions rather than one monolith:
- `policy_document.py` parses raw JSON into `Statement` dataclasses, always keeping a source pointer (policy ARN + Sid) for evidence.
- `matcher.py`: pure functions `action_matches`, `resource_matches`, `condition_matches`. Conditions this static tool can't resolve at scan time (e.g. `aws:SourceIp`) are **not** guessed either way — the resulting edge is tagged `condition_unresolved: true`, surfacing the ambiguity instead of hiding it.
- `simulator.py`: `resolve(allow, deny)` (explicit-deny-always-wins — the top unit-test target) and a generic `intersect()` combinator reused for identity ∩ boundary ∩ SCP. A `PermissionQuery.can(principal, action, resource)` function answers concrete questions against the resulting pattern set, used by both ad-hoc queries and privesc detectors.
- `trust.py` evaluates `AssumeRolePolicyDocument` Principal blocks into `CanAssume` edges (AWS ARN / `Federated` → IdentityProvider / `Service` → ServicePrincipal / unresolvable → ExternalPrincipal), flagging `sts:ExternalId`/MFA conditions as edge properties rather than silently enforcing them.
- `resource_policy.py` applies the same Principal-grant logic to S3 bucket policies and Lambda resource policies.

### Privesc technique catalog
`privesc/registry.py` defines `TechniqueSpec` + `@register` decorator; detectors take `(graph, principal_id, query: PermissionQuery)` and only call `query.can(...)` against already-evaluated edges — they never re-parse raw policy JSON, keeping them trivially testable with small hand-built graphs. New techniques are added by dropping a new module in `privesc/techniques/`, no changes to `eval/` or `graph/`.

V1 seed set (IAM-only): `CreateAccessKey`, `Attach*Policy`/`Put*Policy` family, `CreatePolicyVersion`+`SetDefaultPolicyVersion`, `UpdateAssumeRolePolicy`, `AddUserToGroup`, `CreateLoginProfile`/`UpdateLoginProfile`. Added once EC2/Lambda land: `PassRole+RunInstances`, `PassRole+Lambda CreateFunction+Invoke`.

### Disk cache
Root: `~/.cache/aws-graph-builder/<account_id>/` (overridable via `--cache-dir`), mirroring service/operation/params as files (errors cached too, so `rebuild` reproduces gaps without re-hitting AWS). Scanners talk to a `CachedClient` wrapper with the same method names as boto3, so scanner code reads like plain boto3 calls.

### CLI (Typer)
```
aws-graph-builder scan --output graph.json [--regions us-east-1,us-west-2] [--cache-dir DIR] [--use-cache] [--report graph.report.json]
aws-graph-builder rebuild --cache-dir DIR --output graph.json     # no AWS calls at all
aws-graph-builder permissions [--output policy.json]              # least-privilege read-only IAM policy
```
Typer chosen over raw click for type-hint-driven parsing (fits the dataclass-heavy design) and native `CliRunner` testing. `permissions` aggregates each `Scanner.required_actions()` into one policy document — single source of truth, so it can't drift from what scanners actually call.

### boto3 clients / required actions
| Service | Scope | Key actions |
|---|---|---|
| STS | global | `sts:GetCallerIdentity` |
| EC2 (region discovery) | global-ish | `ec2:DescribeRegions` |
| IAM | global | `iam:GetAccountAuthorizationDetails` (bulk call, PMapper's own approach), `iam:ListSAMLProviders`/`GetSAMLProvider`, `iam:ListOpenIDConnectProviders`/`GetOpenIDConnectProvider`, `iam:ListInstanceProfiles`/`GetInstanceProfile` |
| Organizations | global, best-effort | `organizations:DescribeOrganization`, `ListPoliciesForTarget`, `DescribePolicy` — catch and skip `AWSOrganizationsNotInUseException`/AccessDenied |
| EC2 | per region | `ec2:DescribeInstances` |
| Lambda | per region | `lambda:ListFunctions`, `lambda:GetPolicy` (treat `ResourceNotFoundException` as "no policy") |
| S3 | global list, per-bucket | `s3:ListAllMyBuckets`, `GetBucketLocation`, `GetBucketPolicy`, `GetBucketAcl` |

### Region discovery
`regions.discover_enabled_regions(session)` calls `ec2.describe_regions()` filtered to opted-in/no-opt-in-required regions; `--regions` intersects with this set.

## Phased build order

1. **Packaging groundwork** — src-layout conversion, entry point, dependencies.
2. **IAM-only vertical slice** (structural graph, no evaluation yet) — `session.py`, `cache/`, `scan/base.py` + `scan/iam.py`, `graph/schema.py` + `builder.py` + `export.py`, minimal `cli/app.py` + `scan_cmd.py` + `permissions_cmd.py`. **This alone is demoable**: real account → IAM inventory graph → JSON file.
3. **Policy evaluation engine** (still IAM-only) — `eval/*`, wired into `scan_cmd.py`. Heaviest unit-test investment: deny precedence, wildcard matching, boundary/SCP intersection, condition-unresolved flagging.
4. **Privesc registry + IAM-only detectors** — `privesc/*` with the seed technique set.
5. **Expand resource scope** — `regions.py`, `scan/ec2.py`, `scan/lambda_.py`, `scan/s3.py`, `scan/organizations.py`; extend `graph/builder.py`, `eval/resource_policy.py`, SCP intersection; add PassRole-based detectors; extend `permissions_cmd.py`.
6. **Cache/report/rebuild polish** — `report.py`, `cli/rebuild_cmd.py`, `--use-cache` resume, README.

Build and land phase-by-phase rather than all at once — phase 2 alone is already a working, useful tool.

## Dependencies
Runtime: `boto3`, `networkx`, `typer`, `rich`. Dev: `moto`, `pytest`, `pytest-cov`, `ruff`, `mypy`.

Considered and not adopted: `policyuniverse` (wildcard-expansion utility only, doesn't do boundary/SCP intersection or evidence tracking); `iam:SimulatePrincipalPolicy` (real alternative, but requires live calls incompatible with cache-first `rebuild`, and weaker evidence-per-statement — worth using manually as a cross-check during development, not automated); Access Analyzer/Zelkova (better aligned with the deferred network/exposure phase).

## Verification

- `uv run pytest` for the full suite as each phase lands: `tests/eval/` (pure logic, no moto — deny-beats-allow, wildcard matching, boundary/SCP intersection, condition-unresolved flagging), `tests/scan/` (moto `@mock_aws` per scanner, with AccessDenied simulated via monkeypatched `ClientError` since moto doesn't enforce real IAM semantics), `tests/graph/` (builder against hand-authored fixtures), `tests/privesc/` (detectors against small hand-built graphs, including negative/explicit-deny cases), `tests/cli/` (`typer.testing.CliRunner`; a `rebuild` test mocks `boto3.client` to raise if called at all, proving the cache-only path never touches AWS).
- After phase 2 lands: run `uv run aws-graph-builder permissions --output policy.json`, attach that policy to a scoped IAM user/role, then run `uv run aws-graph-builder scan --output graph.json` against a real (or sandbox) AWS account and inspect the resulting `graph.json` for correct IAM node/edge coverage.
- After phase 3+4: hand-verify at least one known privesc scenario in a sandbox account (e.g. a role with `iam:CreateAccessKey` on `*`) and confirm it shows up as a `PrivescPath` finding in the output.
- After phase 5: re-run `scan` against an account/region set that includes EC2/Lambda/S3 resources and confirm they appear with correct trust/resource-policy edges; confirm `rebuild` reproduces the same graph from cache with zero AWS API calls (verify via network mocking or CloudTrail).
