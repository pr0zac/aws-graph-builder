# aws-graph-builder

A command-line tool that scans an AWS account with read-only credentials and builds an **attack-path / privilege-escalation graph**: not just an inventory of IAM users, roles, groups, policies, EC2 instances, Lambda functions, and S3 buckets, but an *evaluated* graph of who can actually do what to whom — including detection of known IAM privilege-escalation techniques — serialized to JSON for downstream analysis, or explored directly with the built-in local web visualizer (`serve`).

Similar in spirit to tools like PMapper and Cartography. Read-only, defensive: intended to be run by an account owner (or an authorized security assessor) against their own AWS account.

## Requirements

- Python 3.14+
- [uv](https://docs.astral.sh/uv/) for dependency management
- AWS credentials with read-only access (see [`permissions`](#permissions) below for the exact policy needed)

## Install

```bash
uv sync
```

## Usage

### `scan`

Scans the account and writes the attack-path graph as JSON.

```bash
uv run aws-graph-builder scan --output graph.json
```

Credentials are resolved via boto3's standard chain (environment variables, `AWS_PROFILE`, the `default` profile, etc.) — nothing AWS-specific needs to be passed unless you want to override it:

```bash
uv run aws-graph-builder scan --profile my-profile --output graph.json
```

Useful flags:

| Flag | Meaning |
| --- | --- |
| `--output PATH` | Where to write the graph JSON (default `graph.json`) |
| `--profile NAME` | Named AWS CLI profile to use |
| `--region NAME` | Region for the STS/IAM/global-service calls themselves |
| `--regions LIST` | Comma-separated regions to scan for EC2/Lambda (default: every region enabled for the account) |
| `--cache-dir PATH` | Root directory for the on-disk API-response cache |
| `--use-cache` | Reuse anything already cached instead of re-fetching it; only what's missing is called live — useful for resuming a large or interrupted scan |
| `--verbose` / `-v` | Print each AWS call made and what it finds, live, to stdout |

`scan` covers IAM (users, groups, roles, policies, permission boundaries, identity providers, instance profiles), EC2 instances, Lambda functions (+ resource policies), S3 buckets (+ bucket policies + ACLs), and a best-effort fetch of Service Control Policies if the account is part of an AWS Organization.

Every scan also writes a companion `<output>.report.json` (e.g. `graph.report.json` alongside `graph.json`) recording which regions were covered and any gaps encountered — denied or throttled API calls don't fail the scan, they're just recorded so you know what might be missing.

### `rebuild`

Rebuilds the graph purely from a previous scan's on-disk cache — **no AWS API calls, no credentials needed at all**. Useful for iterating on graph/evaluation logic without re-scanning, or for reconstructing a graph on a machine with no AWS access.

```bash
uv run aws-graph-builder rebuild --account-id 123456789012 --cache-dir ~/.cache/aws-graph-builder --output graph.json
```

`--account-id` is required (there's no live credential session to derive it from); `--cache-dir` means the same root directory as `scan --cache-dir` — the account id is appended automatically, same as `scan`.

### `permissions`

Emits the minimal least-privilege read-only IAM policy that `scan` needs, aggregated directly from what each scanner actually calls (so it can't drift out of sync). Use this to create a scoped IAM user or role before running a real scan:

```bash
uv run aws-graph-builder permissions --output scan-policy.json
```

### `serve`

Launches a local, offline web visualizer over a previously-written `graph.json` — **no AWS calls, no credentials needed at all**, the same offline contract as `rebuild`.

```bash
uv run aws-graph-builder serve --input graph.json
```

This starts a local web server and opens the visualizer in your default browser. It renders the full graph interactively — pan/zoom, nodes colored/shaped by type, edges styled by attack-path severity (critical `PrivescPath`, serious `CanAssume`, structural everything else — `EffectivePermission` is hidden by default since it can run into the thousands on a real scan) — alongside a legend, a findings panel (filterable by severity, click a finding to pan/zoom to it and highlight its evidence edges), and a node/edge inspector (click anything for full detail, including raw policy documents). The server also exposes a JSON API for programmatic queries against the loaded graph: `GET /api/graph`, `/api/node`, `/api/edge`, `/api/findings`, general-reachability `/api/paths?source=&target=&max_hops=`, and `/api/attack-paths` — the same query restricted to just the edges that mean "traversing this gets you control of the target principal" (`CanAssume`/`PrivescPath`), including an `?target=high_value` sentinel that finds paths to any detected high-value principal (`/api/high-value-principals` lists them — an `IamUser`/`IamRole` with an unrestricted, `Resource: "*"` + `*`/`iam:*` grant, the AWS equivalent of BloodHound's Domain Admins).

Useful flags:

| Flag | Meaning |
| --- | --- |
| `--input PATH` | Path to the `graph.json` document to serve, written by `scan` or `rebuild` (default `graph.json`) |
| `--host NAME` | Host to bind the local web server to (default `127.0.0.1`) |
| `--port PORT` | Port to bind the local web server to (default `8765`) |
| `--open` / `--no-open` | Whether to automatically open the visualizer in the default browser (default: open) |

## Output format

The graph is written as JSON with `nodes` and `edges` arrays (loadable into `networkx` via `networkx.node_link_graph`), plus a `findings` array denormalizing every detected privilege-escalation path. See `aws-graph-builder.md` for the full schema, node/edge taxonomy, and the design decisions behind them.

## Development

```bash
uv run pytest          # run tests (moto-mocked; no real AWS credentials needed)
uv run ruff check .    # lint
uv run mypy src        # type check
```

See `CLAUDE.md` for architecture orientation and `aws-graph-builder.md` for the full design doc, and `tasks.md` for implementation status.
