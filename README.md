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

This starts a local, offline investigation workspace and opens it in your browser. All assets ship with the Python package; Node.js and internet access are not needed to view a graph.

- **Explore:** search principals by name, type, or ARN, open a neighborhood, and explicitly expand connections. Large expansions offer a selectable preview capped at 50 new nodes per action. An account overview remains available.
- **Findings:** search and group detected techniques; filter by severity, technique, source/target, either endpoint, and whether the source already has high-value access. Open a finding to inspect its supporting relationships.
- **Paths:** select endpoints or ask for routes to any high-value principal. Attack paths traverse only `CanAssume` and `PrivescPath`; general reachability is a separate mode. Select an individual route, inspect each hop's alternative techniques, or explicitly combine returned routes.
- **Inspector:** node/relationship selection preserves the current graph. Details include required permissions, policy references and statements where available, unresolved conditions, and a secondary raw JSON view. Use **Back** to restore the prior graph, including its positions and viewport.

The header shows account/scan context and coverage from a companion report such as `graph.report.json`. Missing or unreadable reports display **coverage unknown**. Effective permissions and AWS-default plumbing are hidden during exploration unless enabled; focused evidence temporarily reveals required items. Hide/restore, graph filters, Fit/Re-layout/Reset, resizable inspection, and System/Light/Dark themes are available. Press `/` for global search.

The new `GET /api/viewer` endpoint supplies compact metadata and render data. `GET /api/routes?source=&target=&mode=attack&max_hops=6` returns unique node routes, shortest first, retaining parallel edge IDs as alternatives per hop. Queries cap hops at 10 and results at 200, with additional budgets of 25,000 examined transitions and 0.5 seconds of traversal. Responses distinguish complete, truncated, interrupted, and already-at-target results. Counts represent unique node sequences, not technique permutations. Static policy analysis and unresolved conditions still require review; a detected route is not a live exploit verification.

Existing read-only endpoints remain compatible: `/api/graph`, `/api/node`, `/api/edge`, `/api/findings`, `/api/paths`, `/api/attack-paths`, and `/api/high-value-principals`. The legacy path endpoints retain their existing multigraph enumeration behavior; new clients should use `/api/routes` for bounded, unique-route queries.

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

### Viewer development checks

Pure frontend logic uses Node's built-in test runner (development only):

```bash
node --test tests/web/frontend/*.test.mjs
```

Browser tests are opt-in and use fictional account fixtures:

```bash
uv run playwright install chromium
uv run pytest tests/web/test_viewer_browser.py --run-browser
```

Use `--browser-executable=/path/to/chromium` for an existing compatible browser, `--viewer-screenshots=/tmp/viewer-qa` to save screenshots, or `--live-graph=/path/to/graph.json` to include the optional local-artifact smoke test. Live account data is never included in committed fixtures. Ordinary `uv run pytest` skips browser tests. Validate distribution assets with `uv build`.
