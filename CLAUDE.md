# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project status

Phase 0 (packaging groundwork) is complete: the repo is now a `src/`-layout installable package (`src/aws_graph_builder/`), with a Typer CLI entry point wired up (`uv run aws-graph-builder`), and runtime (boto3, networkx, typer, rich) plus dev (moto, pytest, pytest-cov, ruff, mypy) dependencies installed. No scanning/graph/evaluation logic exists yet — see `tasks.md` for what's next (Phase 1: IAM-only vertical slice).

## Commands

- `uv run aws-graph-builder` — run the CLI (currently a placeholder `version` command; collapses to single-command mode until more subcommands are added in later phases)
- `uv run pytest` — run tests
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
