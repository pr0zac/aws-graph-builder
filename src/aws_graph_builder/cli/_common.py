"""Shared CLI plumbing used by both `scan_cmd.py` and `rebuild_cmd.py`:
console instances, the default cache directory, and the JSON serialization
hook for datetime-bearing raw AWS response fragments.
"""

from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path
from typing import Any

from rich.console import Console

CACHE_DIR_ENV_VAR = "AWS_GRAPH_BUILDER_CACHE_DIR"

# `highlight=False`: rich's automatic highlighting wraps numbers and
# parenthesized text in their own ANSI spans (e.g. "1 user(s)" becomes
# several separately-styled fragments), which is unwanted for these
# plain progress/status/error messages.
stderr_console = Console(stderr=True, highlight=False)
stdout_console = Console(highlight=False)


def json_default(obj: Any) -> Any:
    """`json.dumps(default=...)` hook: node/edge properties (and, for
    `rebuild`, replayed cache entries) are raw boto3 response fragments,
    which may still contain `datetime` values (e.g. `CreateDate`) --
    serialize those as ISO 8601 strings, same convention as
    `cache.store`'s cache-entry serialization.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


def default_cache_dir() -> Path:
    """Root cache directory before the account-id subdirectory is appended.

    Per aws-graph-builder.md's "Disk cache" section: `$AWS_GRAPH_BUILDER_CACHE_DIR`
    if set, else `~/.cache/aws-graph-builder`.
    """
    override = os.environ.get(CACHE_DIR_ENV_VAR)
    if override:
        return Path(override)
    return Path.home() / ".cache" / "aws-graph-builder"
