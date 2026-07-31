"""Pure, I/O-free matching functions for IAM's wildcard semantics and
condition-block static resolvability. No dependency on `policy_document.py`'s
dataclasses -- everything here operates on plain strings/dicts so it's
trivially unit-testable and reusable from both `simulator.py` (pattern-vs-
pattern comparisons for boundary/deny intersection) and `trust.py`.
"""

from __future__ import annotations

import re
from typing import Any


def _wildcard_to_regex(pattern: str) -> re.Pattern[str]:
    """Translate an IAM wildcard pattern (`*` = any sequence, `?` = any
    single character) into a compiled, case-insensitive, fully-anchored
    regex. Both `action_matches` and `resource_matches` share this: IAM's
    wildcard grammar is identical for both Action and Resource patterns.
    """
    parts = []
    for char in pattern:
        if char == "*":
            parts.append(".*")
        elif char == "?":
            parts.append(".")
        else:
            parts.append(re.escape(char))
    return re.compile("^" + "".join(parts) + "$", re.IGNORECASE)


def action_matches(pattern: str, action: str) -> bool:
    """True if `pattern` (an IAM Action pattern, e.g. `"iam:*"`, `"s3:Get*"`,
    bare `"*"`) matches `action` (a concrete or another pattern-shaped
    action string). IAM action matching is case-insensitive, and `*` matches
    any sequence of characters including across the `service:` separator
    (e.g. `"*"` alone matches every action of every service).
    """
    return bool(_wildcard_to_regex(pattern).match(action))


def resource_matches(pattern: str, arn: str) -> bool:
    """True if `pattern` (an IAM Resource pattern) matches `arn`.

    Known limitation, not a bug: IAM policy variables (e.g.
    `${aws:username}`) are explicitly out of scope for this offline, static
    tool (there's no live request context to substitute them from) -- a
    pattern containing a literal `${` is treated as non-matching rather than
    attempting substitution.
    """
    if "${" in pattern:
        return False
    return bool(_wildcard_to_regex(pattern).match(arn))


def condition_matches(conditions: dict[str, dict[str, Any]]) -> bool | None:
    """Evaluate a `Condition` block using ONLY what's staticly resolvable
    without a live request context (no real source IP, timestamp, MFA
    status, etc. exists in this offline tool).

    Returns:
      - `True` for an empty conditions dict (trivially satisfied -- there's
        nothing to check).
      - `None` ("unresolved") for any non-empty conditions dict. This is
        deliberately conservative: we don't know the caller's MFA status, IP,
        tags, etc. ahead of time, so we never guess `True` or `False` for a
        real condition. Callers (`simulator.py`) treat `None` as "this
        grant/deny might or might not apply" and surface it via
        `condition_unresolved: true` rather than silently assuming either
        way.
    """
    if not conditions:
        return True
    return None
