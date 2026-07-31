"""Raw IAM policy JSON -> normalized `PolicyDocument`/`Statement` dataclasses.

AWS's policy JSON grammar allows several fields to be either a single string
or a list of strings (`Action`, `NotAction`, `Resource`, `NotResource`), and
allows `Resource`/`NotResource` to be omitted entirely in statements where the
resource is implicit -- which happens in practice in trust policies (an
`AssumeRolePolicyDocument` statement grants `sts:AssumeRole` on "this role",
never on an explicit ARN). This module normalizes all of that into consistent
`list[str]` fields so `eval/matcher.py` and `eval/simulator.py` never have to
special-case "is this a string or a list" or "is this field present at all".

Every `Statement` carries a `source` string identifying which policy document
it came from, propagated from the `PolicyDocument.source` passed to
`parse_policy_document`. Convention used throughout this package (callers in
`engine.py`/`trust.py` are responsible for constructing the right string):
  - a customer-managed or AWS-managed policy attached to a principal: the
    policy's ARN, e.g. ``"arn:aws:iam::111111111111:policy/MyPolicy"``.
  - an inline policy: ``f"inline:{owner_arn}#{policy_name}"``.
  - a permission boundary: ``f"boundary:{policy_arn}"``.
  - a role's trust policy: ``f"trust:{role_arn}"``.

Every malformed-input check below deliberately raises `ValueError`, not
`TypeError` (overriding ruff's TRY004 preference, silenced inline where it
fires): a shape mismatch here means "this is not valid IAM policy JSON", a
data-validation failure callers are expected to catch and treat as an
unparseable policy -- not a Python API misuse bug.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class Statement:
    """A single normalized IAM policy statement.

    `effect` is kept as a plain `str` (not a `Literal`/enum) rather than
    validated against `{"Allow", "Deny"}` here -- malformed real-world
    policies can and do contain garbage, and it's `simulator.py`'s job (which
    only ever compares `effect == "Allow"` / `"Deny"`) to treat anything else
    as neither, not this module's job to reject it.
    """

    sid: str | None
    effect: str
    actions: list[str]
    not_actions: list[str]
    resources: list[str]
    not_resources: list[str]
    conditions: dict[str, dict[str, Any]]
    principal: dict[str, Any] | None
    source: str


@dataclass
class PolicyDocument:
    statements: list[Statement] = field(default_factory=list)
    source: str = ""


def _as_str_list(value: Any, *, field_name: str) -> list[str]:
    """Normalize an Action/NotAction/Resource/NotResource value (single
    string or list of strings) into `list[str]`. Raises `ValueError` for
    anything else, since a policy statement with e.g. a dict or number in
    one of these fields is malformed and unparseable.
    """
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        if not all(isinstance(item, str) for item in value):
            raise ValueError(f"Statement field {field_name!r} contains a non-string list item: {value!r}")
        return list(value)
    raise ValueError(f"Statement field {field_name!r} must be a string or list of strings, got {value!r}")


def _parse_statement(raw: dict[str, Any], *, source: str) -> Statement:
    if not isinstance(raw, dict):
        # ValueError (not TypeError) is intentional: this is malformed *policy
        # data*, not a Python API misuse -- callers are meant to catch
        # ValueError to skip an unparseable policy. noqa: TRY004
        raise ValueError(f"Statement must be a dict, got {raw!r}")  # noqa: TRY004

    effect = raw.get("Effect")
    if not isinstance(effect, str):
        raise ValueError(f"Statement missing a string 'Effect': {raw!r}")  # noqa: TRY004

    has_action = "Action" in raw
    has_not_action = "NotAction" in raw
    actions = _as_str_list(raw["Action"], field_name="Action") if has_action else []
    not_actions = _as_str_list(raw["NotAction"], field_name="NotAction") if has_not_action else []

    has_resource = "Resource" in raw
    has_not_resource = "NotResource" in raw
    if has_resource:
        resources = _as_str_list(raw["Resource"], field_name="Resource")
    else:
        # Resource is commonly omitted in trust policies, where the resource
        # is implicitly "this role" -- normalize to a "matches anything"
        # wildcard rather than an empty list, which would otherwise make
        # every resource_matches() check trivially False.
        resources = ["*"]
    not_resources = _as_str_list(raw["NotResource"], field_name="NotResource") if has_not_resource else []

    condition_raw = raw.get("Condition", {})
    if not isinstance(condition_raw, dict):
        raise ValueError(f"Statement field 'Condition' must be a dict, got {condition_raw!r}")  # noqa: TRY004

    principal = raw.get("Principal")
    if principal is not None and not isinstance(principal, (dict, str)):
        raise ValueError(f"Statement field 'Principal' must be a dict, string, or absent, got {principal!r}")
    # Normalize the bare-string principal form (e.g. `"Principal": "*"`) to a
    # dict shape so downstream callers (trust.py) only ever handle one shape.
    if isinstance(principal, str):
        principal = {"__raw__": principal}

    sid = raw.get("Sid")
    if sid is not None and not isinstance(sid, str):
        raise ValueError(f"Statement field 'Sid' must be a string or absent, got {sid!r}")

    return Statement(
        sid=sid,
        effect=effect,
        actions=actions,
        not_actions=not_actions,
        resources=resources,
        not_resources=not_resources,
        conditions=condition_raw,
        principal=principal,
        source=source,
    )


def parse_policy_document(raw: dict[str, Any], *, source: str) -> PolicyDocument:
    """Parse a raw IAM policy document dict (as returned by boto3, e.g.
    `PolicyDocument`/`AssumeRolePolicyDocument`) into a `PolicyDocument`.

    Raises `ValueError` for a missing/malformed `Statement` key or any
    statement that fails to normalize -- callers (`engine.py`/`trust.py`) are
    responsible for catching this and treating the offending policy as
    unparseable/excluded rather than letting it crash the whole scan.
    """
    if not isinstance(raw, dict):
        raise ValueError(f"Policy document must be a dict, got {raw!r}")  # noqa: TRY004

    raw_statements = raw.get("Statement")
    if raw_statements is None:
        raise ValueError(f"Policy document missing required 'Statement' key: {raw!r}")
    if isinstance(raw_statements, dict):
        # A single statement, not wrapped in a list -- valid per the IAM
        # policy grammar.
        raw_statements = [raw_statements]
    if not isinstance(raw_statements, list):
        raise ValueError(  # noqa: TRY004
            f"Policy document field 'Statement' must be a dict or list of dicts, got {raw_statements!r}"
        )

    statements = [_parse_statement(item, source=source) for item in raw_statements]
    return PolicyDocument(statements=statements, source=source)
