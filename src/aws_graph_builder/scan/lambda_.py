"""Lambda scanner: fetches raw Lambda function inventory via
`lambda:ListFunctions` plus each function's resource policy via
`lambda:GetPolicy`.

Region-scoped -- Lambda has no global data, so a separate caller constructs
one `CachedClient`/one `LambdaScanner` per enabled region.

Module is named `lambda_.py` (trailing underscore) because `lambda` is a
Python keyword.

`LambdaScanResult.functions` holds raw boto3 `FunctionConfiguration` dicts
exactly as AWS returns them (PascalCase keys, e.g. `FunctionArn`, `Role`) --
no renaming or filtering -- so `graph.builder` works directly against real,
well-documented AWS API response shapes rather than an invented intermediate
format. Each function's `Role` field is the execution role's ARN, used later
to build `ExecutionRole` edges.

The overwhelming majority of functions have no resource policy at all, which
`GetPolicy` surfaces as `ResourceNotFoundException` -- that's an ordinary,
extremely common empty state, not a scan failure, so it's passed to
`CachedClient.call`'s `ignore_error_codes` to avoid cluttering gap reporting
(mirroring `iam:GetSAMLProvider`-style per-item disambiguated calls, and
`aws-graph-builder.md`'s explicit note to "treat ResourceNotFoundException as
'no policy'").
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from aws_graph_builder.scan.base import CachedClient, ScanGap, Scanner

SERVICE = "lambda"

_IGNORED_GET_POLICY_ERRORS = frozenset({"ResourceNotFoundException"})


@dataclass
class LambdaScanResult:
    region: str
    functions: list[dict[str, Any]] = field(default_factory=list)
    # Keyed by FunctionArn; value is the parsed resource policy document, or
    # None if the function has no resource policy (or the GetPolicy call
    # failed for some other reason -- both cases collapse to None here, and
    # a genuine denial is still recorded as a ScanGap via self._client.gaps).
    resource_policies: dict[str, dict[str, Any] | None] = field(default_factory=dict)
    gaps: list[ScanGap] = field(default_factory=list)


class LambdaScanner(Scanner):
    """Scans Lambda functions and their resource policies for a single
    region. Region-scoped -- a separate caller constructs one
    `CachedClient`/one `LambdaScanner` per enabled region.
    """

    def __init__(self, client: CachedClient, *, region: str) -> None:
        self._client = client
        self._region = region

    @staticmethod
    def required_actions() -> list[str]:
        return ["lambda:ListFunctions", "lambda:GetPolicy"]

    def scan(self) -> LambdaScanResult:
        self._client.report("Fetching Lambda functions...")
        page = self._client.paginate("list_functions", ["Functions"])
        functions = page["Functions"] if page else []
        self._client.report(f"  found {len(functions)} function(s)")

        resource_policies = self._scan_resource_policies(functions)

        return LambdaScanResult(
            region=self._region,
            functions=functions,
            resource_policies=resource_policies,
            # `self._client.gaps` accumulates across every call made above --
            # collect it once at the end rather than threading a list through.
            gaps=list(self._client.gaps),
        )

    def _scan_resource_policies(self, functions: list[dict[str, Any]]) -> dict[str, dict[str, Any] | None]:
        resource_policies: dict[str, dict[str, Any] | None] = {}
        for function in functions:
            arn = function["FunctionArn"]
            response = self._client.call(
                "get_policy",
                {"FunctionName": arn},
                disambiguator=arn,
                ignore_error_codes=_IGNORED_GET_POLICY_ERRORS,
            )
            if response is None:
                resource_policies[arn] = None
                continue
            # GetPolicy's `Policy` field is a JSON-encoded string, not a dict.
            resource_policies[arn] = json.loads(response["Policy"])
        return resource_policies
