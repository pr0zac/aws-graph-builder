"""Organizations scanner: best-effort Service Control Policy (SCP) fetch.

Global-scoped -- Organizations has no per-region data. Most AWS accounts
being scanned either aren't part of an Organization at all, or the scanning
credentials lack Organizations permissions (it's a sensitive, account-wide
API) -- both are completely normal, expected outcomes, not failures, so this
scanner degrades gracefully to `in_organization=False` rather than erroring.

`OrganizationsScanResult.policies` holds raw boto3 policy summary dicts from
`ListPoliciesForTarget` exactly as AWS returns them (PascalCase keys, e.g.
`Id`, `Arn`, `Name`) -- no renaming -- so `graph.builder` works directly
against real, well-documented AWS API response shapes rather than an invented
intermediate format. `policy_documents` is the one exception: `DescribePolicy`
returns its `Content` as a JSON-encoded string, which is parsed here so
downstream consumers get a normal dict.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from aws_graph_builder.scan.base import CachedClient, ScanGap, Scanner

SERVICE = "organizations"
SCOPE = "global"


@dataclass
class OrganizationsScanResult:
    in_organization: bool
    policies: list[dict[str, Any]] = field(default_factory=list)
    policy_documents: dict[str, dict[str, Any]] = field(default_factory=dict)
    gaps: list[ScanGap] = field(default_factory=list)


class OrganizationsScanner(Scanner):
    """Best-effort scan of Service Control Policies attached to the scanned
    account. Global-scoped -- Organizations has no per-region data.
    """

    def __init__(self, client: CachedClient, *, account_id: str) -> None:
        self._client = client
        self._account_id = account_id

    @staticmethod
    def required_actions() -> list[str]:
        return [
            "organizations:DescribeOrganization",
            "organizations:ListPoliciesForTarget",
            "organizations:DescribePolicy",
        ]

    def scan(self) -> OrganizationsScanResult:
        self._client.report("Checking AWS Organizations membership...")
        organization = self._client.call(
            "describe_organization",
            ignore_error_codes=frozenset({"AWSOrganizationsNotInUseException", "AccessDeniedException"}),
        )
        if organization is None:
            self._client.report(
                "  account is not part of an AWS Organization (or lacks permission to check) -- skipping SCP scan"
            )
            return OrganizationsScanResult(
                in_organization=False,
                policies=[],
                policy_documents={},
                gaps=list(self._client.gaps),
            )

        self._client.report("Fetching Service Control Policies attached to this account...")
        policies_page = self._client.paginate(
            "list_policies_for_target",
            ["Policies"],
            {"TargetId": self._account_id, "Filter": "SERVICE_CONTROL_POLICY"},
        )
        policies = policies_page["Policies"] if policies_page else []
        self._client.report(f"  found {len(policies)} Service Control Polic{'y' if len(policies) == 1 else 'ies'}")

        policy_documents = self._scan_policy_documents(policies)

        return OrganizationsScanResult(
            in_organization=True,
            policies=policies,
            policy_documents=policy_documents,
            # `self._client.gaps` accumulates across every call made above --
            # collect it once at the end rather than threading a list through.
            gaps=list(self._client.gaps),
        )

    def _scan_policy_documents(self, policies: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
        policy_documents: dict[str, dict[str, Any]] = {}
        for policy in policies:
            policy_id = policy["Id"]
            detail = self._client.call("describe_policy", {"PolicyId": policy_id}, disambiguator=policy_id)
            if detail is None:
                continue
            policy_documents[policy_id] = json.loads(detail["Policy"]["Content"])
        return policy_documents
