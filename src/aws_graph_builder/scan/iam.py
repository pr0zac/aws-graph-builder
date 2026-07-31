"""IAM scanner: fetches the raw IAM inventory via `iam:GetAccountAuthorizationDetails`
plus SAML/OIDC identity providers and instance profiles.

Every list on `IamScanResult` holds raw boto3 response items exactly as AWS
returns them (PascalCase keys, e.g. `UserName`, `Arn`, `AttachedManagedPolicies`)
-- no renaming or snake_casing -- so `graph.builder` works directly against
real, well-documented AWS API response shapes rather than an invented
intermediate format.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from aws_graph_builder.scan.base import CachedClient, ScanGap, Scanner

SERVICE = "iam"
SCOPE = "global"


@dataclass
class IamScanResult:
    users: list[dict[str, Any]] = field(default_factory=list)
    groups: list[dict[str, Any]] = field(default_factory=list)
    roles: list[dict[str, Any]] = field(default_factory=list)
    customer_managed_policies: list[dict[str, Any]] = field(default_factory=list)
    saml_providers: list[dict[str, Any]] = field(default_factory=list)
    oidc_providers: list[dict[str, Any]] = field(default_factory=list)
    instance_profiles: list[dict[str, Any]] = field(default_factory=list)
    gaps: list[ScanGap] = field(default_factory=list)


class IamScanner(Scanner):
    """Scans IAM users/groups/roles/policies, identity providers, and
    instance profiles for a single account. Global-scoped -- IAM has no
    per-region data.
    """

    def __init__(self, client: CachedClient) -> None:
        self._client = client

    @staticmethod
    def required_actions() -> list[str]:
        return [
            "iam:GetAccountAuthorizationDetails",
            "iam:ListSAMLProviders",
            "iam:GetSAMLProvider",
            "iam:ListOpenIDConnectProviders",
            "iam:GetOpenIDConnectProvider",
            "iam:ListInstanceProfiles",
        ]

    def scan(self) -> IamScanResult:
        auth_details = self._client.paginate(
            "get_account_authorization_details",
            ["UserDetailList", "GroupDetailList", "RoleDetailList", "Policies"],
        )
        users = auth_details["UserDetailList"] if auth_details else []
        groups = auth_details["GroupDetailList"] if auth_details else []
        roles = auth_details["RoleDetailList"] if auth_details else []
        customer_managed_policies = auth_details["Policies"] if auth_details else []

        saml_providers = self._scan_saml_providers()
        oidc_providers = self._scan_oidc_providers()

        instance_profiles_page = self._client.paginate("list_instance_profiles", ["InstanceProfiles"])
        instance_profiles = instance_profiles_page["InstanceProfiles"] if instance_profiles_page else []

        return IamScanResult(
            users=users,
            groups=groups,
            roles=roles,
            customer_managed_policies=customer_managed_policies,
            saml_providers=saml_providers,
            oidc_providers=oidc_providers,
            instance_profiles=instance_profiles,
            # `self._client.gaps` accumulates across every call made above --
            # collect it once at the end rather than threading a list through.
            gaps=list(self._client.gaps),
        )

    def _scan_saml_providers(self) -> list[dict[str, Any]]:
        list_response = self._client.call("list_saml_providers")
        if list_response is None:
            return []

        providers = []
        for entry in list_response.get("SAMLProviderList", []):
            arn = entry.get("Arn")
            if not arn:
                continue
            # GetSAMLProvider's response doesn't echo back the ARN, so merge
            # it in from the List call -- the graph builder needs it.
            detail = self._client.call("get_saml_provider", {"SAMLProviderArn": arn}, disambiguator=arn)
            if detail is None:
                continue
            providers.append({**detail, "Arn": arn})
        return providers

    def _scan_oidc_providers(self) -> list[dict[str, Any]]:
        list_response = self._client.call("list_open_id_connect_providers")
        if list_response is None:
            return []

        providers = []
        for entry in list_response.get("OpenIDConnectProviderList", []):
            arn = entry.get("Arn")
            if not arn:
                continue
            # Same as GetSAMLProvider above: GetOpenIDConnectProvider doesn't
            # echo back the ARN either.
            detail = self._client.call("get_open_id_connect_provider", {"OpenIDConnectProviderArn": arn}, disambiguator=arn)
            if detail is None:
                continue
            providers.append({**detail, "Arn": arn})
        return providers
