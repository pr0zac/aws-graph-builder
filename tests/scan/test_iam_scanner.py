from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import boto3
import pytest
from botocore.exceptions import ClientError, TokenRetrievalError
from moto import mock_aws

from aws_graph_builder.cache.store import CacheStore
from aws_graph_builder.scan.base import CachedClient
from aws_graph_builder.scan.iam import IamScanner, IamScanResult
from aws_graph_builder.session import CredentialError, CredentialsExpiredError

TRUST_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}
PERM_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}

# moto requires >= 1000 chars for SAMLMetadataDocument.
SAML_METADATA_DOCUMENT = (
    '<?xml version="1.0"?>'
    '<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com/saml">'
    '<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">'
    '<KeyDescriptor use="signing"></KeyDescriptor>'
    "</IDPSSODescriptor>"
    "<!-- padding " + ("x" * 900) + " -->"
    "</EntityDescriptor>"
)


def _client_error(code: str, message: str = "boom", operation: str = "SomeOperation") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, operation)


def _build_fixture(iam: Any) -> dict[str, str]:
    """Creates, via real boto3 calls against moto: a group with a member
    user (attached managed policy + inline policy), a role (trust policy +
    attached policy + inline policy + permission boundary -- moto doesn't
    implement `put_user_permissions_boundary`, only the role equivalent, so
    the boundary is exercised on the role), an instance profile attached to
    that role, a SAML provider, and an OIDC provider.

    The same customer-managed policy is used as both "the attached managed
    policy" and "the customer-managed policy" fixture item -- from IAM's
    perspective a customer-managed policy attaches the same way any managed
    policy does, so this covers both without needing an AWS-managed policy
    (moto only loads the real AWS-managed policy catalog behind an opt-in
    env var, and doing so makes `GetAccountAuthorizationDetails` return
    ~1500 policies, which is irrelevant noise for this test).
    """
    iam.create_group(GroupName="admins")
    iam.create_user(UserName="alice")
    iam.add_user_to_group(GroupName="admins", UserName="alice")

    custom_policy = iam.create_policy(PolicyName="CustomPolicy", PolicyDocument=json.dumps(PERM_DOC))
    custom_policy_arn = custom_policy["Policy"]["Arn"]
    iam.attach_user_policy(UserName="alice", PolicyArn=custom_policy_arn)
    iam.put_user_policy(UserName="alice", PolicyName="InlineAlice", PolicyDocument=json.dumps(PERM_DOC))

    boundary_policy = iam.create_policy(PolicyName="BoundaryPolicy", PolicyDocument=json.dumps(PERM_DOC))
    boundary_policy_arn = boundary_policy["Policy"]["Arn"]

    iam.create_role(RoleName="deploy-role", AssumeRolePolicyDocument=json.dumps(TRUST_POLICY))
    iam.attach_role_policy(RoleName="deploy-role", PolicyArn=custom_policy_arn)
    iam.put_role_policy(RoleName="deploy-role", PolicyName="InlineRole", PolicyDocument=json.dumps(PERM_DOC))
    iam.put_role_permissions_boundary(RoleName="deploy-role", PermissionsBoundary=boundary_policy_arn)

    iam.create_instance_profile(InstanceProfileName="deploy-profile")
    iam.add_role_to_instance_profile(InstanceProfileName="deploy-profile", RoleName="deploy-role")

    saml = iam.create_saml_provider(SAMLMetadataDocument=SAML_METADATA_DOCUMENT, Name="MySaml")
    oidc = iam.create_open_id_connect_provider(
        Url="https://oidc.example.com", ThumbprintList=["a" * 40], ClientIDList=["client1"]
    )

    return {
        "custom_policy_arn": custom_policy_arn,
        "boundary_policy_arn": boundary_policy_arn,
        "saml_provider_arn": saml["SAMLProviderArn"],
        "oidc_provider_arn": oidc["OpenIDConnectProviderArn"],
    }


def _make_scanner(iam: Any, tmp_path: Path) -> tuple[IamScanner, CachedClient]:
    cache_store = CacheStore(tmp_path)
    cached_client = CachedClient(iam, cache_store, scope="global", service="iam")
    return IamScanner(cached_client), cached_client


@mock_aws
def test_scan_reflects_created_iam_fixtures(tmp_path: Path) -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    arns = _build_fixture(iam)
    scanner, _ = _make_scanner(iam, tmp_path)

    result = scanner.scan()

    assert isinstance(result, IamScanResult)
    assert result.gaps == []

    assert len(result.users) == 1
    alice = result.users[0]
    assert alice["UserName"] == "alice"
    assert alice["GroupList"] == ["admins"]
    assert alice["AttachedManagedPolicies"] == [
        {"PolicyName": "CustomPolicy", "PolicyArn": arns["custom_policy_arn"]}
    ]
    assert alice["UserPolicyList"][0]["PolicyName"] == "InlineAlice"
    assert alice["UserPolicyList"][0]["PolicyDocument"] == PERM_DOC

    assert len(result.groups) == 1
    assert result.groups[0]["GroupName"] == "admins"

    assert len(result.roles) == 1
    role = result.roles[0]
    assert role["RoleName"] == "deploy-role"
    assert role["AssumeRolePolicyDocument"] == TRUST_POLICY
    assert role["AttachedManagedPolicies"] == [{"PolicyName": "CustomPolicy", "PolicyArn": arns["custom_policy_arn"]}]
    assert role["RolePolicyList"][0]["PolicyName"] == "InlineRole"
    assert role["PermissionsBoundary"]["PermissionsBoundaryArn"] == arns["boundary_policy_arn"]

    policy_arns = {p["Arn"] for p in result.customer_managed_policies}
    assert policy_arns == {arns["custom_policy_arn"], arns["boundary_policy_arn"]}
    custom_policy = next(p for p in result.customer_managed_policies if p["Arn"] == arns["custom_policy_arn"])
    default_version = next(
        v for v in custom_policy["PolicyVersionList"] if v["VersionId"] == custom_policy["DefaultVersionId"]
    )
    assert default_version["Document"] == PERM_DOC

    assert len(result.instance_profiles) == 1
    profile = result.instance_profiles[0]
    assert profile["InstanceProfileName"] == "deploy-profile"
    assert [r["RoleName"] for r in profile["Roles"]] == ["deploy-role"]

    assert len(result.saml_providers) == 1
    assert result.saml_providers[0]["Arn"] == arns["saml_provider_arn"]
    assert "SAMLMetadataDocument" in result.saml_providers[0]

    assert len(result.oidc_providers) == 1
    assert result.oidc_providers[0]["Arn"] == arns["oidc_provider_arn"]
    assert result.oidc_providers[0]["Url"] == "oidc.example.com"


@mock_aws
def test_scan_records_gap_and_continues_on_access_denied(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    _build_fixture(iam)
    scanner, cached_client = _make_scanner(iam, tmp_path)

    def raise_access_denied(**kwargs: Any) -> None:
        raise _client_error("AccessDenied", "not authorized", operation="ListSAMLProviders")

    monkeypatch.setattr(iam, "list_saml_providers", raise_access_denied)

    result = scanner.scan()

    assert result.saml_providers == []
    assert len(result.gaps) == 1
    gap = result.gaps[0]
    assert gap.service == "iam"
    assert gap.operation == "list_saml_providers"
    assert gap.scope == "global"
    assert gap.error_code == "AccessDenied"

    # The rest of the scan still ran and produced real data.
    assert len(result.users) == 1
    assert len(result.roles) == 1
    assert len(result.oidc_providers) == 1

    cached = cached_client._cache_store.get("global", "iam", "list_saml_providers")
    assert cached is not None
    assert cached.error == {"code": "AccessDenied", "message": "not authorized"}


@mock_aws
def test_scan_raises_credentials_expired_error_instead_of_recording_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    iam = boto3.client("iam", region_name="us-east-1")
    _build_fixture(iam)
    scanner, _ = _make_scanner(iam, tmp_path)

    def raise_expired_token(**kwargs: Any) -> None:
        raise _client_error("ExpiredToken", "token is expired", operation="ListOpenIDConnectProviders")

    monkeypatch.setattr(iam, "list_open_id_connect_providers", raise_expired_token)

    with pytest.raises(CredentialsExpiredError):
        scanner.scan()


@mock_aws
def test_scan_raises_credential_error_on_botocore_error_instead_of_recording_gap(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Regression test: a client-side credential-*resolution* failure mid-scan
    (e.g. an SSO session expiring between calls) surfaces from botocore as a
    `BotoCoreError` subclass, not a `ClientError` -- this must abort the scan
    via `CredentialError` rather than being swallowed as an ordinary
    per-resource `ScanGap` (which represents an AWS-side denial, not a
    client-side inability to even make the call).
    """
    iam = boto3.client("iam", region_name="us-east-1")
    _build_fixture(iam)
    scanner, _ = _make_scanner(iam, tmp_path)

    def raise_token_retrieval_error(**kwargs: Any) -> None:
        raise TokenRetrievalError(provider="sso", error_msg="Token has expired and refresh failed")

    monkeypatch.setattr(iam, "list_instance_profiles", raise_token_retrieval_error)

    with pytest.raises(CredentialError) as exc_info:
        scanner.scan()

    assert not isinstance(exc_info.value, CredentialsExpiredError)
