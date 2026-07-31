from __future__ import annotations

import networkx as nx

from aws_graph_builder.graph.builder import build_iam_graph
from aws_graph_builder.graph.schema import (
    EdgeType,
    NodeType,
    inline_policy_id,
    make_edge_id,
)
from aws_graph_builder.scan.iam import IamScanResult

ACCOUNT_ID = "111111111111"
ACCOUNT_ARN = f"arn:aws:iam::{ACCOUNT_ID}:root"

ALICE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/alice"
BOB_ARN = f"arn:aws:iam::{ACCOUNT_ID}:user/bob"
GROUP_ARN = f"arn:aws:iam::{ACCOUNT_ID}:group/admins"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/deploy-role"

CUSTOMER_POLICY_ARN = f"arn:aws:iam::{ACCOUNT_ID}:policy/CustomPolicy"
AWS_MANAGED_POLICY_ARN = "arn:aws:iam::aws:policy/ReadOnlyAccess"
UNSEEN_BOUNDARY_POLICY_ARN = "arn:aws:iam::aws:policy/AdministratorAccess"

INSTANCE_PROFILE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:instance-profile/deploy-profile"
SAML_PROVIDER_ARN = f"arn:aws:iam::{ACCOUNT_ID}:saml-provider/MySaml"
OIDC_PROVIDER_ARN = f"arn:aws:iam::{ACCOUNT_ID}:oidc-provider/oidc.example.com"

PERM_DOC = {"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "s3:*", "Resource": "*"}]}
TRUST_DOC = {
    "Version": "2012-10-17",
    "Statement": [{"Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"}, "Action": "sts:AssumeRole"}],
}


def _build_scan_result() -> IamScanResult:
    """Hand-built raw IAM data (real botocore/AWS response shapes) covering:
    - a user (alice) in a group, with an AWS-managed attached policy, an
      inline policy, and a permission boundary that references a policy not
      otherwise present anywhere else in the scan.
    - bob, attached to the *same* AWS-managed policy as alice, to exercise
      AWS-managed-policy dedup (one node, two AttachedPolicy edges).
    - a role with a trust policy, the customer-managed policy attached, and
      an inline policy.
    - a customer-managed policy with two versions (only the default's
      document should end up on the node).
    - an instance profile attached to the role.
    - a SAML and an OIDC identity provider.
    """
    return IamScanResult(
        users=[
            {
                "Path": "/",
                "UserName": "alice",
                "UserId": "AIDAALICE",
                "Arn": ALICE_ARN,
                "CreateDate": "2026-01-01T00:00:00+00:00",
                "UserPolicyList": [{"PolicyName": "InlineAlice", "PolicyDocument": PERM_DOC}],
                "GroupList": ["admins"],
                "AttachedManagedPolicies": [
                    {"PolicyName": "ReadOnlyAccess", "PolicyArn": AWS_MANAGED_POLICY_ARN}
                ],
                "PermissionsBoundary": {
                    "PermissionsBoundaryType": "PermissionsBoundaryPolicy",
                    "PermissionsBoundaryArn": UNSEEN_BOUNDARY_POLICY_ARN,
                },
            },
            {
                "Path": "/",
                "UserName": "bob",
                "UserId": "AIDABOB",
                "Arn": BOB_ARN,
                "CreateDate": "2026-01-01T00:00:00+00:00",
                "UserPolicyList": [],
                "GroupList": [],
                "AttachedManagedPolicies": [
                    {"PolicyName": "ReadOnlyAccess", "PolicyArn": AWS_MANAGED_POLICY_ARN}
                ],
            },
        ],
        groups=[
            {
                "Path": "/",
                "GroupName": "admins",
                "GroupId": "AGPADMINS",
                "Arn": GROUP_ARN,
                "CreateDate": "2026-01-01T00:00:00+00:00",
                "GroupPolicyList": [],
                "AttachedManagedPolicies": [],
            }
        ],
        roles=[
            {
                "Path": "/",
                "RoleName": "deploy-role",
                "RoleId": "AROADEPLOY",
                "Arn": ROLE_ARN,
                "CreateDate": "2026-01-01T00:00:00+00:00",
                "AssumeRolePolicyDocument": TRUST_DOC,
                "RolePolicyList": [{"PolicyName": "InlineRole", "PolicyDocument": PERM_DOC}],
                "AttachedManagedPolicies": [{"PolicyName": "CustomPolicy", "PolicyArn": CUSTOMER_POLICY_ARN}],
                "InstanceProfileList": [],
            }
        ],
        customer_managed_policies=[
            {
                "PolicyName": "CustomPolicy",
                "PolicyId": "ANPACUSTOM",
                "Arn": CUSTOMER_POLICY_ARN,
                "Path": "/",
                "DefaultVersionId": "v2",
                "AttachmentCount": 1,
                "IsAttachable": True,
                "CreateDate": "2026-01-01T00:00:00+00:00",
                "UpdateDate": "2026-01-02T00:00:00+00:00",
                "PolicyVersionList": [
                    {
                        "VersionId": "v1",
                        "IsDefaultVersion": False,
                        "Document": {"Version": "2012-10-17", "Statement": []},
                        "CreateDate": "2026-01-01T00:00:00+00:00",
                    },
                    {
                        "VersionId": "v2",
                        "IsDefaultVersion": True,
                        "Document": PERM_DOC,
                        "CreateDate": "2026-01-02T00:00:00+00:00",
                    },
                ],
            }
        ],
        saml_providers=[
            {
                "Arn": SAML_PROVIDER_ARN,
                "SAMLMetadataDocument": "<EntityDescriptor .../>",
                "CreateDate": "2026-01-01T00:00:00+00:00",
                "ValidUntil": "2030-01-01T00:00:00+00:00",
            }
        ],
        oidc_providers=[
            {
                "Arn": OIDC_PROVIDER_ARN,
                "Url": "oidc.example.com",
                "ClientIDList": ["client1"],
                "ThumbprintList": ["a" * 40],
                "CreateDate": "2026-01-01T00:00:00+00:00",
            }
        ],
        instance_profiles=[
            {
                "Path": "/",
                "InstanceProfileName": "deploy-profile",
                "InstanceProfileId": "AIPADEPLOY",
                "Arn": INSTANCE_PROFILE_ARN,
                "CreateDate": "2026-01-01T00:00:00+00:00",
                "Roles": [{"Arn": ROLE_ARN, "RoleName": "deploy-role"}],
            }
        ],
        gaps=[],
    )


def _build_graph() -> nx.MultiDiGraph:
    return build_iam_graph(_build_scan_result(), account_id=ACCOUNT_ID)


def test_account_node_present() -> None:
    graph = _build_graph()
    assert graph.nodes[ACCOUNT_ARN]["type"] == NodeType.ACCOUNT.value
    assert graph.nodes[ACCOUNT_ARN]["name"] == ACCOUNT_ID


def test_user_group_role_nodes_created_with_properties() -> None:
    graph = _build_graph()

    assert graph.nodes[ALICE_ARN]["type"] == NodeType.IAM_USER.value
    assert graph.nodes[ALICE_ARN]["name"] == "alice"
    assert graph.nodes[ALICE_ARN]["properties"]["UserId"] == "AIDAALICE"
    # Raw fields not otherwise modeled land in properties.
    assert graph.nodes[ALICE_ARN]["properties"]["Path"] == "/"

    assert graph.nodes[GROUP_ARN]["type"] == NodeType.IAM_GROUP.value
    assert graph.nodes[GROUP_ARN]["name"] == "admins"

    assert graph.nodes[ROLE_ARN]["type"] == NodeType.IAM_ROLE.value
    assert graph.nodes[ROLE_ARN]["name"] == "deploy-role"
    # AssumeRolePolicyDocument is retained for a later phase's trust evaluation.
    assert graph.nodes[ROLE_ARN]["properties"]["AssumeRolePolicyDocument"] == TRUST_DOC


def test_member_of_edge() -> None:
    graph = _build_graph()
    edge_id = make_edge_id(EdgeType.MEMBER_OF, ALICE_ARN, GROUP_ARN)
    assert graph.has_edge(ALICE_ARN, GROUP_ARN, key=edge_id)
    assert graph[ALICE_ARN][GROUP_ARN][edge_id]["type"] == EdgeType.MEMBER_OF.value
    # bob is not in any group.
    assert graph.out_degree(BOB_ARN) == 1  # only the AttachedPolicy edge


def test_customer_managed_policy_node_has_default_version_document() -> None:
    graph = _build_graph()
    node = graph.nodes[CUSTOMER_POLICY_ARN]
    assert node["type"] == NodeType.MANAGED_POLICY.value
    assert node["properties"]["managed_by"] == "customer"
    assert node["properties"]["policy_document"] == PERM_DOC
    # The non-default version's document should not leak in as *the* document.
    assert node["properties"]["policy_document"] != {"Version": "2012-10-17", "Statement": []}


def test_aws_managed_policy_attached_to_two_principals_dedupes_to_one_node() -> None:
    graph = _build_graph()

    assert graph.nodes[AWS_MANAGED_POLICY_ARN]["type"] == NodeType.MANAGED_POLICY.value
    assert graph.nodes[AWS_MANAGED_POLICY_ARN]["properties"]["managed_by"] == "aws"
    assert "policy_document" not in graph.nodes[AWS_MANAGED_POLICY_ARN]["properties"]

    # Exactly one ManagedPolicy node for this ARN...
    managed_policy_nodes = [
        node_id
        for node_id, data in graph.nodes(data=True)
        if data["type"] == NodeType.MANAGED_POLICY.value and node_id == AWS_MANAGED_POLICY_ARN
    ]
    assert managed_policy_nodes == [AWS_MANAGED_POLICY_ARN]

    # ...but two AttachedPolicy edges into it, one per principal.
    alice_edge_id = make_edge_id(EdgeType.ATTACHED_POLICY, ALICE_ARN, AWS_MANAGED_POLICY_ARN)
    bob_edge_id = make_edge_id(EdgeType.ATTACHED_POLICY, BOB_ARN, AWS_MANAGED_POLICY_ARN)
    assert graph.has_edge(ALICE_ARN, AWS_MANAGED_POLICY_ARN, key=alice_edge_id)
    assert graph.has_edge(BOB_ARN, AWS_MANAGED_POLICY_ARN, key=bob_edge_id)
    assert graph.in_degree(AWS_MANAGED_POLICY_ARN) == 2


def test_permission_boundary_references_unseen_policy_creates_placeholder_node() -> None:
    graph = _build_graph()

    assert UNSEEN_BOUNDARY_POLICY_ARN in graph.nodes
    node = graph.nodes[UNSEEN_BOUNDARY_POLICY_ARN]
    assert node["type"] == NodeType.MANAGED_POLICY.value
    assert node["properties"]["managed_by"] == "aws"
    assert node["name"] == "AdministratorAccess"

    edge_id = make_edge_id(EdgeType.HAS_PERMISSION_BOUNDARY, ALICE_ARN, UNSEEN_BOUNDARY_POLICY_ARN)
    assert graph.has_edge(ALICE_ARN, UNSEEN_BOUNDARY_POLICY_ARN, key=edge_id)
    assert graph[ALICE_ARN][UNSEEN_BOUNDARY_POLICY_ARN][edge_id]["type"] == EdgeType.HAS_PERMISSION_BOUNDARY.value


def test_inline_policy_nodes_and_edges() -> None:
    graph = _build_graph()

    alice_inline_id = inline_policy_id(ALICE_ARN, "InlineAlice")
    assert graph.nodes[alice_inline_id]["type"] == NodeType.INLINE_POLICY.value
    assert graph.nodes[alice_inline_id]["arn"] is None
    assert graph.nodes[alice_inline_id]["properties"]["policy_document"] == PERM_DOC

    edge_id = make_edge_id(EdgeType.HAS_INLINE_POLICY, ALICE_ARN, alice_inline_id)
    assert graph.has_edge(ALICE_ARN, alice_inline_id, key=edge_id)

    role_inline_id = inline_policy_id(ROLE_ARN, "InlineRole")
    assert graph.nodes[role_inline_id]["properties"]["policy_document"] == PERM_DOC
    role_edge_id = make_edge_id(EdgeType.HAS_INLINE_POLICY, ROLE_ARN, role_inline_id)
    assert graph.has_edge(ROLE_ARN, role_inline_id, key=role_edge_id)


def test_role_attached_customer_policy_edge() -> None:
    graph = _build_graph()
    edge_id = make_edge_id(EdgeType.ATTACHED_POLICY, ROLE_ARN, CUSTOMER_POLICY_ARN)
    assert graph.has_edge(ROLE_ARN, CUSTOMER_POLICY_ARN, key=edge_id)


def test_instance_profile_node_and_attached_to_edge() -> None:
    graph = _build_graph()

    assert graph.nodes[INSTANCE_PROFILE_ARN]["type"] == NodeType.INSTANCE_PROFILE.value
    assert graph.nodes[INSTANCE_PROFILE_ARN]["name"] == "deploy-profile"

    edge_id = make_edge_id(EdgeType.ATTACHED_TO, INSTANCE_PROFILE_ARN, ROLE_ARN)
    assert graph.has_edge(INSTANCE_PROFILE_ARN, ROLE_ARN, key=edge_id)
    assert graph[INSTANCE_PROFILE_ARN][ROLE_ARN][edge_id]["type"] == EdgeType.ATTACHED_TO.value


def test_identity_provider_nodes() -> None:
    graph = _build_graph()

    assert graph.nodes[SAML_PROVIDER_ARN]["type"] == NodeType.IDENTITY_PROVIDER.value
    assert graph.nodes[SAML_PROVIDER_ARN]["properties"]["provider_type"] == "saml"

    assert graph.nodes[OIDC_PROVIDER_ARN]["type"] == NodeType.IDENTITY_PROVIDER.value
    assert graph.nodes[OIDC_PROVIDER_ARN]["properties"]["provider_type"] == "oidc"
    assert graph.nodes[OIDC_PROVIDER_ARN]["name"] == "oidc.example.com"


def test_no_can_assume_or_identifies_via_edges_created() -> None:
    """Phase 1 stores AssumeRolePolicyDocument raw but doesn't evaluate it."""
    graph = _build_graph()
    edge_types = {data["type"] for _, _, data in graph.edges(data=True)}
    assert EdgeType.CAN_ASSUME.value not in edge_types
    assert EdgeType.IDENTIFIES_VIA.value not in edge_types
