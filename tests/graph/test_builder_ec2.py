from __future__ import annotations

import networkx as nx

from aws_graph_builder.graph.builder import add_ec2_instances_to_graph, build_iam_graph
from aws_graph_builder.graph.schema import EdgeType, NodeType, make_edge_id
from aws_graph_builder.scan.ec2 import Ec2ScanResult
from aws_graph_builder.scan.iam import IamScanResult

ACCOUNT_ID = "111111111111"
REGION = "us-east-1"

INSTANCE_PROFILE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:instance-profile/deploy-profile"
ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/deploy-role"

WITH_PROFILE_ID = "i-0123456789abcdef0"
WITH_PROFILE_ARN = f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:instance/{WITH_PROFILE_ID}"

MISSING_PROFILE_ID = "i-0dangling00000000"
MISSING_PROFILE_ARN = f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:instance/{MISSING_PROFILE_ID}"

NO_PROFILE_ID = "i-0noprofile00000000"
NO_PROFILE_ARN = f"arn:aws:ec2:{REGION}:{ACCOUNT_ID}:instance/{NO_PROFILE_ID}"

DANGLING_PROFILE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:instance-profile/does-not-exist"


def _build_graph() -> nx.MultiDiGraph:
    """A graph containing an IamRole + InstanceProfile (via `build_iam_graph`)
    for the EC2 tests to attach onto.
    """
    scan_result = IamScanResult(
        roles=[
            {
                "Path": "/",
                "RoleName": "deploy-role",
                "RoleId": "AROADEPLOY",
                "Arn": ROLE_ARN,
                "CreateDate": "2026-01-01T00:00:00+00:00",
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
                "RolePolicyList": [],
                "AttachedManagedPolicies": [],
                "InstanceProfileList": [],
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
    )
    return build_iam_graph(scan_result, account_id=ACCOUNT_ID)


def test_instance_node_created_with_constructed_arn_and_properties() -> None:
    graph = _build_graph()
    scan_result = Ec2ScanResult(
        region=REGION,
        instances=[
            {
                "InstanceId": WITH_PROFILE_ID,
                "InstanceType": "t3.micro",
                "State": {"Name": "running"},
                "IamInstanceProfile": {"Arn": INSTANCE_PROFILE_ARN, "Id": "AIPADEPLOY"},
            }
        ],
    )

    add_ec2_instances_to_graph(graph, scan_result, account_id=ACCOUNT_ID)

    assert WITH_PROFILE_ARN in graph.nodes
    node = graph.nodes[WITH_PROFILE_ARN]
    assert node["type"] == NodeType.EC2_INSTANCE.value
    assert node["name"] == WITH_PROFILE_ID
    assert node["arn"] == WITH_PROFILE_ARN
    assert node["properties"]["InstanceType"] == "t3.micro"
    assert node["properties"]["State"] == {"Name": "running"}
    # InstanceId is promoted to name/arn, so not duplicated in properties.
    assert "InstanceId" not in node["properties"]
    # IamInstanceProfile stays in properties too, just like other raw fields.
    assert node["properties"]["IamInstanceProfile"] == {"Arn": INSTANCE_PROFILE_ARN, "Id": "AIPADEPLOY"}


def test_attached_to_edge_created_when_instance_profile_exists() -> None:
    graph = _build_graph()
    scan_result = Ec2ScanResult(
        region=REGION,
        instances=[
            {
                "InstanceId": WITH_PROFILE_ID,
                "IamInstanceProfile": {"Arn": INSTANCE_PROFILE_ARN, "Id": "AIPADEPLOY"},
            }
        ],
    )

    add_ec2_instances_to_graph(graph, scan_result, account_id=ACCOUNT_ID)

    edge_id = make_edge_id(EdgeType.ATTACHED_TO, INSTANCE_PROFILE_ARN, WITH_PROFILE_ARN)
    assert graph.has_edge(INSTANCE_PROFILE_ARN, WITH_PROFILE_ARN, key=edge_id)
    assert graph[INSTANCE_PROFILE_ARN][WITH_PROFILE_ARN][edge_id]["type"] == EdgeType.ATTACHED_TO.value


def test_no_edge_when_instance_has_no_iam_instance_profile() -> None:
    graph = _build_graph()
    scan_result = Ec2ScanResult(region=REGION, instances=[{"InstanceId": NO_PROFILE_ID}])

    add_ec2_instances_to_graph(graph, scan_result, account_id=ACCOUNT_ID)

    assert NO_PROFILE_ARN in graph.nodes
    assert graph.in_degree(NO_PROFILE_ARN) == 0


def test_dangling_instance_profile_reference_skipped_gracefully() -> None:
    graph = _build_graph()
    scan_result = Ec2ScanResult(
        region=REGION,
        instances=[
            {
                "InstanceId": MISSING_PROFILE_ID,
                "IamInstanceProfile": {"Arn": DANGLING_PROFILE_ARN, "Id": "AIPAMISSING"},
            }
        ],
    )

    add_ec2_instances_to_graph(graph, scan_result, account_id=ACCOUNT_ID)

    # Node still created...
    assert MISSING_PROFILE_ARN in graph.nodes
    # ...but no fabricated InstanceProfile node, and no edge.
    assert DANGLING_PROFILE_ARN not in graph.nodes
    assert graph.in_degree(MISSING_PROFILE_ARN) == 0
