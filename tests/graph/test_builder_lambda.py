from __future__ import annotations

import networkx as nx

from aws_graph_builder.graph.builder import (
    add_lambda_functions_to_graph,
    build_iam_graph,
)
from aws_graph_builder.graph.schema import EdgeType, NodeType, make_edge_id
from aws_graph_builder.scan.iam import IamScanResult
from aws_graph_builder.scan.lambda_ import LambdaScanResult

ACCOUNT_ID = "111111111111"
REGION = "us-east-1"

ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/lambda-exec-role"
MISSING_ROLE_ARN = f"arn:aws:iam::{ACCOUNT_ID}:role/does-not-exist"

WITH_POLICY_ARN = f"arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:with-policy"
NO_POLICY_ARN = f"arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:no-policy"
DANGLING_ROLE_ARN = f"arn:aws:lambda:{REGION}:{ACCOUNT_ID}:function:dangling-role"

RESOURCE_POLICY = {
    "Version": "2012-10-17",
    "Statement": [{"Sid": "AllowInvoke", "Effect": "Allow", "Principal": "*", "Action": "lambda:InvokeFunction"}],
}


def _build_graph() -> nx.MultiDiGraph:
    """A graph containing an IamRole (via `build_iam_graph`) for the Lambda
    tests to attach onto.
    """
    scan_result = IamScanResult(
        roles=[
            {
                "Path": "/",
                "RoleName": "lambda-exec-role",
                "RoleId": "AROALAMBDA",
                "Arn": ROLE_ARN,
                "CreateDate": "2026-01-01T00:00:00+00:00",
                "AssumeRolePolicyDocument": {"Version": "2012-10-17", "Statement": []},
                "RolePolicyList": [],
                "AttachedManagedPolicies": [],
                "InstanceProfileList": [],
            }
        ],
    )
    return build_iam_graph(scan_result, account_id=ACCOUNT_ID)


def test_function_node_created_with_properties_and_resource_policy() -> None:
    graph = _build_graph()
    scan_result = LambdaScanResult(
        region=REGION,
        functions=[
            {
                "FunctionArn": WITH_POLICY_ARN,
                "FunctionName": "with-policy",
                "Runtime": "python3.13",
                "Role": ROLE_ARN,
            }
        ],
        resource_policies={WITH_POLICY_ARN: RESOURCE_POLICY},
    )

    add_lambda_functions_to_graph(graph, scan_result)

    node = graph.nodes[WITH_POLICY_ARN]
    assert node["type"] == NodeType.LAMBDA_FUNCTION.value
    assert node["name"] == "with-policy"
    assert node["arn"] == WITH_POLICY_ARN
    assert node["properties"]["Runtime"] == "python3.13"
    assert node["properties"]["resource_policy"] == RESOURCE_POLICY
    # Promoted fields are not duplicated in properties.
    assert "FunctionArn" not in node["properties"]
    assert "FunctionName" not in node["properties"]


def test_resource_policy_defaults_to_none_when_absent() -> None:
    graph = _build_graph()
    scan_result = LambdaScanResult(
        region=REGION,
        functions=[{"FunctionArn": NO_POLICY_ARN, "FunctionName": "no-policy", "Role": ROLE_ARN}],
        resource_policies={NO_POLICY_ARN: None},
    )

    add_lambda_functions_to_graph(graph, scan_result)

    assert graph.nodes[NO_POLICY_ARN]["properties"]["resource_policy"] is None


def test_execution_role_edge_created_when_role_exists() -> None:
    graph = _build_graph()
    scan_result = LambdaScanResult(
        region=REGION,
        functions=[{"FunctionArn": WITH_POLICY_ARN, "FunctionName": "with-policy", "Role": ROLE_ARN}],
    )

    add_lambda_functions_to_graph(graph, scan_result)

    edge_id = make_edge_id(EdgeType.EXECUTION_ROLE, WITH_POLICY_ARN, ROLE_ARN)
    assert graph.has_edge(WITH_POLICY_ARN, ROLE_ARN, key=edge_id)
    assert graph[WITH_POLICY_ARN][ROLE_ARN][edge_id]["type"] == EdgeType.EXECUTION_ROLE.value


def test_dangling_execution_role_reference_skipped_gracefully() -> None:
    graph = _build_graph()
    scan_result = LambdaScanResult(
        region=REGION,
        functions=[{"FunctionArn": DANGLING_ROLE_ARN, "FunctionName": "dangling-role", "Role": MISSING_ROLE_ARN}],
    )

    add_lambda_functions_to_graph(graph, scan_result)

    assert DANGLING_ROLE_ARN in graph.nodes
    assert MISSING_ROLE_ARN not in graph.nodes
    assert graph.out_degree(DANGLING_ROLE_ARN) == 0
