"""Fictional graph used for browser/integration tests; contains no account data."""


def viewer_document():
    nodes = [
        {"id": "analyst", "name": "Analyst", "type": "IamUser", "arn": "arn:aws:iam::111111111111:user/Analyst", "properties": {"mfa_enabled": True}},
        {"id": "deploy", "name": "DeployRole", "type": "IamRole", "arn": "arn:aws:iam::111111111111:role/DeployRole", "properties": {}},
        {"id": "admin", "name": "AdminRole", "type": "IamRole", "arn": "arn:aws:iam::111111111111:role/AdminRole", "properties": {}},
        {"id": "policy", "name": "DeployPolicy", "type": "ManagedPolicy", "arn": "arn:aws:iam::111111111111:policy/DeployPolicy", "properties": {"policy_document": {"Version": "2012-10-17", "Statement": [{"Sid": "Deploy", "Effect": "Allow", "Action": "iam:AttachRolePolicy", "Resource": "*"}]}}},
        {"id": "bucket", "name": "EvidenceBucket", "type": "S3Bucket", "arn": "arn:aws:s3:::example-evidence-bucket", "properties": {}},
    ]
    edges = [
        {"id": "assume", "source": "analyst", "target": "deploy", "type": "CanAssume", "properties": {"requires_mfa": True, "external_id_required": True}},
        {"id": "escalate", "source": "analyst", "target": "deploy", "type": "PrivescPath", "properties": {"technique_id": "attach_policy", "description": "Analyst can modify the role's policy.", "evidence_edges": ["permission"], "required_permissions": ["iam:AttachRolePolicy"]}},
        {"id": "permission", "source": "analyst", "target": "deploy", "type": "EffectivePermission", "properties": {"actions": ["iam:AttachRolePolicy"], "resource_pattern": "*", "condition_unresolved": True, "evaluated_from": [{"policy": "policy", "sid": "Deploy"}]}},
        {"id": "next", "source": "deploy", "target": "admin", "type": "CanAssume", "properties": {}},
        {"id": "attachment", "source": "analyst", "target": "policy", "type": "AttachedPolicy", "properties": {}},
        {"id": "resource", "source": "deploy", "target": "bucket", "type": "EffectivePermission", "properties": {"actions": ["s3:GetObject"]}},
        {"id": "admin-access", "source": "admin", "target": "admin", "type": "EffectivePermission", "properties": {"actions": ["*"], "resource_pattern": "*"}},
    ]
    return {"schema_version": "1.0", "account_id": "111111111111", "generated_at": "2026-11-04T12:00:00Z", "regions_scanned": ["us-east-1"], "nodes": nodes, "edges": edges,
            "findings": [{"technique_id": "attach_policy", "source": "analyst", "target": "deploy", "severity": "critical", "required_permissions": ["iam:AttachRolePolicy"], "evidence_edges": ["permission"], "edge_id": "escalate", "description": "Analyst can modify the role's policy."}]}
