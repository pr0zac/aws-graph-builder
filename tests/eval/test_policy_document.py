from __future__ import annotations

import pytest

from aws_graph_builder.eval.policy_document import parse_policy_document


def test_action_and_resource_single_string_normalized_to_list() -> None:
    raw = {
        "Statement": [
            {"Effect": "Allow", "Action": "iam:CreateAccessKey", "Resource": "arn:aws:iam::111111111111:user/alice"}
        ]
    }
    document = parse_policy_document(raw, source="test")

    statement = document.statements[0]
    assert statement.actions == ["iam:CreateAccessKey"]
    assert statement.resources == ["arn:aws:iam::111111111111:user/alice"]


def test_action_and_resource_list_normalized_unchanged() -> None:
    raw = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": ["iam:CreateAccessKey", "iam:DeleteAccessKey"],
                "Resource": ["arn:aws:iam::111111111111:user/alice", "arn:aws:iam::111111111111:user/bob"],
            }
        ]
    }
    document = parse_policy_document(raw, source="test")

    statement = document.statements[0]
    assert statement.actions == ["iam:CreateAccessKey", "iam:DeleteAccessKey"]
    assert statement.resources == ["arn:aws:iam::111111111111:user/alice", "arn:aws:iam::111111111111:user/bob"]


def test_not_action_and_not_resource_normalized() -> None:
    raw = {
        "Statement": [
            {"Effect": "Deny", "NotAction": "iam:GetUser", "NotResource": ["arn:aws:iam::111111111111:user/alice"]}
        ]
    }
    document = parse_policy_document(raw, source="test")

    statement = document.statements[0]
    assert statement.not_actions == ["iam:GetUser"]
    assert statement.not_resources == ["arn:aws:iam::111111111111:user/alice"]
    # No explicit Action/Resource present.
    assert statement.actions == []
    # Resource omitted (only NotResource present) -> still defaults to ["*"].
    assert statement.resources == ["*"]


def test_missing_resource_in_trust_style_statement_defaults_to_wildcard() -> None:
    raw = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {"AWS": "arn:aws:iam::111111111111:user/alice"},
            }
        ]
    }
    document = parse_policy_document(raw, source="trust:role")

    statement = document.statements[0]
    assert statement.resources == ["*"]


def test_sid_optional() -> None:
    raw = {"Statement": [{"Effect": "Allow", "Action": "iam:GetUser", "Resource": "*"}]}
    document = parse_policy_document(raw, source="test")

    assert document.statements[0].sid is None

    raw_with_sid = {"Statement": [{"Sid": "AllowGetUser", "Effect": "Allow", "Action": "iam:GetUser", "Resource": "*"}]}
    document_with_sid = parse_policy_document(raw_with_sid, source="test")
    assert document_with_sid.statements[0].sid == "AllowGetUser"


def test_condition_and_principal_optional_default_empty_and_none() -> None:
    raw = {"Statement": [{"Effect": "Allow", "Action": "iam:GetUser", "Resource": "*"}]}
    document = parse_policy_document(raw, source="test")

    statement = document.statements[0]
    assert statement.conditions == {}
    assert statement.principal is None


def test_condition_and_principal_present() -> None:
    raw = {
        "Statement": [
            {
                "Effect": "Allow",
                "Action": "sts:AssumeRole",
                "Principal": {"AWS": "arn:aws:iam::111111111111:role/other"},
                "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}},
            }
        ]
    }
    document = parse_policy_document(raw, source="test")

    statement = document.statements[0]
    assert statement.conditions == {"Bool": {"aws:MultiFactorAuthPresent": "true"}}
    assert statement.principal == {"AWS": "arn:aws:iam::111111111111:role/other"}


def test_bare_string_principal_normalized_to_dict() -> None:
    raw = {"Statement": [{"Effect": "Allow", "Action": "sts:AssumeRole", "Principal": "*"}]}
    document = parse_policy_document(raw, source="test")

    assert document.statements[0].principal == {"__raw__": "*"}


def test_single_statement_dict_not_wrapped_in_list() -> None:
    raw = {"Statement": {"Effect": "Allow", "Action": "iam:GetUser", "Resource": "*"}}
    document = parse_policy_document(raw, source="test")

    assert len(document.statements) == 1
    assert document.statements[0].actions == ["iam:GetUser"]


def test_missing_statement_key_raises_value_error() -> None:
    with pytest.raises(ValueError):
        parse_policy_document({"Version": "2012-10-17"}, source="test")


def test_malformed_statement_shape_raises_value_error() -> None:
    with pytest.raises(ValueError):
        parse_policy_document({"Statement": ["not-a-dict"]}, source="test")


def test_statement_missing_effect_raises_value_error() -> None:
    with pytest.raises(ValueError):
        parse_policy_document({"Statement": [{"Action": "iam:GetUser", "Resource": "*"}]}, source="test")


def test_action_field_with_non_string_list_item_raises_value_error() -> None:
    with pytest.raises(ValueError):
        parse_policy_document(
            {"Statement": [{"Effect": "Allow", "Action": ["iam:GetUser", 42], "Resource": "*"}]}, source="test"
        )


def test_action_field_wrong_type_raises_value_error() -> None:
    with pytest.raises(ValueError):
        parse_policy_document({"Statement": [{"Effect": "Allow", "Action": 42, "Resource": "*"}]}, source="test")


def test_source_propagated_to_every_statement() -> None:
    raw = {
        "Statement": [
            {"Effect": "Allow", "Action": "iam:GetUser", "Resource": "*"},
            {"Effect": "Deny", "Action": "iam:DeleteUser", "Resource": "*"},
        ]
    }
    document = parse_policy_document(raw, source="arn:aws:iam::111111111111:policy/MyPolicy")

    assert document.source == "arn:aws:iam::111111111111:policy/MyPolicy"
    assert all(s.source == "arn:aws:iam::111111111111:policy/MyPolicy" for s in document.statements)
