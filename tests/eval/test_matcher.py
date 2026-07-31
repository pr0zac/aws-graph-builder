from __future__ import annotations

from aws_graph_builder.eval.matcher import (
    action_matches,
    condition_matches,
    resource_matches,
)


def test_action_matches_exact() -> None:
    assert action_matches("iam:CreateAccessKey", "iam:CreateAccessKey") is True


def test_action_matches_exact_non_match() -> None:
    assert action_matches("iam:CreateAccessKey", "iam:DeleteAccessKey") is False


def test_action_matches_service_wildcard() -> None:
    assert action_matches("iam:*", "iam:CreateAccessKey") is True
    assert action_matches("iam:*", "s3:GetObject") is False


def test_action_matches_bare_wildcard_matches_anything() -> None:
    assert action_matches("*", "iam:CreateAccessKey") is True
    assert action_matches("*", "s3:GetObject") is True


def test_action_matches_question_mark_wildcard() -> None:
    assert action_matches("iam:GetUse?", "iam:GetUser") is True
    assert action_matches("iam:GetUse?", "iam:GetUse") is False
    assert action_matches("iam:GetUse?", "iam:GetUsers") is False


def test_action_matches_case_insensitive() -> None:
    assert action_matches("IAM:CreateAccessKey", "iam:createaccesskey") is True
    assert action_matches("iam:*", "IAM:CreateAccessKey") is True


def test_action_matches_wildcard_across_colon_separator() -> None:
    # "*" matches any sequence, including across the service:action separator.
    assert action_matches("*Key*", "iam:CreateAccessKey") is True


def test_resource_matches_exact() -> None:
    arn = "arn:aws:iam::111111111111:user/alice"
    assert resource_matches(arn, arn) is True


def test_resource_matches_wildcard() -> None:
    assert resource_matches("arn:aws:iam::111111111111:user/*", "arn:aws:iam::111111111111:user/alice") is True
    assert resource_matches("arn:aws:iam::111111111111:user/*", "arn:aws:iam::111111111111:role/alice") is False


def test_resource_matches_bare_wildcard() -> None:
    assert resource_matches("*", "arn:aws:iam::111111111111:user/alice") is True


def test_resource_matches_question_mark_wildcard() -> None:
    assert resource_matches("arn:aws:iam::111111111111:user/al?ce", "arn:aws:iam::111111111111:user/alice") is True


def test_resource_matches_case_insensitive() -> None:
    arn = "arn:aws:iam::111111111111:user/Alice"
    assert resource_matches(arn.lower(), arn) is True


def test_resource_matches_non_match() -> None:
    assert resource_matches("arn:aws:iam::111111111111:user/bob", "arn:aws:iam::111111111111:user/alice") is False


def test_resource_matches_policy_variable_returns_false() -> None:
    # Known limitation, not a bug -- see matcher.py docstring: IAM policy
    # variable substitution is out of scope for this offline static tool.
    pattern = "arn:aws:iam::111111111111:user/${aws:username}"
    assert resource_matches(pattern, "arn:aws:iam::111111111111:user/alice") is False


def test_condition_matches_empty_dict_is_true() -> None:
    assert condition_matches({}) is True


def test_condition_matches_non_empty_dict_is_unresolved() -> None:
    assert condition_matches({"Bool": {"aws:MultiFactorAuthPresent": "true"}}) is None
    assert condition_matches({"StringEquals": {"aws:username": "alice"}}) is None
