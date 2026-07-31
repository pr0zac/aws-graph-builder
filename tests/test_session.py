from __future__ import annotations

from unittest.mock import MagicMock, patch

import boto3
import pytest
from botocore.exceptions import ClientError, NoCredentialsError, TokenRetrievalError
from moto import mock_aws

from aws_graph_builder.session import (
    CallerIdentity,
    CredentialError,
    CredentialsExpiredError,
    NoCredentialsFoundError,
    build_session,
    is_expired_credentials_error,
    validate_credentials,
)


def _client_error(code: str, message: str = "boom", operation: str = "GetCallerIdentity") -> ClientError:
    return ClientError({"Error": {"Code": code, "Message": message}}, operation)


def test_build_session_returns_boto3_session() -> None:
    session = build_session()
    assert isinstance(session, boto3.Session)


def test_build_session_honors_region_override() -> None:
    session = build_session(region="eu-west-1")
    assert session.region_name == "eu-west-1"


@mock_aws
def test_validate_credentials_returns_caller_identity() -> None:
    session = boto3.Session(
        aws_access_key_id="testing",
        aws_secret_access_key="testing",
        region_name="us-east-1",
    )
    expected = session.client("sts").get_caller_identity()

    identity = validate_credentials(session)

    assert isinstance(identity, CallerIdentity)
    assert identity.account_id == expected["Account"]
    assert identity.arn == expected["Arn"]
    assert identity.user_id == expected["UserId"]


def test_validate_credentials_raises_no_credentials_found_error() -> None:
    session = boto3.Session(region_name="us-east-1")
    mock_sts = MagicMock()
    mock_sts.get_caller_identity.side_effect = NoCredentialsError()

    with patch.object(session, "client", return_value=mock_sts), pytest.raises(NoCredentialsFoundError) as exc_info:
        validate_credentials(session)

    assert exc_info.value.__cause__ is not None
    assert isinstance(exc_info.value.__cause__, NoCredentialsError)


def test_validate_credentials_wraps_botocore_error_as_credential_error() -> None:
    """Regression test: an expired SSO session (or a missing/invalid profile,
    etc.) fails during credential *resolution*, before STS is ever called, so
    botocore raises a `BotoCoreError` subclass (e.g. `TokenRetrievalError`)
    rather than `ClientError`/`NoCredentialsError`. This must be caught and
    wrapped, not left to propagate as a raw traceback -- caught live against a
    real AWS profile with an expired SSO token during manual CLI verification.
    """
    session = boto3.Session(region_name="us-east-1")
    mock_sts = MagicMock()
    error = TokenRetrievalError(provider="sso", error_msg="Token has expired and refresh failed")
    mock_sts.get_caller_identity.side_effect = error

    with patch.object(session, "client", return_value=mock_sts), pytest.raises(CredentialError) as exc_info:
        validate_credentials(session)

    assert not isinstance(exc_info.value, (NoCredentialsFoundError, CredentialsExpiredError))
    assert exc_info.value.__cause__ is error


@pytest.mark.parametrize(
    "code",
    [
        "ExpiredToken",
        "ExpiredTokenException",
        "RequestExpired",
        "InvalidClientTokenId",
    ],
)
def test_validate_credentials_raises_credentials_expired_error(code: str) -> None:
    session = boto3.Session(region_name="us-east-1")
    mock_sts = MagicMock()
    error = _client_error(code, message="the security token included in the request is expired")
    mock_sts.get_caller_identity.side_effect = error

    with patch.object(session, "client", return_value=mock_sts), pytest.raises(CredentialsExpiredError) as exc_info:
        validate_credentials(session)

    assert exc_info.value.__cause__ is error
    assert code in str(exc_info.value)


def test_validate_credentials_raises_credential_error_for_non_expiry_failure() -> None:
    session = boto3.Session(region_name="us-east-1")
    mock_sts = MagicMock()
    error = _client_error("AccessDenied", message="not authorized to perform sts:GetCallerIdentity")
    mock_sts.get_caller_identity.side_effect = error

    with patch.object(session, "client", return_value=mock_sts), pytest.raises(CredentialError) as exc_info:
        validate_credentials(session)

    assert not isinstance(exc_info.value, CredentialsExpiredError)
    assert exc_info.value.__cause__ is error


def test_is_expired_credentials_error_true_for_expired_codes() -> None:
    assert is_expired_credentials_error(_client_error("ExpiredToken")) is True
    assert is_expired_credentials_error(_client_error("InvalidClientTokenId")) is True


def test_is_expired_credentials_error_false_for_non_expiry_codes() -> None:
    assert is_expired_credentials_error(_client_error("AccessDenied")) is False
    assert is_expired_credentials_error(_client_error("Throttling")) is False
