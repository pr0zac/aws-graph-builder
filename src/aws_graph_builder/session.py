"""boto3 Session construction and credential validation.

This module is the single place scanning code goes to get a validated
boto3 session. It never restricts *how* credentials are resolved — it
relies entirely on boto3's standard credential chain (env vars, shared
config/credentials files, SSO, instance/container roles, etc.) — but it
does guarantee that by the time `validate_credentials` returns
successfully, the credentials are known-good (an `sts:GetCallerIdentity`
call has succeeded), and that any failure to do so is surfaced as a
specific, human-readable exception rather than a raw botocore traceback.
"""

from __future__ import annotations

from dataclasses import dataclass

import boto3
from botocore.exceptions import (
    BotoCoreError,
    ClientError,
    NoCredentialsError,
    ProfileNotFound,
)

# botocore error codes that indicate the credentials themselves are
# expired or otherwise no longer valid (as opposed to being well-formed
# but lacking permission, which is a different failure mode).
_EXPIRED_CREDENTIAL_ERROR_CODES = frozenset(
    {
        "ExpiredToken",
        "ExpiredTokenException",
        "RequestExpired",
        "InvalidClientTokenId",
        "UnrecognizedClientException",
        "AuthFailure",
    }
)


@dataclass
class CallerIdentity:
    """The identity of the credentials boto3 resolved, per STS."""

    account_id: str
    arn: str
    user_id: str


class CredentialError(Exception):
    """Base class for credential-related errors raised by this module."""


class CredentialsExpiredError(CredentialError):
    """Raised when STS reports the credentials are expired or invalid."""


class NoCredentialsFoundError(CredentialError):
    """Raised when boto3's credential chain found no credentials at all."""


class ProfileNotFoundError(CredentialError):
    """Raised when an explicitly-requested named profile doesn't exist in
    the local AWS config/credentials files.
    """


def build_session(*, region: str | None = None, profile: str | None = None) -> boto3.Session:
    """Construct a boto3 Session using the standard credential chain.

    This is a thin wrapper — it exists as a seam for testing and future
    extension, not to add logic beyond optional region/profile overrides.
    `profile=None` falls back to boto3's normal resolution (the
    `AWS_PROFILE` env var if set, else the `default` profile).

    Unlike credential resolution itself (which is lazy -- see
    `validate_credentials`), boto3 eagerly validates that a *named* profile
    actually exists at `Session` construction time, so this can itself raise;
    wrapped here to keep this module's promise that failures surface as a
    specific, human-readable exception rather than a raw botocore traceback.
    """
    try:
        return boto3.Session(region_name=region, profile_name=profile)
    except ProfileNotFound as exc:
        raise ProfileNotFoundError(
            f"AWS profile {profile!r} was not found in your local AWS config "
            "or credentials files. Check the profile name (e.g. via `aws "
            "configure list-profiles`) and try again."
        ) from exc


def is_expired_credentials_error(exc: ClientError) -> bool:
    """Return True if a ClientError indicates expired/invalid credentials.

    Reusable by later code (e.g. the scan layer) to detect credential
    expiry mid-scan on *any* AWS API call, not just STS.
    """
    error_code = exc.response.get("Error", {}).get("Code", "")
    return error_code in _EXPIRED_CREDENTIAL_ERROR_CODES


def validate_credentials(session: boto3.Session) -> CallerIdentity:
    """Validate credentials by calling sts:GetCallerIdentity.

    Raises `NoCredentialsFoundError` if boto3 has no credentials at all,
    `CredentialsExpiredError` if STS reports the credentials are expired
    or invalid, or `CredentialError` for any other authentication
    failure -- including client-side credential-*resolution* failures
    (e.g. an expired SSO token, a missing/invalid profile) that never
    reach STS as an API call at all, and so surface from botocore as a
    `BotoCoreError` subclass rather than a `ClientError`. On success,
    returns the resolved `CallerIdentity`.
    """
    try:
        response = session.client("sts").get_caller_identity()
    except NoCredentialsError as exc:
        raise NoCredentialsFoundError(
            "No AWS credentials found. Configure credentials via environment "
            "variables, a shared credentials/config file, SSO, or an "
            "instance/container role, then try again."
        ) from exc
    except ClientError as exc:
        error_code = exc.response.get("Error", {}).get("Code", "unknown")
        message = exc.response.get("Error", {}).get("Message", str(exc))
        if is_expired_credentials_error(exc):
            raise CredentialsExpiredError(
                f"AWS credentials are expired or invalid ({error_code}): "
                f"{message}. Refresh your credentials (e.g. re-run `aws sso "
                "login` or obtain new temporary credentials) and try again."
            ) from exc
        raise CredentialError(
            f"Failed to validate AWS credentials via sts:GetCallerIdentity "
            f"({error_code}): {message}"
        ) from exc
    except BotoCoreError as exc:
        raise CredentialError(
            f"Failed to resolve AWS credentials: {exc}. This can happen with "
            "an expired SSO session, a missing/invalid profile, or other "
            "local credential-chain configuration problems -- run `aws sso "
            "login` (if using SSO) or check your AWS profile/config and try "
            "again."
        ) from exc

    return CallerIdentity(
        account_id=response["Account"],
        arn=response["Arn"],
        user_id=response["UserId"],
    )
