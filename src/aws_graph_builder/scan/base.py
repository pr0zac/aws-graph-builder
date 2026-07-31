"""Shared scanning infrastructure: the `Scanner` ABC, `ScanGap`, and the
`CachedClient` wrapper that routes every AWS call through the disk cache.

Pagination-caching granularity: paginated operations (e.g.
`get_account_authorization_details`, `list_instance_profiles`) are merged into
a single logical result and cached under **one cache entry per operation**,
not one entry per page. Reasoning: the cache is keyed by
`(scope, service, operation[, disambiguator])`, mirroring a single logical API
call rather than the wire-level pagination of it; a future `rebuild` only
needs to reconstruct "what did GetAccountAuthorizationDetails return", not
replay page-by-page. It also sidesteps needing a stable per-page
disambiguator (page tokens aren't stable across runs) and keeps `CacheStore`
usage symmetric with non-paginated calls.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from botocore.exceptions import BotoCoreError, ClientError

from aws_graph_builder.cache.store import CacheEntry, CacheStore
from aws_graph_builder.session import (
    CredentialError,
    CredentialsExpiredError,
    is_expired_credentials_error,
)


@dataclass
class ScanGap:
    """A single denied/failed/throttled API call, recorded so the scan can
    continue and later report what it missed.
    """

    service: str
    operation: str
    scope: str  # region name, or "global"
    error_code: str
    message: str


class Scanner(ABC):
    """Base class for all resource scanners.

    Only `IamScanner` exists yet (Phase 1); EC2/Lambda/S3/Organizations
    scanners land in Phase 5 and will share this same minimal shape.
    """

    @abstractmethod
    def scan(self) -> Any:
        """Run the scan against AWS (via a `CachedClient`) and return a
        scanner-specific result dataclass. Every such result embeds its own
        `gaps: list[ScanGap]` field, per aws-graph-builder.md's
        partial-failure-handling requirement -- a scan degrades to a partial
        result rather than raising on an ordinary denied/throttled call.
        """
        raise NotImplementedError

    @staticmethod
    @abstractmethod
    def required_actions() -> list[str]:
        """The IAM action strings this scanner calls, in `service:Action`
        form. Aggregated by the future `permissions` CLI command into the
        minimal least-privilege read-only policy a scan needs -- this is the
        single source of truth, so it can't drift from what the scanner
        actually calls.
        """
        raise NotImplementedError


def _utc_now_iso() -> str:
    return datetime.now(UTC).isoformat()


class CachedClient:
    """Wraps a boto3 client so scanner code calls AWS operations while
    transparently going through the disk cache: write-through -- every call
    goes to AWS, and both the raw response and any error get cached, so a
    Phase 5 `rebuild` can reconstruct the scan (including its gaps) without
    re-hitting AWS.

    `operation` is always the boto3 client method name in snake_case (e.g.
    `"get_account_authorization_details"`), matching the convention already
    established by `cache.keys.cache_filename`.

    On a `ClientError`, the error is cached and a `ScanGap` is appended to
    `self.gaps` so the caller can continue the scan -- *unless* the error
    indicates the credentials themselves have expired mid-scan
    (`session.is_expired_credentials_error`), in which case
    `session.CredentialsExpiredError` is raised instead: at that point the
    entire scan is unrecoverable, not just this one call.

    An optional `reporter` callback -- one arg, a message string -- is
    invoked for each AWS call made (via `report()`/`call()`/`paginate()`),
    for `--verbose` progress output. Scanners (e.g. `IamScanner`) also call
    `report()` directly for their own higher-level, domain-specific
    narration (e.g. "found 12 users"), so this is the single shared channel
    for both "what it's doing" (this class) and "what it's finding" (the
    scanner).
    """

    def __init__(
        self,
        client: Any,
        cache_store: CacheStore,
        *,
        scope: str,
        service: str,
        reporter: Callable[[str], None] | None = None,
    ) -> None:
        self._client = client
        self._cache_store = cache_store
        self._scope = scope
        self._service = service
        self._reporter = reporter
        self.gaps: list[ScanGap] = []

    def report(self, message: str) -> None:
        """Emit a verbose progress message, if a `reporter` was configured."""
        if self._reporter is not None:
            self._reporter(message)

    def call(
        self,
        operation: str,
        params: dict[str, Any] | None = None,
        *,
        disambiguator: str | None = None,
    ) -> dict[str, Any] | None:
        """Call a single (non-paginated) boto3 operation.

        Returns the raw response dict, or `None` if the call failed (in which
        case a `ScanGap` was appended to `self.gaps`).
        """
        self.report(f"{self._service}:{operation}" + (f" ({disambiguator})" if disambiguator else ""))
        params = dict(params) if params else {}
        method = getattr(self._client, operation)
        try:
            response = method(**params)
        except ClientError as exc:
            self._record_error(operation, params, exc, disambiguator=disambiguator)
            return None
        except BotoCoreError as exc:
            raise CredentialError(
                f"Failed to call {self._service}:{operation}: {exc}. This "
                "indicates a client-side credential-chain problem (e.g. an "
                "SSO session that expired mid-scan) rather than an AWS-side "
                "denial, so the scan cannot continue."
            ) from exc

        self._cache_store.put(
            self._scope,
            self._service,
            operation,
            CacheEntry(fetched_at=_utc_now_iso(), operation=operation, params=params, response=response, error=None),
            disambiguator=disambiguator,
        )
        return response  # type: ignore[no-any-return]

    def paginate(
        self,
        operation: str,
        list_keys: Sequence[str],
        params: dict[str, Any] | None = None,
        *,
        disambiguator: str | None = None,
    ) -> dict[str, list[Any]] | None:
        """Call a paginated boto3 operation, merging `list_keys` across pages
        into a single dict (see module docstring for the caching-granularity
        rationale), and cache the merged result as one entry.

        Returns the merged dict, or `None` if any page's call failed (in
        which case a `ScanGap` was appended and any partial pages already
        fetched are discarded rather than cached as if complete).
        """
        self.report(f"{self._service}:{operation} (paginated)")
        params = dict(params) if params else {}
        paginator = self._client.get_paginator(operation)
        merged: dict[str, list[Any]] = {key: [] for key in list_keys}
        try:
            for page in paginator.paginate(**params):
                for key in list_keys:
                    merged[key].extend(page.get(key, []))
        except ClientError as exc:
            self._record_error(operation, params, exc, disambiguator=disambiguator)
            return None
        except BotoCoreError as exc:
            raise CredentialError(
                f"Failed to call {self._service}:{operation}: {exc}. This "
                "indicates a client-side credential-chain problem (e.g. an "
                "SSO session that expired mid-scan) rather than an AWS-side "
                "denial, so the scan cannot continue."
            ) from exc

        self._cache_store.put(
            self._scope,
            self._service,
            operation,
            CacheEntry(fetched_at=_utc_now_iso(), operation=operation, params=params, response=merged, error=None),
            disambiguator=disambiguator,
        )
        return merged

    def _record_error(
        self,
        operation: str,
        params: dict[str, Any],
        exc: ClientError,
        *,
        disambiguator: str | None,
    ) -> None:
        error_code = exc.response.get("Error", {}).get("Code", "unknown")
        message = exc.response.get("Error", {}).get("Message", str(exc))

        self._cache_store.put(
            self._scope,
            self._service,
            operation,
            CacheEntry(
                fetched_at=_utc_now_iso(),
                operation=operation,
                params=params,
                response=None,
                error={"code": error_code, "message": message},
            ),
            disambiguator=disambiguator,
        )

        if is_expired_credentials_error(exc):
            raise CredentialsExpiredError(
                f"AWS credentials expired mid-scan while calling {self._service}:{operation} "
                f"({error_code}): {message}. Refresh your credentials and re-run the scan."
            ) from exc

        self.gaps.append(
            ScanGap(
                service=self._service,
                operation=operation,
                scope=self._scope,
                error_code=error_code,
                message=message,
            )
        )
