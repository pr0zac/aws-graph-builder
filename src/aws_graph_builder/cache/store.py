"""Content-keyed JSON file cache for raw AWS API responses.

Layout (relative to the store's root):
    <root>/global/<service>/<operation>[__<disambiguator>].json
    <root>/regions/<region>/<service>/<operation>[__<disambiguator>].json
    <root>/manifest.json

Scanners write one `CacheEntry` per API call (success or error) so that a
later `rebuild` can reconstruct the graph — including reproducing scan gaps
— without re-hitting AWS.
"""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path
from typing import Any

from aws_graph_builder.cache.keys import cache_filename

GLOBAL_SCOPE = "global"


@dataclass
class CacheEntry:
    """A single cached API call: its request params and the resulting outcome.

    Exactly one of `response`/`error` is expected to be non-None in practice,
    but this dataclass doesn't enforce that — it just stores what it's given.
    """

    fetched_at: str  # ISO 8601 UTC
    operation: str
    params: dict[str, Any]
    response: dict[str, Any] | None = None
    error: dict[str, Any] | None = None  # {"code": str, "message": str}


def _json_default(obj: Any) -> Any:
    """`json.dumps(default=...)` hook: serialize datetimes (raw boto3 responses
    contain them) as ISO 8601 strings. Anything else is a genuine TypeError.
    """
    if isinstance(obj, datetime):
        return obj.isoformat()
    raise TypeError(f"Object of type {type(obj).__name__} is not JSON serializable")


class CacheStore:
    """Read-through/write-through JSON file cache rooted at `root`."""

    def __init__(self, root: Path) -> None:
        self.root = root

    def _scope_dir(self, scope: str) -> Path:
        if scope == GLOBAL_SCOPE:
            return self.root / "global"
        return self.root / "regions" / scope

    def _entry_path(
        self,
        scope: str,
        service: str,
        operation: str,
        *,
        disambiguator: str | None = None,
    ) -> Path:
        filename = cache_filename(operation, disambiguator)
        return self._scope_dir(scope) / service / filename

    def get(
        self,
        scope: str,
        service: str,
        operation: str,
        *,
        disambiguator: str | None = None,
    ) -> CacheEntry | None:
        """Return the cached entry, or None if it isn't present.

        Note: deserialization does NOT convert ISO date strings back into
        `datetime` objects — they're left as plain strings. Cached JSON is
        meant to be inspected and rebuilt-from as plain JSON, not round-tripped
        back into live boto3-typed objects.
        """
        path = self._entry_path(scope, service, operation, disambiguator=disambiguator)
        if not path.exists():
            return None
        try:
            data = json.loads(path.read_text())
        except json.JSONDecodeError as exc:
            raise ValueError(f"Corrupt cache entry at {path}: invalid JSON") from exc
        return CacheEntry(**data)

    def put(
        self,
        scope: str,
        service: str,
        operation: str,
        entry: CacheEntry,
        *,
        disambiguator: str | None = None,
    ) -> None:
        path = self._entry_path(scope, service, operation, disambiguator=disambiguator)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(asdict(entry), default=_json_default, indent=2))

    def write_manifest(self, manifest: dict[str, Any]) -> None:
        path = self.root / "manifest.json"
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(json.dumps(manifest, default=_json_default, indent=2))

    def read_manifest(self) -> dict[str, Any] | None:
        path = self.root / "manifest.json"
        if not path.exists():
            return None
        try:
            return json.loads(path.read_text())  # type: ignore[no-any-return]
        except json.JSONDecodeError as exc:
            raise ValueError(f"Corrupt manifest at {path}: invalid JSON") from exc
