"""Deterministic cache file naming.

Cache entries are stored as one JSON file per (operation, disambiguator) pair.
`operation` is always caller-supplied in snake_case (e.g. "get_bucket_policy")
matching the boto3 client method name — this module does no case conversion.
"""

from __future__ import annotations

_UNSAFE_CHARS = ("/", ":")


def _sanitize(disambiguator: str) -> str:
    """Make a disambiguator (which may be an ARN or bucket name) filesystem-safe."""
    sanitized = disambiguator
    for char in _UNSAFE_CHARS:
        sanitized = sanitized.replace(char, "_")
    return sanitized


def cache_filename(operation: str, disambiguator: str | None = None) -> str:
    """Return the cache filename for an operation, optionally scoped to a resource.

    Examples:
        cache_filename("get_account_authorization_details") -> "get_account_authorization_details.json"
        cache_filename("get_bucket_policy", "mybucket") -> "get_bucket_policy__mybucket.json"
    """
    if disambiguator is None:
        return f"{operation}.json"
    return f"{operation}__{_sanitize(disambiguator)}.json"
