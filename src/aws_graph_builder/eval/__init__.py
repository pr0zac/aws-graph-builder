"""Policy evaluation engine: parses raw IAM policy JSON into `Statement`s
(`policy_document.py`), matches action/resource wildcards and (staticly
resolvable) conditions (`matcher.py`), resolves identity/boundary statements
into a deny-filtered set of `Grant`s and answers `PermissionQuery.can()`
questions (`simulator.py`), evaluates trust policies into `CanAssume`/
`IdentifiesVia` edges (`trust.py`), and orchestrates all of the above over a
structural graph produced by `graph.builder` (`engine.py`).

See ``aws-graph-builder.md`` -> "Policy evaluation engine" for the design
this package implements, and this package's `engine.py` docstring for the
exact scoping decisions made for Phase 2 (IAM-only; no SCP/resource-policy
intersection yet -- that's Phase 4).
"""

from __future__ import annotations
