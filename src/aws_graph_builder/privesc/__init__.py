"""Privilege-escalation technique catalog.

`registry.py` defines `TechniqueSpec` (technique metadata), `PrivescFinding`
(a single detected instance), the `DetectorFn` protocol, and the `@register`
decorator detectors use to add themselves to the catalog. `techniques/` holds
one module per detected technique. `engine.py` runs the full catalog over a
graph already evaluated by `eval.engine.evaluate_iam_permissions` (so
`EffectivePermission`/`CanAssume` edges already exist), materializing
`PrivescPath` edges and returning the flat findings list for the CLI layer to
attach to the JSON output document's `"findings"` key.

See ``aws-graph-builder.md`` -> "Privesc technique catalog" for the design
this package implements.
"""

from __future__ import annotations
