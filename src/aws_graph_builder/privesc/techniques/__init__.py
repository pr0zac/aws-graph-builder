"""Technique detector modules -- imported here purely for their `@register`
side effects, so `privesc.engine.run_privesc_detection` triggering
`import aws_graph_builder.privesc.techniques` registers the full catalog.

New techniques are added by dropping a new module here (per
aws-graph-builder.md's privesc catalog design) and adding it to this import
list -- nothing in `privesc/engine.py` or `privesc/registry.py` needs to
change.
"""

from __future__ import annotations

from aws_graph_builder.privesc.techniques import (
    add_user_to_group,
    attach_policy,
    create_access_key,
    create_login_profile,
    create_policy_version,
    pass_role_ec2,
    pass_role_lambda,
    update_assume_role_policy,
)

__all__ = [
    "add_user_to_group",
    "attach_policy",
    "create_access_key",
    "create_login_profile",
    "create_policy_version",
    "pass_role_ec2",
    "pass_role_lambda",
    "update_assume_role_policy",
]
