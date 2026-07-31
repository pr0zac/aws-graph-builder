from __future__ import annotations

import networkx as nx

from aws_graph_builder.eval.simulator import PermissionQuery
from aws_graph_builder.privesc.registry import (
    PrivescFinding,
    TechniqueSpec,
    all_techniques,
    register,
)


def test_register_adds_to_all_techniques_and_returns_fn_unchanged() -> None:
    before = len(all_techniques())

    spec = TechniqueSpec(
        id="test_dummy_technique",
        name="Dummy Technique",
        description="A no-op technique used only to exercise @register.",
        reference_url="https://example.invalid/dummy",
        severity="low",
    )

    @register(spec)
    def detect(graph: nx.MultiDiGraph, principal_id: str, query: PermissionQuery) -> list[PrivescFinding]:
        return []

    after = all_techniques()
    assert len(after) == before + 1
    assert after[-1] == (spec, detect)

    # The decorated function is still directly callable/importable for its
    # own unit tests, unaffected by registration.
    result = detect(nx.MultiDiGraph(), "some-principal", PermissionQuery(nx.MultiDiGraph()))
    assert result == []


def test_all_techniques_returns_a_copy_not_the_live_registry() -> None:
    snapshot = all_techniques()
    original_length = len(snapshot)

    snapshot.append(("not", "a real entry"))  # type: ignore[arg-type]

    assert len(all_techniques()) == original_length


def test_real_technique_modules_register_themselves_once_imported() -> None:
    # Importing the techniques package triggers every module's @register
    # call as a side effect.
    import aws_graph_builder.privesc.techniques  # noqa: F401

    ids = {spec.id for spec, _fn in all_techniques()}
    assert {
        "create_access_key",
        "attach_policy",
        "create_policy_version",
        "update_assume_role_policy",
        "add_user_to_group",
        "create_login_profile",
    }.issubset(ids)
