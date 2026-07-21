from __future__ import annotations

import base64
import shutil

from webapp.app_backend import (
    _attack_flow_builder_afb_for_chain,
    _attack_graph_dot,
    _attack_graph_for_chain,
    _attack_graph_pdf_base64,
)


def _afb_action_edges(afb: dict) -> set[tuple[str, str]]:
    """Return action-to-action edges using the AFB anchor/latch representation."""
    objects = [item for item in afb.get("objects") or [] if isinstance(item, dict)]
    anchor_owner: dict[str, str] = {}
    latch_anchor: dict[str, str] = {}
    action_name: dict[str, str] = {}

    for item in objects:
        instance = str(item.get("instance") or "").strip()
        if not instance:
            continue
        if item.get("id") == "action":
            for pair in item.get("properties") or []:
                if isinstance(pair, list) and len(pair) == 2 and pair[0] == "name":
                    action_name[instance] = str(pair[1] or "")
            for anchor in (item.get("anchors") or {}).values():
                if anchor:
                    anchor_owner[str(anchor)] = instance
        if item.get("id") == "horizontal_anchor":
            for latch in item.get("latches") or []:
                if latch:
                    latch_anchor[str(latch)] = instance

    edges: set[tuple[str, str]] = set()
    for item in objects:
        if item.get("id") != "dynamic_line":
            continue
        source_owner = anchor_owner.get(latch_anchor.get(str(item.get("source") or ""), ""))
        target_owner = anchor_owner.get(latch_anchor.get(str(item.get("target") or ""), ""))
        if source_owner in action_name and target_owner in action_name:
            edges.add((action_name[source_owner], action_name[target_owner]))
    return edges


def test_attack_flow_and_attack_graph_share_the_same_ordered_path():
    chain = [
        {"id": "entry", "name": "Entry", "type": "docker"},
        {"id": "observe", "name": "Observe", "type": "docker"},
        {"id": "target", "name": "Target", "type": "docker"},
    ]
    assignments = [
        {"node_id": "entry", "id": "entry-generator", "produces": ["Token(entry)"]},
        {"node_id": "observe", "id": "observe-generator"},
        {"node_id": "target", "id": "target-generator", "requires": ["Token(entry)"]},
    ]

    graph = _attack_graph_for_chain(
        chain_nodes=chain,
        scenario_label="Export consistency",
        flag_assignments=assignments,
    )
    afb = _attack_flow_builder_afb_for_chain(
        chain_nodes=chain,
        scenario_label="Export consistency",
        flag_assignments=assignments,
    )

    assert graph["schema_version"] == 2
    assert graph["chain_order"] == ["entry", "observe", "target"]
    assert [(edge["source"], edge["target"]) for edge in graph["edges"]] == [
        ("entry", "observe"),
        ("observe", "target"),
    ]
    assert all(edge["relationship"] == "sequence" for edge in graph["edges"])
    # The prerequisite skips an ordered step, so it is provenance rather than
    # a second visual path that would disagree with the linear AFB export.
    assert [(edge["source"], edge["target"], edge["facts"]) for edge in graph["fact_dependencies"]] == [
        ("entry", "target", ["Token(entry)"]),
    ]
    assert _afb_action_edges(afb) == {
        ("Step 1: Find Flag -- entry-generator: Entry", "Step 2: Find Flag -- observe-generator: Observe"),
        ("Step 2: Find Flag -- observe-generator: Observe", "Step 3: Find Flag -- target-generator: Target"),
    }

    dot = _attack_graph_dot(graph)
    assert '"N0" -> "N1"' in dot
    assert '"N1" -> "N2"' in dot
    if shutil.which("dot"):
        pdf_base64 = _attack_graph_pdf_base64(dot)
        assert pdf_base64 is not None
        assert base64.b64decode(pdf_base64).startswith(b"%PDF")
