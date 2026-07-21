from __future__ import annotations

import copy
import json
from pathlib import Path

from jsonschema import Draft202012Validator

from webapp.app_backend import _attack_graph_for_chain


SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "attack_graph" / "attack_graph_v2.schema.json"


def _schema() -> dict:
    return json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))


def _export() -> dict:
    return _attack_graph_for_chain(
        chain_nodes=[
            {"id": "entry", "name": "Entry", "type": "docker", "ipv4": "10.0.0.1"},
            {"id": "target", "name": "Target", "type": "docker", "is_vuln": True},
        ],
        scenario_label="Schema validation",
        flag_assignments=[
            {
                "node_id": "entry",
                "id": "entry-generator",
                "name": "Entry generator",
                "type": "flag-node-generator",
                "resolved_outputs": {"Token(entry)": "value"},
                "produces": ["Token(entry)"],
            },
            {
                "node_id": "target",
                "id": "target-generator",
                "name": "Target generator",
                "type": "flag-generator",
                "requires": ["Token(entry)"],
            },
        ],
    )


def test_attack_graph_v2_schema_is_valid_and_accepts_current_export():
    schema = _schema()
    Draft202012Validator.check_schema(schema)

    errors = list(Draft202012Validator(schema).iter_errors(_export()))

    assert errors == []


def test_attack_graph_v2_schema_rejects_invalid_contract_fields():
    validator = Draft202012Validator(_schema())

    wrong_version = copy.deepcopy(_export())
    wrong_version["schema_version"] = 1
    assert list(validator.iter_errors(wrong_version))

    missing_relationship = copy.deepcopy(_export())
    del missing_relationship["edges"][0]["relationship"]
    assert list(validator.iter_errors(missing_relationship))

    invalid_fact_dependency = copy.deepcopy(_export())
    invalid_fact_dependency["fact_dependencies"][0]["relationship"] = "sequence"
    assert list(validator.iter_errors(invalid_fact_dependency))
