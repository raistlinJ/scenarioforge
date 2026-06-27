import json
import os
import time
import xml.etree.ElementTree as ET

from webapp import app_backend
from webapp import flow_prepare_preview_execute
from webapp import flow_prepare_preview_helpers


class _FinalizeDeps:
    @staticmethod
    def _enrich_flow_state_with_artifacts(flow_state):
        return flow_state

    @staticmethod
    def _flow_strip_runtime_sensitive_fields(assignments):
        return [dict(item) if isinstance(item, dict) else item for item in (assignments or [])]

    @staticmethod
    def _canonicalize_flow_assignment_paths(assignment):
        return dict(assignment)

    @staticmethod
    def _abs_path_or_original(path):
        return str(path or "")

    @staticmethod
    def _iso_now():
        return "2026-06-24T00:00:00Z"

    @staticmethod
    def _flow_normalize_fact_override(value):
        return value if isinstance(value, list) else []


class _FinalizeHelpers:
    def __init__(self):
        self.captured_flow_meta = None

    def persist_prepare_preview_plan(self, **kwargs):
        self.captured_flow_meta = kwargs["flow_meta"]
        return {
            "ok": True,
            "out_path": kwargs["base_plan_path"],
            "meta": {
                "xml_path": kwargs["base_plan_path"],
                "flow": kwargs["flow_meta"],
            },
        }

    @staticmethod
    def build_host_ip_map(_host_by_id, *, preview_host_ip4):
        return {}

    @staticmethod
    def collect_realized_flags(_assignments):
        return []

    @staticmethod
    def cleanup_generated_run_dirs(**_kwargs):
        return []

    def build_prepare_preview_success_payload(self, **_kwargs):
        return {
            "ok": True,
            "persisted_allow_node_duplicates": bool((self.captured_flow_meta or {}).get("allow_node_duplicates")),
            "persisted_chain_ids": [
                str(item.get("id") or "")
                for item in ((self.captured_flow_meta or {}).get("chain") or [])
                if isinstance(item, dict)
            ],
        }


def test_finalize_prepare_preview_persists_duplicate_node_allowance(tmp_path) -> None:
    scenario = "DuplicateFlowChain"
    xml_path = tmp_path / "scenario.xml"
    xml_path.write_text(
        f'<Scenarios><Scenario name="{scenario}"><ScenarioEditor/></Scenario></Scenarios>',
        encoding="utf-8",
    )
    helpers = _FinalizeHelpers()

    with app_backend.app.test_request_context("/"):
        response, status = flow_prepare_preview_execute._finalize_prepare_preview_response(
            _FinalizeDeps(),
            helpers=helpers,
            flag_assignments=[
                {"node_id": "docker-2", "id": "gen-a", "type": "flag-generator"},
                {"node_id": "docker-2", "id": "gen-b", "type": "flag-generator"},
            ],
            flow_run_remote=False,
            run_generators=True,
            run_generators_request=True,
            mode="resolve",
            base_plan_path=str(xml_path),
            scenario_label=scenario,
            scenario_norm=scenario.lower(),
            length=2,
            requested_length=2,
            dependency_level=1,
            allow_node_duplicates=True,
            chain_nodes=[
                {"id": "docker-2", "name": "docker-2", "type": "docker"},
                {"id": "docker-2", "name": "docker-2", "type": "docker"},
            ],
            flags_enabled=True,
            flow_valid=True,
            flow_errors=[],
            meta={"xml_path": str(xml_path)},
            preview={"hosts": []},
            host_by_id={},
            preview_host_ip4=lambda _host: "",
            created_run_dirs=[],
            failed_run_dirs=[],
            cleanup_generated_artifacts=False,
            stats={},
            best_effort=False,
            started_at=time.monotonic(),
            generator_runs=[],
            progress_log=[],
            generation_failures=[],
            generation_skipped=[],
            debug_dag=False,
            dag_debug=None,
            warning=None,
            backend=app_backend,
            flow_errors_detail=[],
            phase_timings={},
            finalize_started_at=time.monotonic(),
        )

    assert status == 200
    data = response.get_json()
    assert data["persisted_allow_node_duplicates"] is True
    assert data["persisted_chain_ids"] == ["docker-2", "docker-2"]
    assert helpers.captured_flow_meta["allow_node_duplicates"] is True


def test_persist_prepare_preview_plan_fails_when_flow_state_write_fails(tmp_path) -> None:
    scenario = "DuplicateFlowChain"
    xml_path = tmp_path / "scenario.xml"
    xml_path.write_text(
        f'<Scenarios><Scenario name="{scenario}"><ScenarioEditor/></Scenario></Scenarios>',
        encoding="utf-8",
    )
    planner_calls: list[tuple[str, str]] = []

    class FakeBackend:
        @staticmethod
        def _iso_now():
            return "2026-06-24T00:00:00Z"

        @staticmethod
        def _existing_xml_path_or_none(path):
            return str(path) if path and os.path.exists(str(path)) else ""

        @staticmethod
        def _latest_xml_path_for_scenario(_scenario):
            return ""

        @staticmethod
        def _update_plan_preview_in_xml(_xml_path, _scenario_label, _payload):
            return True, ""

        @staticmethod
        def _update_flow_state_in_xml(_xml_path, _scenario_label, _flow_meta):
            return False, "Flow chain reuses nodes while duplicates are disabled"

        @staticmethod
        def _planner_set_plan(scenario_norm, *, plan_path, xml_path, seed=None):
            planner_calls.append((scenario_norm, plan_path))

    result = flow_prepare_preview_helpers.persist_prepare_preview_plan(
        meta={"xml_path": str(xml_path)},
        preview={"hosts": []},
        flow_meta={
            "scenario": scenario,
            "chain": [{"id": "docker-2"}, {"id": "docker-2"}],
            "allow_node_duplicates": False,
            "flag_assignments": [],
        },
        base_plan_path=str(xml_path),
        scenario_label=scenario,
        scenario_norm=scenario.lower(),
        backend=FakeBackend,
    )

    assert result["ok"] is False
    assert "FlowState" in result["error"]
    assert "duplicates are disabled" in result["error"]
    assert planner_calls == []


def test_persist_prepare_preview_plan_writes_duplicate_flow_state_when_allowed(tmp_path) -> None:
    scenario = "DuplicateFlowChain"
    xml_path = tmp_path / "scenario.xml"
    xml_path.write_text(
        f'<Scenarios><Scenario name="{scenario}"><ScenarioEditor/></Scenario></Scenarios>',
        encoding="utf-8",
    )

    result = flow_prepare_preview_helpers.persist_prepare_preview_plan(
        meta={"xml_path": str(xml_path)},
        preview={"hosts": []},
        flow_meta={
            "scenario": scenario,
            "chain": [{"id": "docker-2"}, {"id": "docker-2"}],
            "chain_ids": ["docker-2", "docker-2"],
            "allow_node_duplicates": True,
            "flag_assignments": [
                {"node_id": "docker-2", "id": "gen-a", "type": "flag-generator"},
                {"node_id": "docker-2", "id": "gen-b", "type": "flag-generator"},
            ],
        },
        base_plan_path=str(xml_path),
        scenario_label=scenario,
        scenario_norm=scenario.lower(),
        backend=app_backend,
    )

    assert result["ok"] is True, result
    root = ET.parse(str(xml_path)).getroot()
    flow_el = root.find("./Scenario/ScenarioEditor/FlagSequencing/FlowState")
    assert flow_el is not None and (flow_el.text or "").strip()
    persisted = json.loads(flow_el.text or "{}")
    assert persisted.get("allow_node_duplicates") is True
    assert persisted.get("chain_ids") == ["docker-2", "docker-2"]
