"""The Check Artifacts job must validate against the real source scenario XML.

The CORE session's ``file`` attribute (what the button forwards) is the VM-side
deployed session XML and carries no ScenarioEditor block, so the validator would
see an empty expected topology. The resolver recovers the saved source XML from
the session store.
"""

import os

import webapp.app_backend as b


_WITH_EDITOR = (
    "<Scenarios><Scenario name='S1'><ScenarioEditor>"
    "<PlanPreview>{}</PlanPreview></ScenarioEditor></Scenario></Scenarios>"
)
_DEPLOYED = "<scenario name='pycore'><devices/><networks/></scenario>"


def _write(tmp_path, name, text):
    p = tmp_path / name
    p.write_text(text, encoding="utf-8")
    return str(p)


def test_xml_has_scenario_editor(tmp_path):
    src = _write(tmp_path, "source.xml", _WITH_EDITOR)
    deployed = _write(tmp_path, "session-deployed.xml", _DEPLOYED)
    assert b._xml_has_scenario_editor(src) is True
    assert b._xml_has_scenario_editor(deployed) is False
    assert b._xml_has_scenario_editor("/nonexistent.xml") is False


def test_resolver_recovers_source_xml_from_session_store(tmp_path, monkeypatch):
    src = _write(tmp_path, "Scenario1.xml", _WITH_EDITOR)
    deployed = "/tmp/pycore.1/session-deployed.xml"
    store = {src: {"session_id": 1, "scenario_norm": "scenario1",
                   "scenario_name": "Scenario1", "updated_at": "2026-08-01T10:00:00Z"}}
    monkeypatch.setattr(b, "_load_core_sessions_store", lambda: store)

    resolved = b._resolve_check_source_xml(
        deployed, scenario_label="Scenario1", session_id=1, core_cfg={},
    )
    assert resolved == src


def test_resolver_keeps_passed_path_when_already_a_source_xml(tmp_path, monkeypatch):
    src = _write(tmp_path, "Scenario1.xml", _WITH_EDITOR)
    monkeypatch.setattr(b, "_load_core_sessions_store", lambda: {})
    # A real source XML is used as-is without consulting the store.
    assert b._resolve_check_source_xml(src, scenario_label="Scenario1", session_id=1, core_cfg={}) == src


def test_resolver_prefers_most_recent_matching_entry(tmp_path, monkeypatch):
    old = _write(tmp_path, "old.xml", _WITH_EDITOR)
    new = _write(tmp_path, "new.xml", _WITH_EDITOR)
    store = {
        old: {"session_id": 1, "scenario_norm": "s", "updated_at": "2026-07-01T00:00:00Z"},
        new: {"session_id": 1, "scenario_norm": "s", "updated_at": "2026-08-01T00:00:00Z"},
    }
    monkeypatch.setattr(b, "_load_core_sessions_store", lambda: store)
    resolved = b._resolve_check_source_xml(
        "/tmp/pycore.1/session-deployed.xml", scenario_label="s", session_id=1, core_cfg={},
    )
    assert resolved == new
