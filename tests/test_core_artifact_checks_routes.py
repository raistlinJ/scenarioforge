"""Route coverage for the CORE Check Artifacts start/status endpoints."""

from flask import Flask

from webapp.routes import core_artifact_checks


def _make_app(store, *, core_cfg=None, scheduled=None, fail_cfg=False):
    app = Flask(__name__)
    app.config["TESTING"] = True

    def _core_config_for_request(**kwargs):
        if fail_cfg:
            raise RuntimeError("no CORE VM configured")
        return core_cfg if core_cfg is not None else {"host": "vm", "ssh_password": "pw"}

    def _init(check_id, *, session_id, scenario):
        store[check_id] = {
            "check_id": check_id, "status": "queued", "session_id": session_id,
            "scenario": scenario, "step": 0, "total": 6, "checks": [], "overall": "running",
        }

    def _schedule(check_id, cfg, *, session_id, xml_path, scenario_label=None, logger=None):
        if scheduled is not None:
            scheduled.append({"check_id": check_id, "cfg": cfg, "session_id": session_id,
                              "xml_path": xml_path, "scenario_label": scenario_label})
        if check_id in store:
            store[check_id]["status"] = "running"

    def _get(check_id):
        return store.get(check_id)

    core_artifact_checks.register(
        app,
        core_config_for_request=_core_config_for_request,
        init_artifact_check_progress=_init,
        schedule_artifact_checks=_schedule,
        get_artifact_check_progress=_get,
        uuid_hex=lambda: "abc123",
    )
    return app.test_client()


def test_start_creates_check_and_schedules():
    store, scheduled = {}, []
    client = _make_app(store, scheduled=scheduled)
    resp = client.post("/core/check_artifacts/start",
                       data={"session_id": "12", "xml_path": "/o/s.xml", "scenario": "Lab1"})
    assert resp.status_code == 200
    body = resp.get_json()
    assert body["ok"] is True
    assert body["check_id"] == "abc123"
    assert store["abc123"]["session_id"] == 12
    assert scheduled and scheduled[0]["xml_path"] == "/o/s.xml"
    assert scheduled[0]["scenario_label"] == "Lab1"


def test_start_requires_session_and_xml():
    client = _make_app({})
    assert client.post("/core/check_artifacts/start", data={"xml_path": "/o/s.xml"}).status_code == 400
    assert client.post("/core/check_artifacts/start", data={"session_id": "12"}).status_code == 400


def test_start_reports_config_failure():
    client = _make_app({}, fail_cfg=True)
    resp = client.post("/core/check_artifacts/start",
                       data={"session_id": "12", "xml_path": "/o/s.xml"})
    assert resp.status_code == 400
    assert "CORE" in resp.get_json()["error"]


def test_status_returns_progress_then_404():
    store = {}
    client = _make_app(store)
    client.post("/core/check_artifacts/start", data={"session_id": "5", "xml_path": "/o/s.xml"})
    ok = client.get("/core/check_artifacts/status/abc123")
    assert ok.status_code == 200
    body = ok.get_json()
    assert body["ok"] is True
    assert body["status"] == "running"
    assert body["session_id"] == 5
    missing = client.get("/core/check_artifacts/status/nope")
    assert missing.status_code == 404
    assert missing.get_json()["status"] == "unknown"


def test_start_accepts_json_body():
    store, scheduled = {}, []
    client = _make_app(store, scheduled=scheduled)
    resp = client.post("/core/check_artifacts/start",
                       json={"session_id": 9, "path": "/o/j.xml", "scenario_name": "JLab"})
    assert resp.status_code == 200
    assert scheduled[0]["xml_path"] == "/o/j.xml"
    assert scheduled[0]["scenario_label"] == "JLab"
