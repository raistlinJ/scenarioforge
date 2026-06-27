from __future__ import annotations

import contextlib
import json
import subprocess

import pytest

from webapp import app_backend as backend


def test_remote_core_target_host_rewrites_same_machine_public_host_to_loopback():
    assert backend._remote_core_target_host(
        {
            'host': '129.108.4.37',
            'port': 50051,
            'ssh_host': '129.108.4.37',
            'ssh_port': 10000,
            'ssh_username': 'sampleuser',
            'ssh_password': 'pw',
        }
    ) == '127.0.0.1'


def test_remote_core_target_host_preserves_distinct_grpc_host():
    assert backend._remote_core_target_host(
        {
            'host': '10.10.10.20',
            'port': 50051,
            'ssh_host': '129.108.4.37',
            'ssh_port': 10000,
            'ssh_username': 'sampleuser',
            'ssh_password': 'pw',
        }
    ) == '10.10.10.20'


def test_execute_remote_core_session_action_rewrites_same_machine_host_to_loopback(monkeypatch):
    captured = {}

    def _fake_run_remote_python_json(core_cfg, script, logger=None, label=None, meta=None, command_desc=None, timeout=None):
        captured['label'] = label
        captured['command_desc'] = command_desc
        captured['script'] = script
        return {'ok': True}

    monkeypatch.setattr(backend, '_run_remote_python_json', _fake_run_remote_python_json)

    payload = backend._execute_remote_core_session_action(
        {
            'host': '12.0.0.100',
            'port': 50051,
            'ssh_host': '12.0.0.100',
            'ssh_port': 22,
            'ssh_username': 'sampleuser',
            'ssh_password': 'pw',
        },
        'delete',
        1,
        logger=backend.app.logger,
    )

    assert payload == {'ok': True}
    assert captured.get('label') == 'core.delete_session'
    assert '127.0.0.1:50051' in str(captured.get('command_desc') or '')


def test_grpc_save_current_session_xml_falls_back_to_remote_python(tmp_path, monkeypatch):
    @contextlib.contextmanager
    def _broken_core_connection(_cfg):
        raise RuntimeError("local grpc failed")
        yield

    downloaded = {}
    removed = []

    monkeypatch.setattr(backend, "_core_connection", _broken_core_connection)
    monkeypatch.setattr(backend, "_require_core_ssh_credentials", lambda cfg: cfg)

    def _fake_run_remote_python_json(core_cfg, script, logger=None, label=None, command_desc=None, timeout=None):
        assert label == "core.save_xml"
        assert "save_xml" in str(command_desc or "")
        return {
            "session_id": "1",
            "output_path": "/tmp/scenarioforge/core-post/session-1.xml",
        }

    monkeypatch.setattr(backend, "_run_remote_python_json", _fake_run_remote_python_json)

    def _fake_download(core_cfg, remote_path, local_path):
        downloaded["remote_path"] = remote_path
        downloaded["local_path"] = local_path
        with open(local_path, "w", encoding="utf-8") as handle:
            handle.write("<scenario />\n")

    monkeypatch.setattr(backend, "_download_remote_file", _fake_download)
    monkeypatch.setattr(backend, "_remove_remote_file", lambda core_cfg, remote_path: removed.append(remote_path))

    out = backend._grpc_save_current_session_xml_with_config(
        {
            "host": "localhost",
            "port": 50051,
            "ssh_host": "core-vm",
            "ssh_port": 22,
            "ssh_username": "core",
            "ssh_password": "pw",
        },
        str(tmp_path),
        session_id="1",
    )

    assert out == str(tmp_path / "session-1.xml")
    assert downloaded["remote_path"] == "/tmp/scenarioforge/core-post/session-1.xml"
    assert downloaded["local_path"] == str(tmp_path / "session-1.xml")
    assert removed == ["/tmp/scenarioforge/core-post/session-1.xml"]


def test_grpc_save_current_session_xml_falls_back_to_local_core_python(tmp_path, monkeypatch):
    @contextlib.contextmanager
    def _missing_local_core(_cfg):
        raise ModuleNotFoundError("No module named 'core'")
        yield

    calls = []

    monkeypatch.setattr(backend, "_core_connection", _missing_local_core)
    monkeypatch.setattr(
        backend,
        "_require_core_ssh_credentials",
        lambda cfg: (_ for _ in ()).throw(RuntimeError("missing ssh")),
    )
    monkeypatch.setattr(
        backend,
        "_candidate_remote_python_interpreters",
        lambda _cfg: ["/opt/core/venv/bin/python"],
    )

    def _fake_run(cmd, stdout=None, stderr=None, text=None, timeout=None):
        calls.append(list(cmd))
        assert cmd[:2] == ["/opt/core/venv/bin/python", "-c"]
        out_path = tmp_path / "session-7.xml"
        out_path.write_text("<scenario />\n", encoding="utf-8")
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=json.dumps({"session_id": "7", "output_path": str(out_path)}) + "\n",
            stderr="",
        )

    monkeypatch.setattr(backend.subprocess, "run", _fake_run)

    out = backend._grpc_save_current_session_xml_with_config(
        {"host": "localhost", "port": 50051, "venv_bin": "/opt/core/venv/bin"},
        str(tmp_path),
        session_id="7",
    )

    assert out == str(tmp_path / "session-7.xml")
    assert calls
    script = str(calls[0][2])
    assert "127.0.0.1:50051" in script
    assert "CoreGrpcClient" in script


def test_grpc_save_current_session_xml_uses_local_core_python_when_remote_fallback_fails(tmp_path, monkeypatch):
    @contextlib.contextmanager
    def _missing_local_core(_cfg):
        raise ModuleNotFoundError("No module named 'core'")
        yield

    monkeypatch.setattr(backend, "_core_connection", _missing_local_core)
    monkeypatch.setattr(backend, "_require_core_ssh_credentials", lambda cfg: dict(cfg, ssh_username="core", ssh_password="pw"))
    monkeypatch.setattr(backend, "_run_remote_python_json", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("ssh failed")))
    monkeypatch.setattr(
        backend,
        "_candidate_remote_python_interpreters",
        lambda _cfg: ["/opt/core/venv/bin/python"],
    )

    def _fake_run(cmd, stdout=None, stderr=None, text=None, timeout=None):
        out_path = tmp_path / "session-9.xml"
        out_path.write_text("<scenario />\n", encoding="utf-8")
        return subprocess.CompletedProcess(
            cmd,
            0,
            stdout=json.dumps({"session_id": "9", "output_path": str(out_path)}) + "\n",
            stderr="",
        )

    monkeypatch.setattr(backend.subprocess, "run", _fake_run)

    out = backend._grpc_save_current_session_xml_with_config(
        {
            "host": "127.0.0.1",
            "port": 50051,
            "ssh_host": "127.0.0.1",
            "ssh_username": "core",
            "ssh_password": "pw",
            "venv_bin": "/opt/core/venv/bin",
        },
        str(tmp_path),
        session_id="9",
    )

    assert out == str(tmp_path / "session-9.xml")


def test_grpc_save_current_session_xml_reraises_when_fallback_unavailable(tmp_path, monkeypatch):
    @contextlib.contextmanager
    def _broken_core_connection(_cfg):
        raise RuntimeError("local grpc failed")
        yield

    monkeypatch.setattr(backend, "_core_connection", _broken_core_connection)
    monkeypatch.setattr(backend, "_require_core_ssh_credentials", lambda cfg: (_ for _ in ()).throw(RuntimeError("missing ssh")))

    try:
        backend._grpc_save_current_session_xml_with_config({"host": "localhost", "port": 50051}, str(tmp_path), session_id="1")
        assert False, "expected helper to re-raise original exception"
    except RuntimeError as exc:
        assert str(exc) == "local grpc failed"


def test_core_connection_via_ssh_does_not_label_body_error_as_tunnel_failure(monkeypatch, caplog):
    closed = []

    class _Tunnel:
        def __init__(self, **_kwargs):
            pass

        def start(self):
            return "127.0.0.1", 43210

        def close(self):
            closed.append(True)

    monkeypatch.setattr(backend, "_SshTunnel", _Tunnel)

    with pytest.raises(ModuleNotFoundError, match="No module named 'core'"):
        with backend._core_connection_via_ssh(
            {
                "host": "localhost",
                "port": 50051,
                "ssh_host": "core-vm",
                "ssh_port": 22,
                "ssh_username": "core",
                "ssh_password": "pw",
            }
        ):
            raise ModuleNotFoundError("No module named 'core'")

    assert closed == [True]
    assert "SSH tunnel" not in caplog.text


def test_core_connection_via_ssh_logs_actual_setup_failure(monkeypatch, caplog):
    class _Tunnel:
        def __init__(self, **_kwargs):
            pass

        def start(self):
            raise RuntimeError("authentication failed")

        def close(self):
            pass

    monkeypatch.setattr(backend, "_SshTunnel", _Tunnel)

    with pytest.raises(RuntimeError, match="authentication failed"):
        with backend._core_connection_via_ssh(
            {
                "host": "localhost",
                "port": 50051,
                "ssh_host": "core-vm",
                "ssh_port": 22,
                "ssh_username": "core",
                "ssh_password": "pw",
            }
        ):
            pass

    assert "SSH tunnel setup failed: authentication failed" in caplog.text
    assert "Did you mean" not in caplog.text
