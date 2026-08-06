from types import SimpleNamespace

from scenarioforge import cli


class _Node:
    def __init__(self, name):
        self.name = name


class _Session:
    def get_node(self, node_id):
        assert node_id == 4
        return _Node("router-4")


def test_router_control_plane_retries_until_protocol_stanza_is_loaded(monkeypatch):
    inspections = iter(["ip forwarding\n", "router ospf\n ip forwarding\n"])
    calls = []

    def fake_run(args, **kwargs):
        calls.append(args)
        if args[-2:] == ["-c", "show running-config"]:
            return SimpleNamespace(returncode=0, stdout=next(inspections))
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(cli, "_run_local_cmd", fake_run)
    monkeypatch.setattr(cli.time, "sleep", lambda _seconds: None)

    result = cli._ensure_router_control_planes(
        _Session(),
        7,
        {4: ["OSPFv2"]},
        attempts=3,
        retry_delay_s=0,
    )

    assert result["ok"] is True
    assert result["configured"] == ["router-4"]
    assert result["missing"] == []
    assert sum(args[-1] == "-b" for args in calls) == 2
    assert all("/tmp/pycore.7/router-4" in args for args in calls)


def test_router_control_plane_reports_persistently_missing_stanza(monkeypatch):
    monkeypatch.setattr(
        cli,
        "_run_local_cmd",
        lambda args, **kwargs: SimpleNamespace(
            returncode=0,
            stdout="ip forwarding\n" if args[-2:] == ["-c", "show running-config"] else "",
        ),
    )
    monkeypatch.setattr(cli.time, "sleep", lambda _seconds: None)

    result = cli._ensure_router_control_planes(
        _Session(), 9, {4: ["OSPFv2"]}, attempts=2, retry_delay_s=0
    )

    assert result["ok"] is False
    assert result["missing"] == ["router-4"]
    assert result["details"]["router-4"]["missing"] == ["router ospf"]
