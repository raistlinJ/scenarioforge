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
    # vcmd itself succeeded (exit 0) every attempt; the stanza was simply
    # never applied. This is the real Quagga race, not an unreachable node.
    assert result["unreachable"] == []


# --------------------------------------------------------------------------- #
# A router vcmd can never reach is a different failure than one that answers
# but is missing its stanza -- and the two need different fixes
# --------------------------------------------------------------------------- #
#
# A real eval run's CORE session never left "configuration" for its whole
# 120s start timeout. Every vcmd call against its routers failed outright
# (their netns never came up), and the retry loop reported the identical
# generic "did not load" for that as it would for a router whose daemon was
# alive but simply hadn't applied its stanza yet -- sending the reader after
# a Quagga bootstrap race when the session itself was the problem.

def test_router_unreachable_for_the_whole_retry_window_is_classified_separately(monkeypatch):
    monkeypatch.setattr(
        cli,
        "_run_local_cmd",
        lambda args, **kwargs: SimpleNamespace(
            returncode=1, stdout="vcmd: could not open control socket\n"
        ),
    )
    monkeypatch.setattr(cli.time, "sleep", lambda _seconds: None)

    result = cli._ensure_router_control_planes(
        _Session(), 9, {4: ["OSPFv2"]}, attempts=3, retry_delay_s=0
    )

    assert result["ok"] is False
    assert result["missing"] == ["router-4"]
    assert result["unreachable"] == ["router-4"]
    assert "could not open control socket" in result["details"]["router-4"]["unreachable_output"]


def test_a_router_that_becomes_reachable_before_giving_up_is_not_marked_unreachable(monkeypatch):
    # Unreachable on the first attempt, then the netns comes up and vcmd
    # succeeds from then on -- classification must reflect the LAST attempt,
    # since that is what actually determined the final failure.
    attempts_seen = {"n": 0}

    def fake_run(args, **kwargs):
        if args[-2:] == ["-c", "show running-config"]:
            return SimpleNamespace(returncode=0, stdout="ip forwarding\n")
        attempts_seen["n"] += 1
        if attempts_seen["n"] == 1:
            return SimpleNamespace(returncode=1, stdout="vcmd: could not open control socket\n")
        return SimpleNamespace(returncode=0, stdout="")

    monkeypatch.setattr(cli, "_run_local_cmd", fake_run)
    monkeypatch.setattr(cli.time, "sleep", lambda _seconds: None)

    result = cli._ensure_router_control_planes(
        _Session(), 9, {4: ["OSPFv2"]}, attempts=3, retry_delay_s=0
    )

    assert result["missing"] == ["router-4"]
    assert result["unreachable"] == []


# --------------------------------------------------------------------------- #
# Retry budget must scale for a genuinely slow/busy VM, not just a brief race
# --------------------------------------------------------------------------- #
#
# A real eval run saw its CORE session never leave "configuration" for the
# whole 120s start timeout, and needed a 45s Docker restart-recovery in the
# same execute -- then this check gave up on every router after the old
# defaults' 5 x 0.5s = 2.5s, reporting "Routing control-plane configuration
# did not load" for a VM that was simply slower that run, not broken.

def test_default_retry_config_gives_a_realistic_total_budget(monkeypatch):
    monkeypatch.delenv("CORETG_ROUTING_CONTROL_PLANE_ATTEMPTS", raising=False)
    monkeypatch.delenv("CORETG_ROUTING_CONTROL_PLANE_RETRY_DELAY_S", raising=False)

    attempts, retry_delay_s = cli._routing_control_plane_retry_config()

    assert attempts * retry_delay_s >= 50.0, (
        "2.5s (the old 5x0.5s default) was too short for a VM already shown "
        "to need dozens of seconds elsewhere in the same run"
    )


def test_retry_config_reads_env_overrides(monkeypatch):
    monkeypatch.setenv("CORETG_ROUTING_CONTROL_PLANE_ATTEMPTS", "8")
    monkeypatch.setenv("CORETG_ROUTING_CONTROL_PLANE_RETRY_DELAY_S", "2.5")

    assert cli._routing_control_plane_retry_config() == (8, 2.5)


def test_retry_config_bounds_extreme_overrides(monkeypatch):
    monkeypatch.setenv("CORETG_ROUTING_CONTROL_PLANE_ATTEMPTS", "99999")
    monkeypatch.setenv("CORETG_ROUTING_CONTROL_PLANE_RETRY_DELAY_S", "0")

    attempts, retry_delay_s = cli._routing_control_plane_retry_config()

    assert attempts <= 120
    assert retry_delay_s >= 0.1


def test_retry_config_falls_back_to_defaults_on_garbage_env(monkeypatch):
    monkeypatch.setenv("CORETG_ROUTING_CONTROL_PLANE_ATTEMPTS", "not-a-number")
    monkeypatch.setenv("CORETG_ROUTING_CONTROL_PLANE_RETRY_DELAY_S", "also-not-a-number")

    assert cli._routing_control_plane_retry_config() == (40, 1.5)


def test_ensure_router_control_planes_default_signature_matches_retry_config():
    # The function's own defaults (used by any future caller that omits
    # attempts/retry_delay_s) must not silently regress to the old 2.5s budget.
    import inspect

    sig = inspect.signature(cli._ensure_router_control_planes)
    assert sig.parameters["attempts"].default == 40
    assert sig.parameters["retry_delay_s"].default == 1.5


# --------------------------------------------------------------------------- #
# _routing_control_plane_failure_message: the reader-facing verdict
# --------------------------------------------------------------------------- #

def test_failure_message_names_unreachable_routers_distinctly():
    msg = cli._routing_control_plane_failure_message({
        "missing": ["router-1", "router-2"],
        "unreachable": ["router-1", "router-2"],
    })
    assert "CORE never finished instantiating router-1, router-2" in msg
    assert "--start-timeout-s" in msg
    assert "Quagga configuration did not load" not in msg


def test_failure_message_names_a_genuine_quagga_race_distinctly():
    msg = cli._routing_control_plane_failure_message({
        "missing": ["router-3"],
        "unreachable": [],
    })
    assert "Quagga configuration did not load within the retry window on: router-3" in msg
    assert "CORE never finished instantiating" not in msg


def test_failure_message_reports_both_when_routers_split_across_causes():
    msg = cli._routing_control_plane_failure_message({
        "missing": ["router-1", "router-2", "router-3"],
        "unreachable": ["router-1"],
    })
    assert "CORE never finished instantiating router-1" in msg
    assert "Quagga configuration did not load within the retry window on: router-2, router-3" in msg


def test_failure_message_treats_missing_unreachable_key_as_all_reachable():
    # A result shape from before this classification existed (no `unreachable`
    # key at all) must not crash, and defaults to the safer assumption -- every
    # missing router is reported as a Quagga race, not silently dropped.
    msg = cli._routing_control_plane_failure_message({"missing": ["router-4"]})
    assert msg == "Quagga configuration did not load within the retry window on: router-4"


def test_failure_message_fallback_when_nothing_is_actually_missing():
    # Degenerate shape: ok=False was reported but `missing` is empty. Rather
    # than emit an empty message, fall back to the generic wording.
    msg = cli._routing_control_plane_failure_message({"missing": [], "unreachable": []})
    assert msg == "Routing control-plane configuration did not load on: "
