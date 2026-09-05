"""Power-on approval and runtime behavior of the installed host shortcuts."""
import importlib.util
from pathlib import Path
from types import SimpleNamespace
import subprocess
from unittest.mock import Mock

import pytest

SOURCE = Path(__file__).resolve().parents[1] / "scripts/provision/vmware-workstation-linux/desktop-launcher.py"
spec = importlib.util.spec_from_file_location("vmware_desktop_launcher", SOURCE)
launcher = importlib.util.module_from_spec(spec)
spec.loader.exec_module(launcher)


@pytest.fixture(params=["ws", "fusion"])
def options(request, tmp_path):
    paths = {}
    for name in ("core", "app", "participant"):
        path = tmp_path / f"{name} VM.vmx"
        path.touch()
        paths[name] = str(path)
    return SimpleNamespace(mode="browser", platform=request.param, vmrun="vmrun", vmware="vmware",
                           fusion_app="/Applications/Custom Fusion.app", **paths)


def fake_runtime(monkeypatch, options, running=(), consent=True, fail=None):
    state = set(running)
    calls, prompts = [], []

    def command(args, timeout=30):
        calls.append(args)
        if args[0] == options.vmrun:
            action = args[3]
            if action == fail:
                return subprocess.CompletedProcess(args, 1, "", "VMware failed")
            if action == "list":
                return subprocess.CompletedProcess(args, 0, f"Total running VMs: {len(state)}\n" + "\n".join(sorted(state)), "")
            if action == "start":
                state.add(args[4])
            if action == "getGuestIPAddress":
                return subprocess.CompletedProcess(args, 0, "192.168.42.55\n", "")
        return subprocess.CompletedProcess(args, 0, "", "")

    def dialog(message, platform, question=False):
        prompts.append((message, question))
        return consent

    def popen(args, **kwargs):
        result = command(args)
        if result.stderr:
            kwargs["stdout"].write(result.stderr.encode())
        return Mock(poll=Mock(return_value=result.returncode))

    monkeypatch.setattr(launcher, "command", command)
    monkeypatch.setattr(launcher, "dialog", dialog)
    monkeypatch.setattr(launcher.subprocess, "Popen", popen)
    return state, calls, prompts


def starts(calls):
    return [args[4] for args in calls if len(args) > 4 and args[3] == "start"]


@pytest.mark.parametrize("mode", ["browser", "participant"])
def test_running_vms_open_without_prompt_or_restart(monkeypatch, options, mode):
    options.mode = mode
    required = [options.core, options.app if mode == "browser" else options.participant]
    _, calls, prompts = fake_runtime(monkeypatch, options, required)
    assert launcher.launch(options) == 0
    assert not prompts
    assert not starts(calls)
    if mode == "browser":
        assert calls[-1] == ["open" if options.platform == "fusion" else "xdg-open", "https://192.168.42.55/"]
    else:
        assert calls[-1][-1] == options.participant


@pytest.mark.parametrize("mode", ["browser", "participant"])
def test_one_confirmation_starts_only_required_vms_in_order(monkeypatch, options, mode):
    options.mode = mode
    _, calls, prompts = fake_runtime(monkeypatch, options)
    assert launcher.launch(options) == 0
    assert len(prompts) == 1 and prompts[0][1] is True
    assert "CORE VM" in prompts[0][0]
    assert ("APP VM" if mode == "browser" else "Participant VM") in prompts[0][0]
    assert starts(calls) == [options.core, options.app if mode == "browser" else options.participant]
    assert all(args[-1] == "gui" for args in calls if len(args) > 4 and args[3] == "start")


@pytest.mark.parametrize("mode", ["browser", "participant"])
def test_cancel_starts_nothing_and_does_not_open(monkeypatch, options, mode):
    options.mode = mode
    _, calls, prompts = fake_runtime(monkeypatch, options, consent=False)
    assert launcher.launch(options) == 0
    assert len(prompts) == 1
    assert not starts(calls)
    assert all(args[0] == "vmrun" and args[3] == "list" for args in calls)


def test_partial_running_only_prompts_for_stopped_vm(monkeypatch, options):
    _, calls, prompts = fake_runtime(monkeypatch, options, [options.core])
    assert launcher.launch(options) == 0
    assert starts(calls) == [options.app]
    assert "CORE VM" not in prompts[0][0]


@pytest.mark.parametrize("failure", ["list", "start"])
def test_vmware_failure_stops_launch_with_error(monkeypatch, options, failure):
    _, calls, prompts = fake_runtime(monkeypatch, options, fail=failure)
    assert launcher.launch(options) == 1
    assert prompts[-1][1] is False
    assert "Could not" in prompts[-1][0]
    assert all(args[0] == "vmrun" for args in calls)
    if failure == "list":
        assert not starts(calls)
        assert not any(question for _, question in prompts)


def test_missing_vm_is_reported_before_prompting(monkeypatch, options):
    Path(options.core).unlink()
    _, calls, prompts = fake_runtime(monkeypatch, options)
    assert launcher.launch(options) == 1
    assert not calls
    assert "CORE VM was not found" in prompts[0][0]
    assert prompts[0][1] is False


def test_vm_started_during_confirmation_is_not_started_twice(monkeypatch, options):
    state, calls, _ = fake_runtime(monkeypatch, options)
    def confirm(*args, **kwargs):
        state.add(options.core)
        return True
    monkeypatch.setattr(launcher, "dialog", confirm)
    assert launcher.launch(options) == 0
    assert starts(calls) == [options.app]


def test_network_not_ready_reports_retry_instead_of_opening_stale_url(monkeypatch, options):
    _, calls, prompts = fake_runtime(monkeypatch, options, [options.core, options.app], fail="getGuestIPAddress")
    clock = iter([0, 121])
    monkeypatch.setattr(launcher.time, "monotonic", lambda: next(clock))
    assert launcher.launch(options) == 1
    assert "network address is not ready" in prompts[-1][0]
    assert all(args[0] == "vmrun" or args[:3] == ["open", "-g", "-a"] for args in calls)


@pytest.mark.parametrize("platform", ["fusion", "ws"])
def test_native_dialog_cancellation_is_not_consent(monkeypatch, platform):
    calls = []
    def command(args, timeout=30):
        calls.append(args)
        return subprocess.CompletedProcess(args, 1, "", "User canceled. (-128)" if platform == "fusion" else "")
    monkeypatch.setattr(launcher, "command", command)
    monkeypatch.setattr(launcher.shutil, "which", lambda _: "/usr/bin/zenity")
    monkeypatch.setattr(launcher.sys.stdin, "isatty", lambda: False)
    text = 'CORE VM: "quoted" and $(literal)'
    assert launcher.dialog(text, platform, question=True) is False
    if platform == "fusion":
        assert calls[0][-1] == text
        assert text not in calls[0][2]
    else:
        assert "--text=" + text in calls[0]


def test_no_dialog_and_no_terminal_never_starts_silently(monkeypatch):
    monkeypatch.setattr(launcher.shutil, "which", lambda _: None)
    monkeypatch.setattr(launcher.sys.stdin, "isatty", lambda: False)
    assert launcher.dialog("Start CORE?", "ws", question=True) is False


@pytest.mark.parametrize("returncode", [None, 0, 1])
def test_start_uses_actual_power_state_even_if_client_hangs_or_fails(monkeypatch, options, returncode):
    process = Mock(poll=Mock(return_value=returncode))
    monkeypatch.setattr(launcher.subprocess, "Popen", Mock(return_value=process))
    monkeypatch.setattr(launcher, "running_vms", Mock(return_value={options.core}))
    launcher.start_vm(options, "CORE VM", options.core)
    assert process.terminate.call_count == (1 if returncode is None else 0)
    process.kill.assert_not_called()


def test_start_waits_for_power_state_after_client_exits(monkeypatch, options):
    process = Mock(poll=Mock(return_value=0))
    monkeypatch.setattr(launcher.subprocess, "Popen", Mock(return_value=process))
    status = Mock(side_effect=[set(), {options.core}])
    monkeypatch.setattr(launcher, "running_vms", status)
    monkeypatch.setattr(launcher.time, "sleep", Mock())
    launcher.start_vm(options, "CORE VM", options.core)
    assert status.call_count == 2
    process.terminate.assert_not_called()


@pytest.mark.parametrize("status_error", [False, True])
def test_start_timeout_reports_recovery_and_reaps_only_client(monkeypatch, options, status_error):
    process = Mock(poll=Mock(return_value=None))
    process.wait.side_effect = [subprocess.TimeoutExpired("vmrun", 5), 0]
    popen = Mock(return_value=process)
    monkeypatch.setattr(launcher.subprocess, "Popen", popen)
    status = Mock(side_effect=launcher.LaunchError("status unavailable")) if status_error else Mock(return_value=set())
    monkeypatch.setattr(launcher, "running_vms", status)
    monkeypatch.setattr(launcher.time, "monotonic", Mock(side_effect=[0, 121]))
    with pytest.raises(launcher.LaunchError, match="check the VM window") as error:
        launcher.start_vm(options, "CORE VM", options.core)
    assert ("status unavailable" in str(error.value)) == status_error
    process.terminate.assert_called_once_with()
    process.kill.assert_called_once_with()
    assert process.wait.call_count == 2
    assert popen.call_args.args[0] == ["vmrun", "-T", options.platform, "start", options.core, "gui"]


@pytest.mark.parametrize("mode", ["browser", "participant"])
def test_fusion_attaches_running_vms_before_opening_destination(monkeypatch, options, mode):
    options.mode = mode
    required = [options.core, options.app if mode == "browser" else options.participant]
    _, calls, prompts = fake_runtime(monkeypatch, options, required)
    assert launcher.launch(options) == 0
    assert not prompts
    attach = ["open", "-g", "-a", options.fusion_app, *required]
    if options.platform == "fusion":
        assert attach in calls
        assert calls.index(attach) < len(calls) - 1
        if mode == "browser":
            network = next(i for i, args in enumerate(calls) if "getGuestIPAddress" in args)
            assert calls.index(attach) < network
    else:
        assert attach not in calls
