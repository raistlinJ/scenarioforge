"""Shared CORE VM lock: cross-repo contract and mutual exclusion.

Background CLI jobs from the web UI and runs from the scenarioforge-eval
harness both drive the same CORE VM, and both do daemon-level work that
destroys in-memory CORE sessions (`core-cleanup`, custom-service installs,
`systemctl restart core-daemon`). They exclude each other with an flock on a
shared temp file, so the two independently-maintained derivations of that
file's path have to agree exactly -- if they drift, both sides still "lock",
just not against each other, and the failure resurfaces as a mid-run session
disappearing.
"""

import multiprocessing
import os

import pytest

from webapp import app_backend as ab


# Observed in real scenarioforge-eval run metadata (`shared_vm_lock` in a
# *_result.json). Pins the wire format against the harness; changing either
# side's key or digest derivation must break this.
_GOLDEN_KEY = '12.0.0.100:22:corevm'
_GOLDEN_BASENAME = 'scenarioforge-eval-f26e50de670b546c.lock'


def test_lock_path_matches_eval_harness_golden_vector():
    assert os.path.basename(ab._shared_vm_lock_path(_GOLDEN_KEY)) == _GOLDEN_BASENAME


def test_lock_key_matches_harness_derivation():
    cfg = {'ssh_host': '12.0.0.100', 'ssh_port': 22, 'ssh_username': 'corevm'}
    assert ab._shared_vm_lock_key(cfg) == _GOLDEN_KEY


def test_lock_key_falls_back_to_host_and_appends_vm_identifier():
    # Mirrors the harness: `ssh_host or host`, with vmid/vm_key appended last.
    assert ab._shared_vm_lock_key(
        {'host': '10.0.0.5', 'ssh_port': '22', 'ssh_username': 'u'}
    ) == '10.0.0.5:22:u'
    assert ab._shared_vm_lock_key(
        {'ssh_host': 'h', 'ssh_port': '22', 'ssh_username': 'u', 'vmid': '900'}
    ) == 'h:22:u:900'


@pytest.mark.parametrize('cfg', [
    None,
    {},
    {'ssh_host': '12.0.0.100', 'ssh_port': 22},           # no username
    {'ssh_port': 22, 'ssh_username': 'corevm'},           # no host
    {'ssh_host': '12.0.0.100', 'ssh_username': 'corevm'},  # no port
])
def test_no_lock_key_without_a_full_ssh_target(cfg):
    # No resolved SSH target means the job is not driving a shared VM.
    assert ab._shared_vm_lock_key(cfg) is None


def test_missing_ssh_target_acquires_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(ab.tempfile, 'gettempdir', lambda: str(tmp_path))
    assert ab._acquire_shared_vm_lock({}) is None
    ab._release_shared_vm_lock(None)  # must tolerate the no-lock case


def _hold_lock_in_child(tmp_dir, cfg, acquired, release):
    """Take the lock in a separate process and hold it until told to stop."""
    import tempfile as _tempfile

    _tempfile.gettempdir = lambda: tmp_dir  # type: ignore[assignment]
    ab.tempfile.gettempdir = lambda: tmp_dir  # type: ignore[assignment]
    lock = ab._acquire_shared_vm_lock(cfg)
    acquired.set()
    release.wait(timeout=30)
    ab._release_shared_vm_lock(lock)


def test_lock_is_mutually_exclusive_across_processes(tmp_path, monkeypatch):
    """The real guarantee: a second holder cannot enter while the first holds.

    Uses a separate process because the eval harness is a separate process --
    a same-process test would not prove flock spans process boundaries.
    """
    cfg = {'ssh_host': '12.0.0.100', 'ssh_port': 22, 'ssh_username': 'corevm'}
    monkeypatch.setattr(ab.tempfile, 'gettempdir', lambda: str(tmp_path))
    monkeypatch.setenv('CORETG_SHARED_VM_LOCK_TIMEOUT_S', '1')

    ctx = multiprocessing.get_context('fork')
    acquired = ctx.Event()
    release = ctx.Event()
    child = ctx.Process(
        target=_hold_lock_in_child, args=(str(tmp_path), cfg, acquired, release)
    )
    child.start()
    try:
        assert acquired.wait(timeout=30), 'child never acquired the lock'

        # Contended: must refuse rather than proceed onto a busy VM.
        with pytest.raises(TimeoutError) as excinfo:
            ab._acquire_shared_vm_lock(cfg)
        assert '12.0.0.100:22:corevm' in str(excinfo.value)

        release.set()
        child.join(timeout=30)
        assert child.exitcode == 0

        # Uncontended once the holder is gone.
        lock = ab._acquire_shared_vm_lock(cfg)
        assert lock is not None and lock['key'] == '12.0.0.100:22:corevm'
        ab._release_shared_vm_lock(lock)
    finally:
        release.set()
        if child.is_alive():
            child.terminate()
        child.join(timeout=10)


def test_release_allows_a_later_acquire(tmp_path, monkeypatch):
    cfg = {'ssh_host': '12.0.0.100', 'ssh_port': 22, 'ssh_username': 'corevm'}
    monkeypatch.setattr(ab.tempfile, 'gettempdir', lambda: str(tmp_path))

    first = ab._acquire_shared_vm_lock(cfg)
    assert first is not None
    ab._release_shared_vm_lock(first)

    second = ab._acquire_shared_vm_lock(cfg)
    assert second is not None
    ab._release_shared_vm_lock(second)


def test_background_task_releases_lock_even_when_the_run_raises(monkeypatch):
    """A crashing run must not strand the VM as permanently busy."""
    released: list = []

    def fake_inner(run_id, job_spec, lock_holder):
        lock_holder['lock'] = {'key': 'k', 'path': 'p', 'handle': None}
        raise RuntimeError('boom')

    monkeypatch.setattr(ab, '_run_cli_background_task_locked', fake_inner)
    monkeypatch.setattr(ab, '_release_shared_vm_lock', released.append)

    with pytest.raises(RuntimeError):
        ab._run_cli_background_task('run-1', {})

    assert len(released) == 1
    assert released[0]['key'] == 'k'


def test_background_task_releases_lock_on_early_return(monkeypatch):
    """Most inner exit paths are early returns, not exceptions."""
    released: list = []

    def fake_inner(run_id, job_spec, lock_holder):
        lock_holder['lock'] = {'key': 'k', 'path': 'p', 'handle': None}
        return

    monkeypatch.setattr(ab, '_run_cli_background_task_locked', fake_inner)
    monkeypatch.setattr(ab, '_release_shared_vm_lock', released.append)

    ab._run_cli_background_task('run-1', {})

    assert len(released) == 1


def test_timeout_is_configurable_and_bounded(monkeypatch):
    monkeypatch.delenv('CORETG_SHARED_VM_LOCK_TIMEOUT_S', raising=False)
    assert ab._shared_vm_lock_timeout_s() == ab._SHARED_VM_LOCK_DEFAULT_TIMEOUT_S

    monkeypatch.setenv('CORETG_SHARED_VM_LOCK_TIMEOUT_S', '30')
    assert ab._shared_vm_lock_timeout_s() == 30.0

    # Garbage must not disable the wait entirely.
    monkeypatch.setenv('CORETG_SHARED_VM_LOCK_TIMEOUT_S', 'not-a-number')
    assert ab._shared_vm_lock_timeout_s() == ab._SHARED_VM_LOCK_DEFAULT_TIMEOUT_S

    monkeypatch.setenv('CORETG_SHARED_VM_LOCK_TIMEOUT_S', '999999')
    assert ab._shared_vm_lock_timeout_s() == 86400.0
