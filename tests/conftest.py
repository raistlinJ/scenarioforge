import gc
import sys
from pathlib import Path

import pytest

# Ensure repository root is on sys.path so imports like 'webapp.app_backend' work
ROOT = Path(__file__).resolve().parent.parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))


_CORE_ENV_KEYS = (
    'CORE_SSH_HOST',
    'CORE_SSH_PORT',
    'CORE_SSH_USERNAME',
    'CORE_SSH_PASSWORD',
    'CORE_SSH_ENABLED',
    'CORE_HOST',
    'CORE_PORT',
    'CORETG_WEBUI_MODE',
    'CORETG_RUNTIME_MODE',
)


@pytest.fixture(scope='session')
def _isolated_secrets_dir(tmp_path_factory):
    return str(tmp_path_factory.mktemp('scenarioforge-secrets'))


@pytest.fixture(autouse=True)
def _isolate_core_runtime_env(monkeypatch, _isolated_secrets_dir):
    """Keep the suite independent of the developer's `.scenarioforge.env`.

    That file is gitignored and holds whatever CORE VM the machine currently
    points at, including working SSH credentials. Tests inherit it, so on a
    machine configured for a reachable CORE VM the CORE-touching tests stop
    being unit tests: they SSH out, sync the repo to the VM, and run generators
    on it. That is slow, non-deterministic (the same commit fails different
    tests on consecutive runs), and it writes to live infrastructure.

    `CORETG_WEBUI_MODE` matters too -- it gates whole blueprints, so switching a
    local deployment to VM mode turns unrelated files red with 404s.

    Tests that exercise this configuration set the variables they need; because
    a test body runs after its fixtures, those assignments still win.
    """
    for key in _CORE_ENV_KEYS:
        monkeypatch.delenv(key, raising=False)
    monkeypatch.setenv('CORETG_WEBUI_MODE', 'native')
    # Stored CORE credentials live under ~/.scenarioforge/secrets and are
    # consulted whenever a scenario has no explicit config. Left alone, tests
    # dial whatever hosts the developer has saved -- and once those hosts are
    # off-network, every lookup burns an SSH timeout (one file took seven
    # minutes). Point the store at an empty per-session directory.
    monkeypatch.setenv('CORETG_SECRETS_DIR', _isolated_secrets_dir)


# Endpoints that run a generator or a batch hand the work to a daemon thread and
# respond immediately. That thread persists its result when it finishes -- and
# it resolves the state path *then*, not when it started. A test can therefore
# return, its monkeypatched environment can be torn down, and the thread can
# land its write on the operator's real catalog a moment later. Joining these
# before the redirect is undone keeps the write where the test put it.
_APP_WORKER_THREAD_PREFIXES = (
    'flaggen-',
    'flagnodegen-',
    'flag-batch-',
    'flag-cache-',
    'builder-test-',
    'artifact-check-',
    'core-repo-push-',
)


def _join_app_worker_threads(timeout_s: float = 10.0) -> None:
    import threading
    import time as _time

    deadline = _time.time() + timeout_s
    for thread in list(threading.enumerate()):
        if thread is threading.current_thread() or not thread.is_alive():
            continue
        if not str(thread.name or '').startswith(_APP_WORKER_THREAD_PREFIXES):
            continue
        remaining = deadline - _time.time()
        if remaining <= 0:
            break
        # Best effort: a wedged worker must not hang the suite.
        thread.join(timeout=remaining)


def pytest_configure(config):
    config.addinivalue_line(
        'markers',
        'real_installed_catalogs: test reads the machine\'s installed catalogs '
        'instead of an isolated temp root (read-only tests only)',
    )


@pytest.fixture(autouse=True)
def _isolate_installed_catalog_roots(request, monkeypatch, tmp_path_factory):
    """Keep catalog installs out of the operator's real catalogs.

    Installing a generator pack or a vulnerability catalog writes into
    ``outputs/installed_generators`` and ``outputs/installed_vuln_catalogs``.
    Those are live application state that the Web UI and CLI read,
    ``_catalogs_state.json`` is rewritten wholesale rather than appended to, and
    both are gitignored -- so anything a test overwrites is gone, with no
    ``git checkout`` to undo it. A suite run once left junk catalogs behind,
    made one of them active, and destroyed the installed vulnerability catalog
    outright.

    Redirecting by default means a new test cannot cause that by forgetting to
    isolate itself. A handful of end-to-end tests genuinely need the machine's
    real catalog to have vulnerabilities in it; they opt out with
    ``@pytest.mark.real_installed_catalogs`` and must be read-only, since
    opting out puts the operator's data back in reach.

    A test that sets either variable itself still wins, because a test body
    runs after its fixtures.
    """
    if request.node.get_closest_marker('real_installed_catalogs'):
        yield
        return
    root = tmp_path_factory.mktemp('scenarioforge-catalogs')
    monkeypatch.setenv('CORETG_INSTALLED_GENERATORS_DIR', str(root / 'installed_generators'))
    monkeypatch.setenv('CORETG_INSTALLED_VULN_CATALOGS_DIR', str(root / 'installed_vuln_catalogs'))
    yield
    _join_app_worker_threads()


@pytest.fixture(autouse=True)
def _collect_abandoned_stream_generators():
    """Close abandoned streaming responses in the test that created them.

    Routes that stream with `stream_with_context` build a generator holding a
    request/app context. When a test asserts before draining that stream, the
    generator is abandoned and only closed at an arbitrary later garbage
    collection -- pushing its teardown, and the context it leaves behind, into
    an unrelated test.

    Production code branches on `has_app_context()` (for example
    `_stop_vuln_test_meta`, which returns a bare dict outside a request context
    and a `(payload, status)` tuple inside one), so a stray context silently
    changes what a later test observes. Collecting here pins that cleanup to the
    test responsible, which makes the suite independent of allocation timing.
    """
    yield
    gc.collect()

# Provide a minimal stub for missing CORE gRPC dependency in testing environments
try:  # only create if real package absent
    import core.api.grpc.client  # type: ignore
except Exception:  # pragma: no cover - defensive
    import types
    core_mod = sys.modules.setdefault('core', types.ModuleType('core'))
    api_mod = sys.modules.setdefault('core.api', types.ModuleType('core.api'))
    grpc_mod = sys.modules.setdefault('core.api.grpc', types.ModuleType('core.api.grpc'))
    client_mod = types.ModuleType('core.api.grpc.client')
    class CoreGrpcClient:  # minimal placeholder
        pass
    client_mod.CoreGrpcClient = CoreGrpcClient
    sys.modules['core.api.grpc.client'] = client_mod
    # wrappers stub
    wrappers_mod = types.ModuleType('core.api.grpc.wrappers')
    class Position:
        def __init__(self, x=0, y=0): self.x=x; self.y=y
    class Interface:
        def __init__(self, id=0, name='', ip4='', ip4_mask=24, mac=''): self.id=id; self.name=name; self.ip4=ip4; self.ip4_mask=ip4_mask; self.mac=mac
    class NodeType:
        DEFAULT=0; SWITCH=1; DOCKER=2
    wrappers_mod.Position = Position
    wrappers_mod.Interface = Interface
    wrappers_mod.NodeType = NodeType
    sys.modules['core.api.grpc.wrappers'] = wrappers_mod
