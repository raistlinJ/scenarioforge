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
