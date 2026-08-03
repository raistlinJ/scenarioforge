import importlib.util
import sys
import threading
import time
import types
from pathlib import Path


def test_coretg_prereqs_service_declares_absolute_file_and_dual_path_startup() -> None:
    p = Path("on_core_machine/custom_services/CoreTGPrereqs.py")
    txt = p.read_text("utf-8", errors="ignore")

    # The file declaration stays absolute: that is where CORE puts it inside a
    # Docker node. The startup command must find it on a namespaced vnode too,
    # where the script only exists in the node's `.conf` working directory.
    assert 'files: list[str] = ["/runprereqs.sh"]' in txt
    assert "f=runprereqs.sh" in txt
    assert 'f=/runprereqs.sh' in txt
    assert 'LOG="/tmp/coretg_prereqs_output.txt"' in txt


def test_coretg_prereqs_serializes_mako_template_loading() -> None:
    p = Path("on_core_machine/custom_services/CoreTGPrereqs.py")
    txt = p.read_text("utf-8", errors="ignore")

    assert "threading.RLock()" in txt
    assert "TemplateLookup.get_template = _locked_get_template" in txt
    assert "_coretg_threadsafe_get_template" in txt


def test_coretg_prereqs_mako_hook_serializes_concurrent_lookups(monkeypatch) -> None:
    state = {"active": 0, "max_active": 0}
    state_lock = threading.Lock()

    class _TemplateLookup:
        def get_template(self, uri):
            with state_lock:
                state["active"] += 1
                state["max_active"] = max(state["max_active"], state["active"])
            time.sleep(0.02)
            with state_lock:
                state["active"] -= 1
            return uri

    class _CoreService:
        pass

    class _ShadowDir:
        pass

    class _ServiceMode:
        NON_BLOCKING = "NON_BLOCKING"

    core_module = types.ModuleType("core")
    core_services_module = types.ModuleType("core.services")
    core_services_base_module = types.ModuleType("core.services.base")
    core_services_base_module.CoreService = _CoreService
    core_services_base_module.ShadowDir = _ShadowDir
    core_services_base_module.ServiceMode = _ServiceMode
    mako_module = types.ModuleType("mako")
    mako_lookup_module = types.ModuleType("mako.lookup")
    mako_lookup_module.TemplateLookup = _TemplateLookup

    monkeypatch.setitem(sys.modules, "core", core_module)
    monkeypatch.setitem(sys.modules, "core.services", core_services_module)
    monkeypatch.setitem(sys.modules, "core.services.base", core_services_base_module)
    monkeypatch.setitem(sys.modules, "mako", mako_module)
    monkeypatch.setitem(sys.modules, "mako.lookup", mako_lookup_module)

    service_path = Path("on_core_machine/custom_services/CoreTGPrereqs.py")
    spec = importlib.util.spec_from_file_location("_coretg_prereqs_test", service_path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    lookup = _TemplateLookup()
    threads = [
        threading.Thread(target=lookup.get_template, args=(f"template-{index}",))
        for index in range(4)
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert state["max_active"] == 1


def test_segmentation_service_declares_absolute_file_and_dual_path_startup() -> None:
    p = Path("on_core_machine/custom_services/Segmentation.py")
    txt = p.read_text("utf-8", errors="ignore")

    assert 'files: list[str] = ["/runsegmentation.sh"]' in txt
    assert "f=runsegmentation.sh" in txt
    assert "f=/runsegmentation.sh" in txt


def test_every_script_service_startup_resolves_on_both_node_kinds() -> None:
    """A vnode only has the script in its `.conf` working directory.

    CORE writes a Docker node's service files into the container (so the
    absolute path resolves) but a namespaced vnode shares the host filesystem
    and only gets the file in `/tmp/pycore.<id>/<node>.conf/`. A startup command
    that names only the absolute path fails silently there, which is how traffic
    could be fully configured and deployed yet never start.
    """
    expected = {
        "TrafficService.py": "runtraffic.sh",
        "Segmentation.py": "runsegmentation.sh",
        "CoreTGPrereqs.py": "runprereqs.sh",
        "DockerDefaultRoute.py": "defaultroute.sh",
    }
    for filename, script in expected.items():
        txt = Path("on_core_machine/custom_services", filename).read_text("utf-8", errors="ignore")
        startup = next(line for line in txt.splitlines() if "f=" + script in line)
        # relative first (vnode), absolute fallback (Docker node)
        assert f"f={script};" in startup
        assert f"f=/{script}" in startup
