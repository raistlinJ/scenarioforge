import importlib.util
import sys
import threading
import time
import types
from pathlib import Path


def test_coretg_prereqs_service_uses_absolute_paths() -> None:
    p = Path("on_core_machine/custom_services/CoreTGPrereqs.py")
    txt = p.read_text("utf-8", errors="ignore")

    assert 'files: list[str] = ["/runprereqs.sh"]' in txt
    assert 'startup: list[str] = ["/bin/sh /runprereqs.sh"]' in txt
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


def test_segmentation_service_uses_absolute_paths() -> None:
    p = Path("on_core_machine/custom_services/Segmentation.py")
    txt = p.read_text("utf-8", errors="ignore")

    assert 'files: list[str] = ["/runsegmentation.sh"]' in txt
    assert 'startup: list[str] = ["/bin/bash /runsegmentation.sh &"]' in txt
