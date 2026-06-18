from pathlib import Path
import os

from webapp import app_backend
from webapp import env_loader


BACKEND_PATH = Path(__file__).resolve().parent.parent / "webapp" / "app_backend.py"


def test_vm_mode_backend_exposes_runtime_mode_defaults_and_env_only_route() -> None:
    text = BACKEND_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "_WEBUI_RUNTIME_MODE_ALLOWED = {'native', 'vm'}",
        "def _webui_runtime_mode_default() -> str:",
        "os.getenv('CORETG_WEBUI_MODE')",
        "os.getenv('CORETG_RUNTIME_MODE')",
        "def _webui_runtime_mode() -> str:",
        "def _webui_vm_mode_defaults(*, include_password: bool = True) -> Dict[str, Any]:",
        "os.getenv('CORE_HOST')",
        "os.getenv('CORE_SSH_PASSWORD')",
        "if _webui_runtime_mode() == 'vm':",
        "'webui_runtime_mode': _webui_runtime_mode(),",
        "'webui_vm_mode_defaults': _webui_vm_mode_defaults(include_password=True),",
        "def set_webui_runtime_mode():",
        "runtime_mode = _webui_runtime_mode()",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing VM-mode backend snippets: " + "; ".join(missing)

    unexpected_runtime_override_snippets = [
        "_WEBUI_RUNTIME_MODE_SESSION_KEY",
        "session[_WEBUI_RUNTIME_MODE_SESSION_KEY] =",
        "selected = str(session.get(_WEBUI_RUNTIME_MODE_SESSION_KEY)",
    ]
    present_override = [snippet for snippet in unexpected_runtime_override_snippets if snippet in text]
    assert not present_override, "Runtime mode should not be session-overridable: " + "; ".join(present_override)

    unexpected_snippets = [
        "os.getenv('CORETG_VM_MODE_CORE_VM_NODE')",
        "os.getenv('CORETG_VM_MODE_CORE_VMID')",
        "os.getenv('CORETG_VM_MODE_CORE_VM_NAME')",
        "os.getenv('CORETG_VM_MODE_CORE_VM_KEY')",
    ]
    present = [snippet for snippet in unexpected_snippets if snippet in text]
    assert not present, "Unexpected VM identity env snippets still present: " + "; ".join(present)


def test_vm_mode_backend_ignores_vm_identity_metadata_env_vars(monkeypatch) -> None:
    monkeypatch.setenv("CORE_HOST", "10.77.88.99")
    monkeypatch.setenv("CORE_PORT", "50061")
    monkeypatch.setenv("CORE_SSH_HOST", "10.77.88.100")
    monkeypatch.setenv("CORE_SSH_PORT", "2222")
    monkeypatch.setenv("CORE_SSH_USERNAME", "sampleuser")
    monkeypatch.setenv("CORE_SSH_PASSWORD", "samplepassword")
    monkeypatch.setenv("CORETG_VM_MODE_CORE_VM_NODE", "smoke-node")
    monkeypatch.setenv("CORETG_VM_MODE_CORE_VMID", "777")
    monkeypatch.setenv("CORETG_VM_MODE_CORE_VM_NAME", "Smoke CORE VM")
    monkeypatch.setenv("CORETG_VM_MODE_CORE_VM_KEY", "smoke-node::777")

    vm_defaults = app_backend._webui_vm_mode_defaults(include_password=True)
    vm_core = vm_defaults["core"]
    assert vm_core["host"] == "10.77.88.99"
    assert vm_core["ssh_host"] == "10.77.88.100"
    assert vm_core["ssh_username"] == "sampleuser"
    assert vm_core["ssh_password"] == "samplepassword"
    assert vm_core["vm_key"] == ""
    assert vm_core["vm_name"] == ""
    assert vm_core["vm_node"] == ""
    assert vm_core["vmid"] == ""
    assert vm_core["validated"] is True

    monkeypatch.setattr(app_backend, "_webui_runtime_mode", lambda: "vm")
    merged = app_backend._core_backend_defaults(include_password=True)
    assert merged["host"] == "10.77.88.99"
    assert merged["ssh_host"] == "10.77.88.100"
    assert merged["ssh_username"] == "sampleuser"
    assert merged["ssh_password"] == "samplepassword"
    assert merged["vm_key"] == ""
    assert merged["vm_name"] == ""
    assert merged["vm_node"] == ""
    assert merged["vmid"] == ""


def test_vm_mode_backend_defaults_do_not_require_vm_identity_metadata(monkeypatch) -> None:
    monkeypatch.setenv("CORE_HOST", "10.77.88.99")
    monkeypatch.setenv("CORE_PORT", "50061")
    monkeypatch.setenv("CORE_SSH_HOST", "10.77.88.100")
    monkeypatch.setenv("CORE_SSH_PORT", "2222")
    monkeypatch.setenv("CORE_SSH_USERNAME", "sampleuser")
    monkeypatch.setenv("CORE_SSH_PASSWORD", "samplepassword")
    monkeypatch.delenv("CORETG_VM_MODE_CORE_VM_NODE", raising=False)
    monkeypatch.delenv("CORETG_VM_MODE_CORE_VMID", raising=False)
    monkeypatch.delenv("CORETG_VM_MODE_CORE_VM_NAME", raising=False)
    monkeypatch.delenv("CORETG_VM_MODE_CORE_VM_KEY", raising=False)

    vm_defaults = app_backend._webui_vm_mode_defaults(include_password=True)
    vm_core = vm_defaults["core"]
    assert vm_core["host"] == "10.77.88.99"
    assert vm_core["ssh_host"] == "10.77.88.100"
    assert vm_core["ssh_username"] == "sampleuser"
    assert vm_core["ssh_password"] == "samplepassword"
    assert vm_core["vm_key"] == ""
    assert vm_core["vm_name"] == ""
    assert vm_core["vm_node"] == ""
    assert vm_core["vmid"] == ""

    monkeypatch.setattr(app_backend, "_webui_runtime_mode", lambda: "vm")
    merged = app_backend._core_backend_defaults(include_password=True)
    assert merged["host"] == "10.77.88.99"
    assert merged["ssh_host"] == "10.77.88.100"
    assert merged["ssh_username"] == "sampleuser"
    assert merged["ssh_password"] == "samplepassword"
    assert merged["vm_key"] == ""
    assert merged["vm_name"] == ""
    assert merged["vm_node"] == ""
    assert merged["vmid"] == ""


def test_docker_bridge_preserves_loopback_core_host_in_vm_mode(monkeypatch) -> None:
    monkeypatch.setenv("CORETG_DOCKER_BRIDGE", "1")
    monkeypatch.setenv("CORETG_WEBUI_MODE", "vm")
    monkeypatch.delenv("CORETG_RUNTIME_MODE", raising=False)
    monkeypatch.delenv("CORETG_KEEP_CONTAINER_LOCAL_CORE", raising=False)
    monkeypatch.setenv("CORE_HOST", "127.0.0.1")

    app_backend._apply_docker_bridge_core_defaults()

    assert os.environ["CORE_HOST"] == "127.0.0.1"


def test_docker_bridge_rewrites_loopback_core_host_in_native_mode(monkeypatch) -> None:
    monkeypatch.setenv("CORETG_DOCKER_BRIDGE", "1")
    monkeypatch.setenv("CORETG_WEBUI_MODE", "native")
    monkeypatch.delenv("CORETG_RUNTIME_MODE", raising=False)
    monkeypatch.delenv("CORETG_KEEP_CONTAINER_LOCAL_CORE", raising=False)
    monkeypatch.setenv("CORE_HOST", "127.0.0.1")

    app_backend._apply_docker_bridge_core_defaults()

    assert os.environ["CORE_HOST"] == "host.docker.internal"


def test_vm_mode_backend_defaults_leave_hitl_ifnames_blank_until_configured(monkeypatch) -> None:
    monkeypatch.delenv("CORETG_VM_MODE_HITL_ENABLED", raising=False)
    monkeypatch.delenv("CORETG_VM_MODE_HITL_CORE_IFX_NAME", raising=False)
    monkeypatch.delenv("CORETG_VM_MODE_HITL_CORE_IFX_ATTACHMENT", raising=False)
    monkeypatch.delenv("CORETG_VM_MODE_HITL_CORE_IFX_DESCRIPTION", raising=False)
    monkeypatch.delenv("CORETG_HITL_CORE_IFX_IPV4", raising=False)
    monkeypatch.delenv("CORETG_VM_MODE_NET0_NAME", raising=False)

    vm_defaults = app_backend._webui_vm_mode_defaults(include_password=False)
    hitl_defaults = vm_defaults["hitl"]
    assert hitl_defaults["interfaces"] == []

    monkeypatch.setenv("CORETG_VM_MODE_HITL_ENABLED", "true")
    monkeypatch.setenv("CORETG_VM_MODE_HITL_CORE_IFX_NAME", "ens18")
    monkeypatch.setenv("CORETG_VM_MODE_HITL_CORE_IFX_ATTACHMENT", "existing_router")
    monkeypatch.setenv("CORETG_HITL_CORE_IFX_IPV4", "10.254.200.3/24")

    vm_defaults = app_backend._webui_vm_mode_defaults(include_password=False)
    hitl_defaults = vm_defaults["hitl"]
    assert hitl_defaults["enabled"] is True
    assert len(hitl_defaults["interfaces"]) == 1
    assert hitl_defaults["interfaces"][0]["name"] == "ens18"
    assert hitl_defaults["interfaces"][0]["attachment"] == "existing_router"
    assert hitl_defaults["interfaces"][0]["ipv4"] == ["10.254.200.3/24"]
    assert "proxmox_target" not in hitl_defaults["interfaces"][0]
    assert hitl_defaults["shared_core_ifx_ipv4"] == ["10.254.200.3/24"]


def test_vm_mode_backend_defaults_ignore_non_vm_hitl_interface_names(monkeypatch) -> None:
    monkeypatch.delenv("CORETG_VM_MODE_HITL_ENABLED", raising=False)
    monkeypatch.delenv("CORETG_VM_MODE_HITL_CORE_IFX_NAME", raising=False)
    monkeypatch.delenv("CORETG_VM_MODE_HITL_CORE_IFX_ATTACHMENT", raising=False)
    monkeypatch.delenv("CORETG_VM_MODE_HITL_CORE_IFX_DESCRIPTION", raising=False)
    monkeypatch.delenv("CORETG_HITL_CORE_IFX_IPV4", raising=False)

    monkeypatch.setenv("CORETG_HITL_CORE_IFX_NAME", "ens19")
    monkeypatch.setenv("CORETG_HITL_CORE_IFX_ATTACHMENT", "new_router")
    monkeypatch.setenv("CORETG_HITL_CORE_IFX_IPV4", "10.10.20.3/24")

    vm_defaults = app_backend._webui_vm_mode_defaults(include_password=False)
    hitl_defaults = vm_defaults["hitl"]
    assert hitl_defaults["enabled"] is True
    assert hitl_defaults["interfaces"] == []
    assert hitl_defaults["shared_core_ifx_ipv4"] == ["10.10.20.3/24"]


def test_runtime_env_loader_prefers_dotenv_over_example_and_preserves_real_env(tmp_path, monkeypatch) -> None:
    example_path = tmp_path / ".scenarioforge.env.example"
    example_path.write_text(
        "CORETG_WEBUI_MODE=native\n"
        "CORE_HOST=12.0.0.100\n"
        "CORE_SSH_USERNAME=example-user\n",
        encoding="utf-8",
    )
    env_path = tmp_path / ".scenarioforge.env"
    env_path.write_text(
        "CORETG_WEBUI_MODE=vm\n"
        "CORE_HOST=10.0.0.25\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("CORETG_WEBUI_MODE", raising=False)
    monkeypatch.delenv("CORE_HOST", raising=False)
    monkeypatch.setenv("CORE_SSH_USERNAME", "shell-user")

    loaded = env_loader.load_runtime_env_files(base_dir=tmp_path, include_example=True)

    assert env_path.resolve() in loaded
    assert example_path.resolve() in loaded
    assert os.environ["CORETG_WEBUI_MODE"] == "vm"
    assert os.environ["CORE_HOST"] == "10.0.0.25"
    assert os.environ["CORE_SSH_USERNAME"] == "shell-user"


def test_runtime_env_loader_ignores_example_defaults_by_default(tmp_path, monkeypatch) -> None:
    example_path = tmp_path / ".scenarioforge.env.example"
    example_path.write_text(
        "CORETG_WEBUI_MODE=vm\n"
        "CORE_HOST=12.0.0.100\n"
        "CORETG_VM_MODE_HITL_CORE_IFX_NAME=ens18\n",
        encoding="utf-8",
    )
    env_path = tmp_path / ".scenarioforge.env"
    env_path.write_text(
        "CORETG_WEBUI_MODE=native\n"
        "CORE_HOST=10.0.0.25\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("CORETG_WEBUI_MODE", raising=False)
    monkeypatch.delenv("CORE_HOST", raising=False)
    monkeypatch.delenv("CORETG_VM_MODE_HITL_CORE_IFX_NAME", raising=False)

    loaded = env_loader.load_runtime_env_files(base_dir=tmp_path)

    assert env_path.resolve() in loaded
    assert example_path.resolve() not in loaded
    assert os.environ["CORETG_WEBUI_MODE"] == "native"
    assert os.environ["CORE_HOST"] == "10.0.0.25"
    assert "CORETG_VM_MODE_HITL_CORE_IFX_NAME" not in os.environ