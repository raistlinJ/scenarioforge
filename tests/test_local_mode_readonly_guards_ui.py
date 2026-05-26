from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_local_mode_seeds_core_connection_endpoint_fields_without_locking() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "const WEBUI_LOCAL_MODE =",
        "const WEBUI_LOCAL_CORE_HOST =",
        "const WEBUI_LOCAL_CORE_PORT =",
        "const WEBUI_LOCAL_SSH_PORT =",
        "if (WEBUI_LOCAL_MODE) {",
        "if (!(coreState.grpc_host || '').toString().trim()) {",
        "coreState.grpc_host = WEBUI_LOCAL_CORE_HOST;",
        "if (!(coreState.ssh_host || '').toString().trim()) {",
        "coreState.ssh_host = coreState.grpc_host || WEBUI_LOCAL_CORE_HOST;",
        "coreModalInputs.grpc_host.disabled = inputsDisabled;",
        "coreModalInputs.grpc_port.disabled = inputsDisabled;",
        "coreModalInputs.ssh_host.disabled = inputsDisabled;",
        "coreModalInputs.ssh_port.disabled = inputsDisabled;",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing local-mode UI fallback snippets: " + "; ".join(missing)
