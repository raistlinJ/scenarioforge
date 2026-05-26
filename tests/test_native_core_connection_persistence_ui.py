from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_native_core_connection_persistence_prefers_ui_state_over_defaults() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "if (USE_LOCAL_EDITOR_STATE && persistedState && persistedState.core) {",
        "const persistedCore = normalizeCoreState(persistedState.core, true);",
        "state.core = {",
        "...state.core,",
        "...persistedCore,",
        "coreModalInputs.grpc_host.value = coreState.grpc_host || (WEBUI_LOCAL_MODE ? WEBUI_LOCAL_CORE_HOST : '');",
        "coreModalInputs.ssh_host.value = coreState.ssh_host || coreState.grpc_host || (WEBUI_LOCAL_MODE ? WEBUI_LOCAL_CORE_HOST : '');",
        "coreModalInputs.grpc_host.disabled = inputsDisabled;",
        "coreModalInputs.ssh_host.disabled = inputsDisabled;",
        "// Local mode seeds sensible defaults, but explicit UI edits still win.",
        "if (!(coreState.grpc_host || '').toString().trim()) {",
        "if (!(coreState.ssh_host || '').toString().trim()) {",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing native core persistence snippets: " + "; ".join(missing)


def test_native_core_connection_persistence_no_longer_forces_local_defaults_into_modal() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    forbidden_snippets = [
        "coreModalInputs.grpc_host.value = WEBUI_LOCAL_MODE ? WEBUI_LOCAL_CORE_HOST : (coreState.grpc_host || '');",
        "coreModalInputs.grpc_port.disabled = WEBUI_LOCAL_MODE || inputsDisabled;",
        "coreModalInputs.ssh_host.value = WEBUI_LOCAL_MODE ? WEBUI_LOCAL_CORE_HOST : (coreState.ssh_host || '');",
        "coreModalInputs.ssh_port.disabled = WEBUI_LOCAL_MODE || inputsDisabled;",
        "// Local mode keeps localhost endpoints static to prevent accidental drift.",
        "coreState.ssh_host = WEBUI_LOCAL_CORE_HOST;",
    ]

    present = [snippet for snippet in forbidden_snippets if snippet in text]
    assert not present, "Unexpected forced-local persistence snippets still present: " + "; ".join(present)