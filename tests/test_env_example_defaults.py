from pathlib import Path


ENV_EXAMPLE_PATH = Path(__file__).resolve().parent.parent / ".scenarioforge.env.example"


def test_env_example_includes_vm_mode_defaults_for_direct_python_and_compose() -> None:
    text = ENV_EXAMPLE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "CORE_HOST=127.0.0.1",
        "CORE_PORT=50051",
        "CORE_SSH_HOST=12.0.0.100",
        "CORE_SSH_PORT=22",
        "CORE_SSH_USERNAME=sampleuser",
        "CORE_SSH_PASSWORD=samplepassword",
        "CORETG_HOST=0.0.0.0",
        "CORETG_PORT=9090",
        "CORETG_WEBUI_MODE=native",
        "CORETG_VM_MODE_HITL_ENABLED=true",
        "CORETG_VM_MODE_HITL_CORE_IFX_NAME=ens19",
        "CORETG_VM_MODE_HITL_CORE_IFX_ATTACHMENT=existing_router",
        "CORETG_VM_MODE_HITL_CORE_IFX_DESCRIPTION=Scenario HITL participant network",
        "CORETG_VM_MODE_PARTICIPANT_URL=http://participant-ui.example",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing .scenarioforge.env.example defaults: " + "; ".join(missing)