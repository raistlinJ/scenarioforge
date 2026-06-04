from pathlib import Path


COMPOSE_PATH = Path(__file__).resolve().parent.parent / "docker-compose.yml"
APP_BACKEND_PATH = Path(__file__).resolve().parent.parent / "webapp" / "app_backend.py"


def test_vm_mode_compose_exposes_runtime_defaults() -> None:
    text = COMPOSE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "env_file:",
        "path: ./.scenarioforge.env.example",
        "required: true",
        "path: ./.scenarioforge.env",
        "required: false",
        "CORETG_HOST=0.0.0.0",
        "CORETG_PORT=9090",
        "CORETG_SECRETS_DIR=/root/.scenarioforge/secrets",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing VM-mode docker-compose snippets: " + "; ".join(missing)


def test_app_runner_keeps_reloader_opt_in_for_generator_workflows() -> None:
    text = APP_BACKEND_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "use_reloader = _env_flag('CORETG_USE_RELOADER', False)",
        "app.run(host=host, port=port, debug=debug, use_reloader=use_reloader, threaded=True)",
        "Generator/VM-mode workflows write plan, report, and artifact files under the repo.",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "App runner should keep the reloader opt-in during generator workflows: " + "; ".join(missing)