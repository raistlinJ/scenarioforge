from pathlib import Path


COMPOSE_PATH = Path(__file__).resolve().parent.parent / "docker-compose.yml"


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