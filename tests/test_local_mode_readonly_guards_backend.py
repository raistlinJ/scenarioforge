from pathlib import Path


BACKEND_PATH = Path(__file__).resolve().parent.parent / "webapp" / "app_backend.py"


def test_local_mode_backend_uses_local_endpoints_as_fallbacks() -> None:
    text = BACKEND_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        "def _webui_local_mode() -> bool:",
        "mode = str(os.getenv('CORETG_RUN_MODE') or '').strip().lower()",
        "if _webui_local_mode():",
        "if not str(cfg.get('host') or '').strip():",
        "cfg['host'] = local_host",
        "if not str(cfg.get('grpc_host') or '').strip():",
        "if not cfg.get('port'):",
        "if not str(cfg.get('ssh_host') or '').strip():",
        "if not cfg.get('ssh_port'):",
        "'webui_local_mode': _webui_local_mode(),",
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing local-mode backend fallback snippets: " + "; ".join(missing)
