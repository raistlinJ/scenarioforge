from pathlib import Path


INDEX_TEMPLATE_PATH = Path(__file__).resolve().parent.parent / "webapp" / "templates" / "index.html"


def test_docker_repair_toggle_hidden_in_dockerized_mode() -> None:
    """Docker repair is hidden when the Web UI itself runs in a container.

    These options used to live in a per-run execute dialog as `executeAdv*`
    checkboxes. That dialog was retired (see
    test_full_preview_page.test_topology_has_no_legacy_execution_modals_or_controls,
    which requires those modals stay out of index.html) and the surviving
    toggles moved into the CORE VM connection settings as `coreAdv*`.

    The guarantee worth pinning is unchanged: the Jinja guard hides the Docker
    repair switch in dockerized mode, and the JS forces the flag off regardless.
    """
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        '{% if not webui_running_in_docker %}',
        'id="coreAdvFixDockerDaemon"',
        "if (WEBUI_RUNNING_IN_DOCKER && scen.hitl.core.adv_fix_docker_daemon !== false) {",
        'scen.hitl.core.adv_fix_docker_daemon = false;',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing dockerized-mode UI safety snippets: " + "; ".join(missing)

    # The retired dialog must not come back with these controls in tow.
    for retired in ('id="executeAdvFixDockerDaemon"', 'id="executeAdvDockerNukeAll"'):
        assert retired not in text, f"Retired execute-dialog control reappeared: {retired}"


def test_core_vm_modal_hides_fix_docker_toggle_in_dockerized_mode() -> None:
    text = INDEX_TEMPLATE_PATH.read_text(encoding="utf-8", errors="ignore")

    expected_snippets = [
        '{% if not webui_running_in_docker %}',
        'id="coreAdvFixDockerDaemon"',
        "if (WEBUI_RUNNING_IN_DOCKER && scen.hitl.core.adv_fix_docker_daemon !== false) {",
        'scen.hitl.core.adv_fix_docker_daemon = false;',
    ]

    missing = [snippet for snippet in expected_snippets if snippet not in text]
    assert not missing, "Missing CORE VM dockerized-mode safety snippets: " + "; ".join(missing)

    forbidden_snippets = [
        'Docker daemon repair controls are hidden while Web UI runs in Docker.',
    ]

    present = [snippet for snippet in forbidden_snippets if snippet in text]
    assert not present, "Unexpected CORE VM docker-mode placeholder text still present: " + "; ".join(present)
