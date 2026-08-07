from pathlib import Path


INDEX_TEMPLATE = Path(__file__).resolve().parents[1] / "webapp" / "templates" / "index.html"


def test_scenario_import_uses_live_progress_modal_and_server_polling():
    text = INDEX_TEMPLATE.read_text(encoding="utf-8")

    for expected in (
        'id="scenarioImportProgressModal"',
        'id="scenarioImportProgressSteps"',
        'id="scenarioImportProgressClose"',
        'id="scenarioImportCredentialPrompt"',
        'id="scenarioImportCoreHost"',
        'id="scenarioImportCorePort"',
        'id="scenarioImportSshHost"',
        'id="scenarioImportSshPort"',
        'id="scenarioImportSshUsername"',
        'id="scenarioImportCredentialPassword"',
        'id="scenarioImportCoreVenvBin"',
        'id="scenarioImportSaveProfile"',
        'id="scenarioImportCredentialContinue"',
        "xhr.upload.onprogress",
        "formData.set('import_progress_id', progressId)",
        "ssh_password: 'core_ssh_password'",
        "/api/scenario-import-progress/",
        "/api/scenario-import-requirements",
        "/api/scenario-import-connection/test",
        "appendClientProgress('Testing destination connection'",
        "appendClientProgress('Destination connection validated'",
        "if (payload.status === 'waiting') return;",
    ):
        assert expected in text
