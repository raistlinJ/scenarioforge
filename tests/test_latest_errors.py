import logging
from types import SimpleNamespace

import scenarioforge.builders.topology as topology
from scenarioforge import cli


def test_cli_latest_errors_handler_writes_warnings_and_errors(tmp_path, monkeypatch):
    xml_path = tmp_path / "scenario.xml"
    xml_path.write_text("<Scenarios />\n", encoding="utf-8")
    monkeypatch.delenv("SCENARIOFORGE_LATEST_ERRORS", raising=False)
    monkeypatch.delenv("CORETG_LATEST_ERRORS_PATH", raising=False)

    try:
        latest_path = cli._configure_cli_logging(SimpleNamespace(verbose=False, xml=str(xml_path)))
        logger = logging.getLogger("scenarioforge.tests.latest_errors")

        logger.info("this info record should not be copied")
        logger.warning("node=docker-9 compose=/tmp/vulns/docker-compose.yml warning detail")
        logger.error("docker compose up -d failed because appweb was missing")

        for handler in logging.getLogger().handlers:
            try:
                handler.flush()
            except Exception:
                pass

        assert latest_path == str(tmp_path / "latest.errors")
        text = (tmp_path / "latest.errors").read_text(encoding="utf-8")
        assert "ScenarioForge latest warnings/errors" in text
        assert "node=docker-9 compose=/tmp/vulns/docker-compose.yml warning detail" in text
        assert "docker compose up -d failed because appweb was missing" in text
        assert "this info record should not be copied" not in text
    finally:
        cli._remove_latest_errors_handlers()


def test_docker_compose_preflight_failure_log_includes_compose_snapshot(tmp_path, caplog):
    compose_path = tmp_path / "docker-compose.yml"
    compose_path.write_text(
        "services:\n"
        "  docker-9:\n"
        "    image: vulhub/appweb:7.0.1\n"
        "    command: ['/usr/local/lib/appweb/7.0.1/bin/appweb']\n",
        encoding="utf-8",
    )

    caplog.set_level(logging.ERROR, logger="scenarioforge.builders.topology")
    topology._log_docker_compose_preflight_failure(
        "docker-9",
        str(compose_path),
        RuntimeError('exec: "appweb": executable file not found in $PATH'),
    )

    text = caplog.text
    assert "compose preflight failed node=docker-9" in text
    assert str(compose_path) in text
    assert 'exec: "appweb": executable file not found in $PATH' in text
    assert "image: vulhub/appweb:7.0.1" in text
    assert "--- docker-compose snapshot:" in text
