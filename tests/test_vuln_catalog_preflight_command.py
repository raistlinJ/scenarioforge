from __future__ import annotations

import json
from pathlib import Path

from scenarioforge.validation import vuln_catalog_preflight as preflight
from scenarioforge.validation.vuln_catalog_preflight import main, run_preflight


def _write_catalog(
    repo_root: Path,
    *,
    compose_text: str | None,
    compose_rel: str = "vulhub/demo/CVE-0000-0000/docker-compose.yml",
) -> Path:
    catalog_id = "cat-1"
    pack_dir = repo_root / "outputs" / "installed_vuln_catalogs" / catalog_id
    content_dir = pack_dir / "content"
    if compose_text is not None:
        compose_path = content_dir / compose_rel
        compose_path.parent.mkdir(parents=True, exist_ok=True)
        compose_path.write_text(compose_text.strip() + "\n", encoding="utf-8")
    state_path = repo_root / "outputs" / "installed_vuln_catalogs" / "_catalogs_state.json"
    state_path.parent.mkdir(parents=True, exist_ok=True)
    state_path.write_text(
        json.dumps(
            {
                "active_id": catalog_id,
                "catalogs": [
                    {
                        "id": catalog_id,
                        "label": "Test Catalog",
                        "compose_items": [
                            {
                                "id": 1,
                                "name": "demo/CVE-0000-0000",
                                "rel_dir": "vulhub/demo/CVE-0000-0000",
                                "compose_rel": compose_rel,
                            }
                        ],
                    }
                ],
            }
        ),
        encoding="utf-8",
    )
    return state_path


def test_vuln_catalog_preflight_passes_clean_catalog_item(tmp_path: Path) -> None:
    _write_catalog(
        tmp_path,
        compose_text="""
services:
  app:
    image: alpine:3.20
    command: ["sh", "-lc", "sleep infinity"]
""",
    )

    summary = run_preflight(repo_root=tmp_path, work_dir=tmp_path / "work")

    assert summary["ok"] is True
    assert summary["total"] == 1
    assert summary["passed"] == 1
    assert summary["failed"] == 0
    assert summary["warnings"] == 0
    assert summary["injects_checked"] == 1
    assert summary["inject_items_checked"] == 1


def test_vuln_catalog_preflight_warns_for_missing_support_file(tmp_path: Path) -> None:
    _write_catalog(
        tmp_path,
        compose_text="""
services:
  app:
    image: alpine:3.20
    command: ["sh", "-lc", "sleep infinity"]
    volumes:
      - ./missing.conf:/etc/demo/missing.conf:ro
""",
    )

    summary = run_preflight(repo_root=tmp_path, work_dir=tmp_path / "work")

    assert summary["ok"] is True
    assert summary["passed"] == 1
    assert summary["failed"] == 0
    assert summary["warnings"] == 1
    assert summary["warnings_by_category"] == {"missing_required_files": 1}
    assert summary["warning_items"][0]["missing_required_files"] == ["missing.conf"]
    assert summary["injects_checked"] == 1


def test_vuln_catalog_preflight_fails_missing_compose(tmp_path: Path) -> None:
    _write_catalog(tmp_path, compose_text=None)

    summary = run_preflight(repo_root=tmp_path, work_dir=tmp_path / "work")

    assert summary["ok"] is False
    assert summary["passed"] == 0
    assert summary["failed"] == 1
    assert summary["issues_by_category"] == {"compose_missing": 1}


def test_vuln_catalog_preflight_fails_missing_inject_plan(tmp_path: Path, monkeypatch) -> None:
    _write_catalog(
        tmp_path,
        compose_text="""
services:
  app:
    image: alpine:3.20
    command: ["sh", "-lc", "sleep infinity"]
""",
    )

    def _fake_prepare(_assignments, out_base: str, compose_name: str = "docker-compose.yml"):
        path = Path(out_base) / "docker-compose-vuln-preflight-1.yml"
        path.write_text(
            """
services:
  vuln-preflight-1:
    image: alpine:3.20
    command: ["sh", "-lc", "sleep infinity"]
""".strip()
            + "\n",
            encoding="utf-8",
        )
        return [str(path)]

    monkeypatch.setattr(preflight, "prepare_compose_for_assignments", _fake_prepare)

    summary = run_preflight(repo_root=tmp_path, work_dir=tmp_path / "work")

    assert summary["ok"] is False
    assert summary["passed"] == 0
    assert summary["failed"] == 1
    assert summary["issues_by_category"] == {"inject_plan_invalid": 1}
    assert "coretg.inject.source_dir" in summary["issues"][0]["reason"]


def test_vuln_catalog_preflight_cli_writes_report(tmp_path: Path, capsys) -> None:
    _write_catalog(
        tmp_path,
        compose_text="""
services:
  app:
    image: alpine:3.20
    command: ["sh", "-lc", "sleep infinity"]
""",
    )
    report_path = tmp_path / "report.json"

    rc = main(["--repo-root", str(tmp_path), "--out", str(report_path), "--work-dir", str(tmp_path / "work")])

    captured = capsys.readouterr()
    assert rc == 0
    assert report_path.is_file()
    assert '"passed": 1' in captured.out
    assert json.loads(report_path.read_text(encoding="utf-8"))["ok"] is True
