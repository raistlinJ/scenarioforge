"""Preflight installed vulnerability catalog compose items.

This catches catalog entries that cannot be prepared into the CORE-shaped
docker-compose files used during scenario execution, without starting CORE or
Docker containers.
"""

from __future__ import annotations

import argparse
import ast
import json
import os
import re
import shutil
import sys
import tempfile
from pathlib import Path
from typing import Any

try:
    import yaml  # type: ignore
except Exception:  # pragma: no cover
    yaml = None  # type: ignore

from scenarioforge.compose_dependencies import missing_dependency_paths, scan_compose_dependencies
from scenarioforge.utils.vuln_process import prepare_compose_for_assignments


def _repo_root(path: str | os.PathLike[str] | None = None) -> Path:
    if path:
        return Path(path).expanduser().resolve()
    return Path(__file__).resolve().parents[2]


def _catalog_state_path(repo_root: Path) -> Path:
    return repo_root / "outputs" / "installed_vuln_catalogs" / "_catalogs_state.json"


def _load_catalog_state(repo_root: Path) -> dict[str, Any]:
    path = _catalog_state_path(repo_root)
    try:
        obj = json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}
    return obj if isinstance(obj, dict) else {}


def _active_catalog_entry(state: dict[str, Any]) -> dict[str, Any] | None:
    active_id = str(state.get("active_id") or "").strip()
    for entry in state.get("catalogs") or []:
        if isinstance(entry, dict) and str(entry.get("id") or "").strip() == active_id:
            return entry
    return None


def _normalize_catalog_items(entry: dict[str, Any]) -> list[dict[str, Any]]:
    items = entry.get("compose_items")
    if not isinstance(items, list):
        return []
    out: list[dict[str, Any]] = []
    next_id = 1
    for raw in items:
        if not isinstance(raw, dict):
            continue
        item = dict(raw)
        try:
            item_id = int(item.get("id"))
        except Exception:
            item_id = next_id
        if item_id < 1:
            item_id = next_id
        next_id = max(next_id, item_id + 1)
        item["id"] = item_id
        item["name"] = str(item.get("name") or "").strip() or "root"
        item["disabled"] = bool(item.get("disabled", False))
        item["rel_dir"] = str(item.get("rel_dir") or item.get("dir_rel") or "").strip()
        item["dir_rel"] = str(item.get("dir_rel") or item.get("rel_dir") or "").strip()
        item["compose_rel"] = str(item.get("compose_rel") or "").strip()
        out.append(item)
    return sorted(out, key=lambda item: int(item.get("id") or 0))


def _safe_path_under(base_dir: Path, rel_path: str) -> Path:
    base = base_dir.resolve()
    candidate = (base / str(rel_path or "")).resolve()
    try:
        candidate.relative_to(base)
    except Exception as exc:
        raise ValueError("path escaped catalog content directory") from exc
    return candidate


def _catalog_content_dir(repo_root: Path, catalog_id: str) -> Path:
    return repo_root / "outputs" / "installed_vuln_catalogs" / catalog_id / "content"


def _item_compose_path(repo_root: Path, catalog_id: str, item: dict[str, Any]) -> Path:
    content_dir = _catalog_content_dir(repo_root, catalog_id)
    rel = str(item.get("compose_rel") or "").strip()
    if rel:
        return _safe_path_under(content_dir, rel)
    repo_rel = str(item.get("compose_path") or "").strip().replace("\\", "/")
    if not repo_rel:
        raise ValueError("missing compose path")
    return _safe_path_under(repo_root, repo_rel)


def _item_label(item: dict[str, Any]) -> str:
    rel_dir = str(item.get("rel_dir") or item.get("dir_rel") or "").replace("\\", "/").strip("/")
    parts = [part for part in rel_dir.split("/") if part]
    if len(parts) >= 2:
        return f"{parts[-2]}/{parts[-1]}"
    if parts:
        return parts[-1]
    return str(item.get("name") or f"item-{int(item.get('id') or 0)}")


def _core_like_compose_template_preflight(path: str | os.PathLike[str]) -> tuple[bool, str | None, dict[str, Any]]:
    meta: dict[str, Any] = {}
    try:
        text = Path(path).read_text(encoding="utf-8", errors="ignore")
    except Exception as exc:
        return False, f"unable to read prepared docker-compose file: {exc}", meta

    scan_text = re.sub(
        r"\$\{\s*([\"'])\$\{[^}]*\}\1\s*\}",
        lambda match: " " * len(match.group(0)),
        text,
    )

    raw_exprs: list[tuple[str, int]] = []
    for match in re.finditer(r"(?<!\\)\$\{([^}]*)\}", scan_text):
        expr = (match.group(1) or "").strip()
        line_no = text.count("\n", 0, match.start()) + 1
        raw_exprs.append((expr, line_no))
    if raw_exprs:
        meta["raw_template_expr_count"] = len(raw_exprs)

    syntax_errors: list[str] = []
    for expr, line_no in raw_exprs[:8]:
        try:
            ast.parse(expr, mode="eval")
        except Exception:
            syntax_errors.append(f"line {line_no}: ${{{expr}}}")
    if syntax_errors:
        return (
            False,
            "compose template contains unescaped `${...}` expression(s) that fail CORE-style parsing: "
            + "; ".join(syntax_errors[:3]),
            meta,
        )

    try:
        from mako import exceptions as mako_exceptions  # type: ignore
        from mako.template import Template as MakoTemplate  # type: ignore

        meta["template_engine"] = "mako"
        try:
            MakoTemplate(text).render()
        except Exception as exc:
            try:
                detail = str(mako_exceptions.text_error_template().render()).strip()
            except Exception:
                detail = str(exc)
            detail = detail.replace("\n", " | ")
            if len(detail) > 700:
                detail = detail[:700] + "..."
            return False, f"CORE-like template render check failed: {detail}", meta
    except Exception:
        meta["template_engine"] = "ast-fallback"

    return True, None, meta


def _scan_compose_shell_command_safety(path: str | os.PathLike[str]) -> tuple[bool, list[dict[str, Any]]]:
    issues: list[dict[str, Any]] = []
    if yaml is None:
        return True, issues
    try:
        doc = yaml.safe_load(Path(path).read_text(encoding="utf-8", errors="ignore"))
    except Exception:
        return True, issues
    services = doc.get("services") if isinstance(doc, dict) else None
    if not isinstance(services, dict):
        return True, issues

    for service_name, service in services.items():
        if not isinstance(service, dict):
            continue
        command = service.get("command")
        command_text = ""
        if isinstance(command, str):
            command_text = command
        elif isinstance(command, list):
            parts = [str(part) for part in command]
            if len(parts) >= 3 and parts[0] in {"sh", "bash"} and parts[1] in {"-c", "-lc"}:
                command_text = parts[2]
            elif parts:
                command_text = " ".join(parts)
        if not command_text:
            continue

        lowered = command_text.lower()
        markers: list[str] = []
        if "rpcbind_pid" in lowered and ("$!" in command_text or "$$" in command_text or "$rpcbind_pid" in lowered):
            markers.append("rpcbind_pid_dollar_expansion")
        if "trap" in lowered and "$$" in command_text:
            markers.append("trap_double_dollar")
        if "$$!" in command_text or "$$rpcbind_pid" in lowered:
            markers.append("double_dollar_pid_pattern")
        if markers:
            issues.append(
                {
                    "service": str(service_name or ""),
                    "path": str(path),
                    "markers": markers,
                    "command_preview": command_text[:300],
                }
            )
    return len(issues) == 0, issues


def _labels_dict(service: dict[str, Any]) -> dict[str, str]:
    labels = service.get("labels") if isinstance(service, dict) else None
    if isinstance(labels, dict):
        return {str(key): str(value) for key, value in labels.items()}
    out: dict[str, str] = {}
    if isinstance(labels, list):
        for raw in labels:
            text = str(raw or "").strip()
            if not text or "=" not in text:
                continue
            key, value = text.split("=", 1)
            out[key.strip()] = value.strip()
    return out


def _volume_pairs(service: dict[str, Any]) -> list[tuple[str, str]]:
    volumes = service.get("volumes") if isinstance(service, dict) else None
    if not isinstance(volumes, list):
        return []
    pairs: list[tuple[str, str]] = []
    for volume in volumes:
        if isinstance(volume, str):
            parts = volume.split(":", 2)
            if len(parts) >= 2:
                pairs.append((parts[0], parts[1]))
        elif isinstance(volume, dict):
            source = str(volume.get("source") or volume.get("src") or "").strip()
            target = str(volume.get("target") or volume.get("dst") or volume.get("destination") or "").strip()
            if target:
                pairs.append((source, target))
    return pairs


def _norm_container_path(value: Any) -> str:
    text = str(value or "").strip().replace("\\", "/").rstrip("/")
    return text or "/"


def _container_dest_for_inject(dest_dir: str, rel_path: str) -> str:
    base = _norm_container_path(dest_dir)
    rel = str(rel_path or "").strip().replace("\\", "/").lstrip("/").strip("/")
    if not rel:
        return base
    if base == "/":
        return "/" + rel
    return base + "/" + rel


def _validate_prepared_inject_plan(prepared_obj: dict[str, Any], node_name: str) -> tuple[bool, str | None, dict[str, Any]]:
    """Validate local inject wiring in a prepared compose file.

    This does not prove Docker/CORE copied bytes into a running container. It proves
    the prepared compose carries enough metadata and delivery wiring for the runtime
    copy/validation path to do that work.
    """
    meta: dict[str, Any] = {"checked": False, "items": []}
    services = prepared_obj.get("services") if isinstance(prepared_obj, dict) else None
    if not isinstance(services, dict):
        return False, "prepared compose services are missing", meta
    node_service = services.get(node_name)
    if not isinstance(node_service, dict):
        return False, f"prepared compose service {node_name} is missing", meta

    labels = _labels_dict(node_service)
    source_dir = str(labels.get("coretg.inject.source_dir") or "").strip()
    raw_map = str(labels.get("coretg.inject.map") or "").strip()
    if not source_dir:
        return False, "prepared compose is missing coretg.inject.source_dir label", meta
    if not raw_map:
        return False, "prepared compose is missing coretg.inject.map label", meta

    try:
        inject_map = json.loads(raw_map)
    except Exception as exc:
        return False, f"prepared compose inject map is not valid JSON: {exc}", meta
    if not isinstance(inject_map, list) or not inject_map:
        return False, "prepared compose inject map is empty", meta
    if not os.path.isdir(source_dir):
        return False, f"inject source directory does not exist: {source_dir}", meta

    node_volume_pairs = _volume_pairs(node_service)
    node_targets = {_norm_container_path(target) for _source, target in node_volume_pairs}
    helper_services = {
        str(name): service
        for name, service in services.items()
        if str(name).startswith("inject_copy") and isinstance(service, dict)
    }
    helper_source_dirs: set[str] = set()
    for helper in helper_services.values():
        for source, target in _volume_pairs(helper):
            if _norm_container_path(target) == "/src":
                helper_source_dirs.add(os.path.abspath(str(source or "")))

    errors: list[str] = []
    item_meta: list[dict[str, Any]] = []
    source_dir_abs = os.path.abspath(source_dir)
    for raw_item in inject_map:
        if not isinstance(raw_item, dict):
            errors.append("inject map contains a non-object entry")
            continue
        src_rel = str(raw_item.get("src") or "").strip().replace("\\", "/").lstrip("/")
        dest_dir = _norm_container_path(raw_item.get("dest") or "")
        if not src_rel:
            errors.append("inject map item is missing src")
            continue
        if not dest_dir:
            errors.append(f"inject map item {src_rel} is missing dest")
            continue

        source_path = os.path.abspath(os.path.join(source_dir, src_rel))
        if not os.path.exists(source_path):
            errors.append(f"inject source missing: {source_path}")
            continue
        try:
            if os.path.commonpath([source_dir_abs, source_path]) != source_dir_abs:
                errors.append(f"inject source escapes source_dir: {source_path}")
                continue
        except Exception:
            errors.append(f"inject source could not be normalized: {source_path}")
            continue

        direct_target = _container_dest_for_inject(dest_dir, src_rel)
        has_direct_bind = _norm_container_path(direct_target) in node_targets
        has_copy_volume = dest_dir in node_targets and bool(helper_services)
        if has_copy_volume and source_dir_abs not in helper_source_dirs:
            errors.append(f"inject helper does not mount source_dir for {src_rel}: {source_dir}")
            continue
        if not has_direct_bind and not has_copy_volume:
            errors.append(f"inject item {src_rel} has no target-service volume for {dest_dir}")
            continue
        item_meta.append(
            {
                "src": src_rel,
                "dest": dest_dir,
                "source_path": source_path,
                "delivery": "direct_bind" if has_direct_bind else "inject_copy",
            }
        )

    meta.update(
        {
            "checked": True,
            "source_dir": source_dir,
            "items": item_meta,
            "helper_services": sorted(helper_services.keys()),
        }
    )
    if errors:
        meta["errors"] = errors
        return False, "; ".join(errors[:3]), meta
    return True, None, meta


def _add_count(counts: dict[str, int], key: str) -> None:
    counts[key] = counts.get(key, 0) + 1


def run_preflight(
    *,
    repo_root: str | os.PathLike[str] | None = None,
    work_dir: str | os.PathLike[str] | None = None,
    include_disabled: bool = True,
    query: str = "",
    limit: int | None = None,
) -> dict[str, Any]:
    root = _repo_root(repo_root)
    state = _load_catalog_state(root)
    entry = _active_catalog_entry(state)
    if not entry:
        return {
            "ok": False,
            "error": "No active vulnerability catalog found.",
            "catalog_id": "",
            "catalog_label": "",
            "total": 0,
            "checked": 0,
            "passed": 0,
            "failed": 0,
            "warnings": 0,
            "injects_checked": 0,
            "inject_items_checked": 0,
            "disabled": 0,
            "issues_by_category": {},
            "warnings_by_category": {},
            "issues": [],
            "warning_items": [],
        }

    catalog_id = str(entry.get("id") or "").strip()
    items = _normalize_catalog_items(entry)
    needle = str(query or "").strip().lower()
    if needle:
        items = [
            item
            for item in items
            if needle in str(item.get("id") or "").lower()
            or needle in str(item.get("name") or "").lower()
            or needle in str(item.get("rel_dir") or item.get("dir_rel") or "").lower()
        ]
    if not include_disabled:
        items = [item for item in items if not bool(item.get("disabled"))]
    if limit is not None:
        items = items[: max(0, int(limit))]

    summary: dict[str, Any] = {
        "ok": True,
        "catalog_id": catalog_id,
        "catalog_label": str(entry.get("label") or "").strip() or catalog_id,
        "total": len(items),
        "checked": 0,
        "passed": 0,
        "failed": 0,
        "warnings": 0,
        "injects_checked": 0,
        "inject_items_checked": 0,
        "disabled": sum(1 for item in items if bool(item.get("disabled"))),
        "issues_by_category": {},
        "warnings_by_category": {},
        "issues": [],
        "warning_items": [],
    }

    temp_root = None
    if work_dir:
        work_root = Path(work_dir).expanduser().resolve()
        work_root.mkdir(parents=True, exist_ok=True)
    else:
        temp_root = tempfile.mkdtemp(prefix="scenarioforge-vuln-preflight-")
        work_root = Path(temp_root)

    def add_issue(item: dict[str, Any], category: str, reason: Any, **extra: Any) -> None:
        summary["failed"] += 1
        _add_count(summary["issues_by_category"], category)
        record = {
            "id": item.get("id"),
            "name": _item_label(item),
            "category": category,
            "reason": str(reason),
        }
        record.update({key: value for key, value in extra.items() if value not in (None, "", [])})
        summary["issues"].append(record)

    def add_warning(item: dict[str, Any], category: str, reason: Any, **extra: Any) -> None:
        summary["warnings"] += 1
        _add_count(summary["warnings_by_category"], category)
        record = {
            "id": item.get("id"),
            "name": _item_label(item),
            "category": category,
            "reason": str(reason),
        }
        record.update({key: value for key, value in extra.items() if value not in (None, "", [])})
        summary["warning_items"].append(record)

    old_repo_root_env = os.environ.get("CORETG_REPO_ROOT")
    os.environ["CORETG_REPO_ROOT"] = str(root)
    try:
        for item in items:
            summary["checked"] += 1
            try:
                compose_path = _item_compose_path(root, catalog_id, item)
            except Exception as exc:
                add_issue(item, "compose_path_invalid", exc)
                continue
            if not compose_path.is_file():
                add_issue(item, "compose_missing", "docker-compose.yml not found", compose_path=str(compose_path))
                continue

            missing_files: list[str] = []
            try:
                dependency_summary = scan_compose_dependencies(compose_path)
                missing_files = missing_dependency_paths(dependency_summary)
            except Exception as exc:
                add_warning(item, "dependency_scan_failed", exc, compose_path=str(compose_path))
            if missing_files:
                add_warning(
                    item,
                    "missing_required_files",
                    "compose references local support files that are missing",
                    compose_path=str(compose_path),
                    missing_required_files=missing_files,
                )

            node_name = f"vuln-preflight-{int(item.get('id') or 0)}"
            item_work_dir = work_root / f"item-{int(item.get('id') or 0):04d}"
            if item_work_dir.exists():
                shutil.rmtree(item_work_dir, ignore_errors=True)
            item_work_dir.mkdir(parents=True, exist_ok=True)
            record = {
                "Name": str(item.get("name") or item.get("Name") or item.get("Title") or node_name),
                "Path": str(compose_path),
                "Type": "docker-compose",
                "ScenarioTag": node_name,
                "CoreTGVulnAssignment": "1",
            }

            try:
                created = prepare_compose_for_assignments({node_name: record}, out_base=str(item_work_dir))
            except Exception as exc:
                add_issue(item, "prepare_exception", exc, compose_path=str(compose_path), missing_required_files=missing_files)
                continue
            if not created:
                add_issue(
                    item,
                    "prepare_failed",
                    "prepare_compose_for_assignments produced no compose",
                    compose_path=str(compose_path),
                    missing_required_files=missing_files,
                )
                continue

            prepared_path = Path(created[0])
            preflight_ok, preflight_error, preflight_meta = _core_like_compose_template_preflight(prepared_path)
            if not preflight_ok:
                add_issue(
                    item,
                    "core_template_preflight",
                    preflight_error or "CORE-like template preflight failed",
                    compose_path=str(compose_path),
                    prepared_compose_path=str(prepared_path),
                    preflight=preflight_meta,
                    missing_required_files=missing_files,
                )
                continue

            shell_ok, shell_issues = _scan_compose_shell_command_safety(prepared_path)
            if not shell_ok:
                add_issue(
                    item,
                    "shell_command_safety",
                    "unsafe shell command pattern for CORE compose rendering",
                    compose_path=str(compose_path),
                    prepared_compose_path=str(prepared_path),
                    shell_issues=shell_issues,
                    missing_required_files=missing_files,
                )
                continue

            if yaml is None:
                add_warning(item, "yaml_unavailable", "PyYAML unavailable; prepared service check skipped")
                summary["passed"] += 1
                continue
            try:
                prepared_obj = yaml.safe_load(prepared_path.read_text(encoding="utf-8", errors="ignore")) or {}
            except Exception as exc:
                add_issue(
                    item,
                    "prepared_yaml_parse",
                    exc,
                    compose_path=str(compose_path),
                    prepared_compose_path=str(prepared_path),
                    missing_required_files=missing_files,
                )
                continue
            services = prepared_obj.get("services") if isinstance(prepared_obj, dict) else None
            if not isinstance(services, dict) or not services:
                add_issue(item, "prepared_no_services", "prepared compose has no services", compose_path=str(compose_path))
                continue
            if node_name not in services:
                add_issue(
                    item,
                    "missing_node_service",
                    f"prepared compose does not define service {node_name}",
                    compose_path=str(compose_path),
                    prepared_compose_path=str(prepared_path),
                    services=list(services.keys())[:10],
                )
                continue
            if not isinstance(services.get(node_name), dict):
                add_issue(
                    item,
                    "node_service_invalid",
                    f"prepared service {node_name} is not a mapping",
                    compose_path=str(compose_path),
                    prepared_compose_path=str(prepared_path),
                )
                continue
            inject_ok, inject_error, inject_meta = _validate_prepared_inject_plan(prepared_obj, node_name)
            if not inject_ok:
                add_issue(
                    item,
                    "inject_plan_invalid",
                    inject_error or "prepared compose inject plan is invalid",
                    compose_path=str(compose_path),
                    prepared_compose_path=str(prepared_path),
                    inject_plan=inject_meta,
                )
                continue
            summary["injects_checked"] += 1
            summary["inject_items_checked"] += len(inject_meta.get("items") if isinstance(inject_meta.get("items"), list) else [])
            summary["passed"] += 1
    finally:
        if old_repo_root_env is None:
            os.environ.pop("CORETG_REPO_ROOT", None)
        else:
            os.environ["CORETG_REPO_ROOT"] = old_repo_root_env
        if temp_root:
            shutil.rmtree(temp_root, ignore_errors=True)

    summary["ok"] = summary["failed"] == 0
    return summary


def _write_report(summary: dict[str, Any], output_path: str | os.PathLike[str] | None) -> Path | None:
    if not output_path:
        return None
    path = Path(output_path).expanduser().resolve()
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(summary, indent=2, sort_keys=True), encoding="utf-8")
    return path


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Preflight installed vulnerability catalog compose items")
    parser.add_argument("--repo-root", default=None, help="ScenarioForge repository root (default: auto-detect)")
    parser.add_argument("--out", default=None, help="JSON report path (default: outputs/vuln-catalog-preflight/latest.json)")
    parser.add_argument("--work-dir", default=None, help="Keep prepared compose work files under this directory")
    parser.add_argument("--enabled-only", action="store_true", help="Skip disabled catalog items")
    parser.add_argument("--query", default="", help="Only check items whose id, name, or directory contains this text")
    parser.add_argument("--limit", type=int, default=None, help="Maximum number of matching items to check")
    parser.add_argument("--fail-on-warning", action="store_true", help="Return nonzero when warning items are found")
    args = parser.parse_args(argv)

    root = _repo_root(args.repo_root)
    out = args.out
    if out is None:
        out = str(root / "outputs" / "vuln-catalog-preflight" / "latest.json")

    summary = run_preflight(
        repo_root=root,
        work_dir=args.work_dir,
        include_disabled=not args.enabled_only,
        query=args.query,
        limit=args.limit,
    )
    report_path = _write_report(summary, out)

    print(
        json.dumps(
            {
                "ok": summary.get("ok"),
                "catalog": summary.get("catalog_label") or summary.get("catalog_id"),
                "total": summary.get("total", 0),
                "passed": summary.get("passed", 0),
                "failed": summary.get("failed", 0),
                "warnings": summary.get("warnings", 0),
                "injects_checked": summary.get("injects_checked", 0),
                "inject_items_checked": summary.get("inject_items_checked", 0),
                "issues_by_category": summary.get("issues_by_category") or {},
                "warnings_by_category": summary.get("warnings_by_category") or {},
                "report": str(report_path) if report_path else None,
            },
            indent=2,
            sort_keys=True,
        )
    )

    if summary.get("issues"):
        print("First hard issues:", file=sys.stderr)
        for issue in list(summary.get("issues") or [])[:10]:
            print(f"- #{issue.get('id')} {issue.get('name')}: {issue.get('category')}: {issue.get('reason')}", file=sys.stderr)
    if summary.get("warning_items"):
        print("First warnings:", file=sys.stderr)
        for warning in list(summary.get("warning_items") or [])[:10]:
            print(f"- #{warning.get('id')} {warning.get('name')}: {warning.get('category')}: {warning.get('reason')}", file=sys.stderr)

    if summary.get("failed", 0):
        return 1
    if args.fail_on_warning and summary.get("warnings", 0):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
