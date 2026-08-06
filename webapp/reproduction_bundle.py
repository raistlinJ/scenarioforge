"""Detection and safe import of ScenarioForge reproduction bundles."""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import stat
import uuid
import xml.etree.ElementTree as ET
import zipfile
from dataclasses import dataclass
from pathlib import Path, PurePosixPath
from typing import Any


BUNDLE_FORMAT = "scenarioforge-reproduction"
MANIFEST_NAME = "scenarioforge-reproduction.json"
MAX_MEMBERS = 10_000
MAX_MANIFEST_BYTES = 2 * 1024 * 1024
MAX_UNCOMPRESSED_BYTES = 4 * 1024 * 1024 * 1024


@dataclass(frozen=True)
class ScenarioImport:
    xml_path: str
    kind: str
    fidelity: str
    manifest_path: str = ""
    bundled_artifact_sources: int = 0
    total_artifact_sources: int = 0


def _sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def _safe_member_name(name: str) -> str:
    normalized = str(name or "").replace("\\", "/")
    path = PurePosixPath(normalized)
    if not normalized or path.is_absolute() or ".." in path.parts:
        raise ValueError(f"unsafe bundle member path: {name!r}")
    return path.as_posix()


def _validate_infos(archive: zipfile.ZipFile) -> dict[str, zipfile.ZipInfo]:
    infos = archive.infolist()
    if len(infos) > MAX_MEMBERS:
        raise ValueError(f"bundle contains more than {MAX_MEMBERS} members")
    if sum(max(0, info.file_size) for info in infos) > MAX_UNCOMPRESSED_BYTES:
        raise ValueError("bundle exceeds the uncompressed import limit")
    by_name: dict[str, zipfile.ZipInfo] = {}
    for info in infos:
        name = _safe_member_name(info.filename)
        mode = (info.external_attr >> 16) & 0xFFFF
        if mode and stat.S_ISLNK(mode):
            raise ValueError(f"bundle contains a symbolic link: {name}")
        if name in by_name:
            raise ValueError(f"bundle contains a duplicate member: {name}")
        by_name[name] = info
    return by_name


def _read_member(archive: zipfile.ZipFile, info: zipfile.ZipInfo, *, limit: int | None = None) -> bytes:
    if limit is not None and info.file_size > limit:
        raise ValueError(f"bundle member is too large: {info.filename}")
    with archive.open(info, "r") as handle:
        value = handle.read((limit + 1) if limit is not None else -1)
    if limit is not None and len(value) > limit:
        raise ValueError(f"bundle member is too large: {info.filename}")
    return value


def _replace_path(value: str, path_map: dict[str, str]) -> str:
    text = value
    for source, destination in sorted(path_map.items(), key=lambda item: len(item[0]), reverse=True):
        source_norm = source.rstrip("/").replace("\\", "/")
        destination_norm = destination.rstrip("/")
        if not source_norm:
            continue
        if text == source_norm:
            return destination_norm
        if text.startswith(source_norm + "/"):
            return destination_norm + text[len(source_norm) :]
    return text


def _rewrite_value(value: Any, path_map: dict[str, str]) -> Any:
    if isinstance(value, dict):
        return {key: _rewrite_value(item, path_map) for key, item in value.items()}
    if isinstance(value, list):
        return [_rewrite_value(item, path_map) for item in value]
    if isinstance(value, str):
        return _replace_path(value, path_map)
    return value


def _rewrite_xml_artifact_paths(
    xml_bytes: bytes,
    path_map: dict[str, str],
    reproduction_sources: list[dict[str, str]] | None = None,
) -> bytes:
    if not path_map and not reproduction_sources:
        return xml_bytes
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError as exc:
        raise ValueError(f"bundle scenario XML is invalid: {exc}") from exc
    for element in root.iter():
        for key, value in list(element.attrib.items()):
            element.attrib[key] = _replace_path(value, path_map)
        text = element.text or ""
        tag = str(element.tag).rsplit("}", 1)[-1]
        if tag in {"FlowState", "PlanPreview"} and text.strip():
            try:
                payload = json.loads(text)
            except json.JSONDecodeError:
                element.text = _replace_path(text, path_map)
            else:
                payload = _rewrite_value(payload, path_map)
                if tag == "FlowState" and reproduction_sources:
                    payload["reproduction_artifact_sources"] = reproduction_sources
                element.text = json.dumps(payload, separators=(",", ":"))
        elif text:
            element.text = _replace_path(text, path_map)
    return ET.tostring(root, encoding="utf-8", xml_declaration=True)


def _portable_target_path(source_path: str, restored_path: str) -> str:
    """Keep stable VM paths and translate known local generator output roots."""
    normalized = source_path.replace("\\", "/")
    if normalized == "/tmp/vulns" or normalized.startswith("/tmp/vulns/"):
        return normalized
    markers = (
        ("/outputs/flag_generators_runs/", "/tmp/vulns/flag_generators_runs/"),
        ("/outputs/flag_node_generators_runs/", "/tmp/vulns/flag_node_generators_runs/"),
        ("/outputs/vulns/flag_generators_runs/", "/tmp/vulns/flag_generators_runs/"),
        ("/outputs/vulns/flag_node_generators_runs/", "/tmp/vulns/flag_node_generators_runs/"),
    )
    for marker, remote_root in markers:
        if marker in normalized:
            return remote_root + normalized.split(marker, 1)[1].lstrip("/")
    return restored_path


def _safe_xml_name(upload_path: Path, manifest: dict[str, Any]) -> str:
    flow = manifest.get("flow") if isinstance(manifest.get("flow"), dict) else {}
    raw = str(flow.get("scenario") or upload_path.name.split(".", 1)[0] or "scenario")
    stem = re.sub(r"[^A-Za-z0-9_.-]+", "_", raw).strip("_.-") or "scenario"
    return f"{stem}.xml"


def _unique_path(directory: Path, filename: str) -> Path:
    candidate = directory / filename
    if not candidate.exists():
        return candidate
    stem, suffix = candidate.stem, candidate.suffix
    for index in range(2, 10_000):
        alternate = directory / f"{stem}-{index}{suffix}"
        if not alternate.exists():
            return alternate
    raise ValueError("unable to choose a unique imported scenario filename")


def _extract_bundle(upload_path: Path, upload_root: Path) -> ScenarioImport:
    with zipfile.ZipFile(upload_path, "r") as archive:
        infos = _validate_infos(archive)
        manifest_info = infos.get(MANIFEST_NAME)
        if manifest_info is None:
            raise ValueError(f"ZIP is not a ScenarioForge bundle: missing {MANIFEST_NAME}")
        try:
            manifest = json.loads(
                _read_member(archive, manifest_info, limit=MAX_MANIFEST_BYTES).decode("utf-8")
            )
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise ValueError(f"invalid reproduction manifest: {exc}") from exc
        if not isinstance(manifest, dict) or manifest.get("format") != BUNDLE_FORMAT:
            raise ValueError("ZIP does not contain a supported ScenarioForge reproduction manifest")
        if manifest.get("version") != 1:
            raise ValueError(f"unsupported ScenarioForge reproduction bundle version: {manifest.get('version')}")

        scenario = manifest.get("scenario") if isinstance(manifest.get("scenario"), dict) else {}
        scenario_member = _safe_member_name(str(scenario.get("path") or "scenario.xml"))
        scenario_info = infos.get(scenario_member)
        if scenario_info is None or scenario_info.is_dir():
            raise ValueError(f"bundle scenario XML is missing: {scenario_member}")
        xml_bytes = _read_member(archive, scenario_info)
        expected_xml_hash = str(scenario.get("sha256") or "").lower()
        if expected_xml_hash and _sha256_bytes(xml_bytes) != expected_xml_hash:
            raise ValueError("bundle scenario XML failed its SHA-256 integrity check")
        try:
            ET.fromstring(xml_bytes)
        except ET.ParseError as exc:
            raise ValueError(f"bundle scenario XML is invalid: {exc}") from exc

        extraction_root = upload_root / f"reproduction-{uuid.uuid4().hex}"
        extraction_root.mkdir(parents=True, exist_ok=False)
        sources = manifest.get("artifact_sources")
        sources = sources if isinstance(sources, list) else []
        path_map: dict[str, str] = {}
        reproduction_sources: list[dict[str, str]] = []
        bundled_count = 0
        try:
            for source in sources:
                if not isinstance(source, dict) or not source.get("bundled"):
                    continue
                source_path = str(source.get("source_path") or "").strip()
                archive_root = _safe_member_name(str(source.get("archive_path") or ""))
                files = source.get("files") if isinstance(source.get("files"), list) else []
                target_root = extraction_root / Path(*PurePosixPath(archive_root).parts)
                target_root.mkdir(parents=True, exist_ok=True)
                for file_record in files:
                    if not isinstance(file_record, dict):
                        raise ValueError("bundle contains an invalid artifact file record")
                    relative = _safe_member_name(str(file_record.get("path") or ""))
                    member_name = f"{archive_root.rstrip('/')}/{relative}"
                    info = infos.get(member_name)
                    if info is None or info.is_dir():
                        raise ValueError(f"bundle artifact is missing: {member_name}")
                    value = _read_member(archive, info)
                    expected_hash = str(file_record.get("sha256") or "").lower()
                    if expected_hash and _sha256_bytes(value) != expected_hash:
                        raise ValueError(f"bundle artifact failed its SHA-256 check: {member_name}")
                    target = target_root / Path(*PurePosixPath(relative).parts)
                    target.parent.mkdir(parents=True, exist_ok=True)
                    target.write_bytes(value)
                    try:
                        target.chmod(int(file_record.get("mode") or 0o600) & 0o777)
                    except (OSError, TypeError, ValueError):
                        pass
                if source_path:
                    restored_path = str(target_root.resolve())
                    target_path = _portable_target_path(source_path, restored_path)
                    path_map[source_path] = target_path
                    reproduction_sources.append(
                        {
                            "source_path": source_path,
                            "restored_path": restored_path,
                            "target_path": target_path,
                        }
                    )
                bundled_count += 1

            rewritten_xml = _rewrite_xml_artifact_paths(
                xml_bytes,
                path_map,
                reproduction_sources,
            )
            xml_path = _unique_path(upload_root, _safe_xml_name(upload_path, manifest))
            xml_path.write_bytes(rewritten_xml)
            manifest_path = extraction_root / MANIFEST_NAME
            manifest_path.write_text(json.dumps(manifest, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except Exception:
            shutil.rmtree(extraction_root, ignore_errors=True)
            raise

    return ScenarioImport(
        xml_path=str(xml_path),
        kind="reproduction-bundle",
        fidelity=str(manifest.get("fidelity") or "deterministic-replay"),
        manifest_path=str(manifest_path),
        bundled_artifact_sources=bundled_count,
        total_artifact_sources=len(sources),
    )


def import_scenario_file(upload_path: str, upload_root: str) -> ScenarioImport:
    """Detect XML versus reproduction ZIP by content and import accordingly."""
    source = Path(upload_path).resolve()
    destination_root = Path(upload_root).resolve()
    destination_root.mkdir(parents=True, exist_ok=True)
    if zipfile.is_zipfile(source):
        return _extract_bundle(source, destination_root)
    try:
        ET.parse(source)
    except (OSError, ET.ParseError) as exc:
        raise ValueError("Unsupported scenario file; choose XML or a ScenarioForge reproduction bundle") from exc
    return ScenarioImport(xml_path=str(source), kind="xml", fidelity="definition")
