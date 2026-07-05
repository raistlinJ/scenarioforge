from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import requests


DEFAULT_BASE_URL = "http://127.0.0.1:9090"
VALID_SCOPES = ("unvalidated", "failed", "all_enabled")
TARGETS = ("vulns", "flag-generators", "flag-node-generators", "all")
SCOPE_ALIASES = {
    "unvalidated": "unvalidated",
    "untested": "unvalidated",
    "incomplete": "unvalidated",
    "unvalidated_incomplete": "unvalidated",
    "unvalidated-incomplete": "unvalidated",
    "unvalidated / incomplete": "unvalidated",
    "failed": "failed",
    "previously_failed": "failed",
    "previously-failed": "failed",
    "previously failed": "failed",
    "all": "all_enabled",
    "all_enabled": "all_enabled",
    "all-enabled": "all_enabled",
    "all enabled": "all_enabled",
    "enabled": "all_enabled",
}


class CatalogBatchError(RuntimeError):
    def __init__(self, message: str, *, exit_code: int = 12) -> None:
        super().__init__(message)
        self.exit_code = exit_code


@dataclass(frozen=True)
class BatchSpec:
    name: str
    start_path: str
    status_path: str
    export_path: str
    payload_kind: str | None = None


@dataclass(frozen=True)
class BatchOutcome:
    name: str
    run_id: str
    selected_count: int
    done: bool
    status: str
    progress: dict[str, Any]
    export_path: Path | None

    def failed_count(self, *, allow_skipped: bool) -> int:
        failed = _progress_int(self.progress, "failed")
        incomplete = _progress_int(self.progress, "incomplete")
        pending = _progress_int(self.progress, "pending")
        skipped = 0 if allow_skipped else _progress_int(self.progress, "skipped")
        not_done = 0 if self.done else 1
        return failed + incomplete + pending + skipped + not_done


def _truthy(value: Any) -> bool:
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    return str(value).strip().lower() in {"1", "true", "yes", "on", "y"}


def _log(message: str) -> None:
    print(message, flush=True)


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run ScenarioForge catalog batch tests through the Web UI API before execute.",
    )
    parser.add_argument(
        "--target",
        choices=TARGETS,
        default=os.getenv("CORETG_BATCH_TARGET", "all"),
        help="Catalog family to test. 'all' runs vulns, flag-generators, then flag-node-generators.",
    )
    parser.add_argument("--base-url", default=os.getenv("CORETG_WEB_BASE", DEFAULT_BASE_URL))
    parser.add_argument("--username", default=os.getenv("CORETG_WEB_USER", "coreadmin"))
    parser.add_argument("--password", default=os.getenv("CORETG_WEB_PASS", "coreadmin"))
    parser.add_argument(
        "--scope",
        default=os.getenv("CORETG_BATCH_SCOPE", "unvalidated"),
        metavar="{untested,failed,all}",
        help="Batch selection scope. Accepts UI-style aliases such as untested, failed, and all.",
    )
    parser.add_argument("--query", default=os.getenv("CORETG_BATCH_QUERY", ""))
    parser.add_argument("--limit", type=int, default=int(os.getenv("CORETG_BATCH_LIMIT", "0") or "0"))
    parser.add_argument(
        "--include-disabled",
        action="store_true",
        default=_truthy(os.getenv("CORETG_BATCH_INCLUDE_DISABLED")),
    )
    parser.add_argument(
        "--allow-skipped",
        action="store_true",
        default=_truthy(os.getenv("CORETG_BATCH_ALLOW_SKIPPED")),
        help="Return success when a batch only has skipped items, for example manual-input generators.",
    )
    parser.add_argument(
        "--core-json",
        default=os.getenv("CORETG_BATCH_CORE_JSON", ""),
        help="CORE config as a JSON object, a path to a JSON file, or @path.",
    )
    parser.add_argument("--core-secret-id", default=os.getenv("CORETG_CORE_SECRET_ID", ""))
    parser.add_argument(
        "--repo-root",
        default=os.getenv("CORETG_REPO_ROOT", "."),
        help="Repo root used for output paths and local core-secret hints.",
    )
    parser.add_argument(
        "--out-dir",
        default=os.getenv("CORETG_BATCH_OUT_DIR", "outputs/catalog-batch-tests"),
        help="Directory for exported JSON reports. Use an empty value to skip export.",
    )
    parser.add_argument("--request-timeout", type=float, default=float(os.getenv("CORETG_BATCH_REQUEST_TIMEOUT", "30")))
    parser.add_argument("--poll-interval", type=float, default=float(os.getenv("CORETG_BATCH_POLL_INTERVAL", "5")))
    parser.add_argument(
        "--max-wait-seconds",
        type=float,
        default=float(os.getenv("CORETG_BATCH_MAX_WAIT_SECONDS", "0") or "0"),
        help="Maximum wait per batch. 0 means wait until the server reports done.",
    )
    return parser.parse_args(argv)


def _normalize_scope(value: Any) -> str:
    key = re.sub(r"\s+", " ", str(value or "unvalidated").strip().lower())
    normalized = SCOPE_ALIASES.get(key)
    if normalized:
        return normalized
    valid = ", ".join(sorted(SCOPE_ALIASES))
    raise CatalogBatchError(f"invalid --scope {value!r}; expected one of: {valid}", exit_code=2)


def _target_specs(target: str) -> list[BatchSpec]:
    vuln = BatchSpec(
        name="vulns",
        start_path="/vuln_catalog_items/batch/start",
        status_path="/vuln_catalog_items/batch/status",
        export_path="/vuln_catalog_items/batch/export.json",
    )
    flag = BatchSpec(
        name="flag-generators",
        start_path="/flag_catalog_items/batch/start",
        status_path="/flag_catalog_items/batch/status",
        export_path="/flag_catalog_items/batch/export.json",
        payload_kind="flag-generator",
    )
    flag_node = BatchSpec(
        name="flag-node-generators",
        start_path="/flag_catalog_items/batch/start",
        status_path="/flag_catalog_items/batch/status",
        export_path="/flag_catalog_items/batch/export.json",
        payload_kind="flag-node-generator",
    )
    if target == "vulns":
        return [vuln]
    if target == "flag-generators":
        return [flag]
    if target == "flag-node-generators":
        return [flag_node]
    return [vuln, flag, flag_node]


def _response_json(response: requests.Response, *, context: str) -> dict[str, Any]:
    try:
        payload = response.json()
    except Exception as exc:
        raise CatalogBatchError(f"{context}: expected JSON response, got HTTP {response.status_code}: {exc}") from exc
    if not isinstance(payload, dict):
        raise CatalogBatchError(f"{context}: expected JSON object, got {type(payload).__name__}")
    return payload


def _login(session: requests.Session, *, base_url: str, username: str, password: str, timeout: float) -> None:
    response = session.post(
        f"{base_url}/login",
        data={"username": username, "password": password},
        allow_redirects=False,
        timeout=timeout,
    )
    _log(f"LOGIN_STATUS={response.status_code}")
    if response.status_code not in (200, 302):
        raise CatalogBatchError("login failed", exit_code=10)


def _parse_json_object(text: str, *, context: str) -> dict[str, Any]:
    try:
        payload = json.loads(text)
    except Exception as exc:
        raise CatalogBatchError(f"{context}: invalid JSON: {exc}", exit_code=11) from exc
    if not isinstance(payload, dict):
        raise CatalogBatchError(f"{context}: expected a JSON object", exit_code=11)
    return payload


def _load_core_json(value: str, *, repo_root: Path) -> dict[str, Any] | None:
    raw = str(value or "").strip()
    if not raw:
        return None

    path_text = raw[1:] if raw.startswith("@") else raw
    candidate = Path(path_text).expanduser()
    if not candidate.is_absolute():
        candidate = repo_root / candidate
    if raw.startswith("@") or candidate.is_file():
        try:
            return _parse_json_object(candidate.read_text(encoding="utf-8"), context=f"core json file {candidate}")
        except OSError as exc:
            raise CatalogBatchError(f"core json file {candidate}: {exc}", exit_code=11) from exc

    return _parse_json_object(raw, context="--core-json")


def _candidate_secret_ids(repo_root: Path, explicit_secret_id: str) -> list[str]:
    candidate_ids: list[str] = []
    preferred = str(explicit_secret_id or "").strip()
    if preferred:
        candidate_ids.append(preferred)

    hint_path = repo_root / "outputs" / "flag_generators_test_core_hint.json"
    try:
        if hint_path.is_file():
            hint_payload = json.loads(hint_path.read_text(encoding="utf-8"))
            if isinstance(hint_payload, dict):
                hinted_id = str(hint_payload.get("core_secret_id") or "").strip()
                if hinted_id and hinted_id not in candidate_ids:
                    candidate_ids.append(hinted_id)
    except Exception:
        pass

    secret_dir = repo_root / "outputs" / "secrets" / "core"
    if secret_dir.is_dir():
        for path in sorted(secret_dir.glob("*.json")):
            secret_id = path.stem
            if secret_id and secret_id not in candidate_ids:
                candidate_ids.append(secret_id)

    return candidate_ids


def _core_cfg_from_secret_payload(creds: dict[str, Any]) -> dict[str, Any] | None:
    ssh_host = str(creds.get("ssh_host") or creds.get("host") or "").strip()
    ssh_user = str(creds.get("ssh_username") or "").strip()
    ssh_password = str(creds.get("ssh_password") or "").strip()
    if not (ssh_host and ssh_user and ssh_password):
        return None

    core_cfg: dict[str, Any] = {
        "ssh_host": ssh_host,
        "ssh_port": int(creds.get("ssh_port") or 22),
        "ssh_username": ssh_user,
        "ssh_password": ssh_password,
        "host": str(creds.get("host") or ssh_host),
        "port": int(creds.get("port") or 50051),
    }
    venv_bin = str(creds.get("venv_bin") or "").strip()
    if venv_bin:
        core_cfg["venv_bin"] = venv_bin
    return core_cfg


def _load_core_cfg_from_secret(
    session: requests.Session,
    *,
    base_url: str,
    timeout: float,
    repo_root: Path,
    secret_id: str,
) -> dict[str, Any] | None:
    candidate_ids = _candidate_secret_ids(repo_root, secret_id)
    if candidate_ids:
        _log(f"CORE_SECRET_COUNT={len(candidate_ids)}")
    for sid in candidate_ids:
        try:
            response = session.post(
                f"{base_url}/api/core/credentials/get",
                json={"core_secret_id": sid},
                timeout=timeout,
            )
        except Exception as exc:
            _log(f"SECRET_READ_ERR={sid} {exc}")
            continue
        if response.status_code != 200:
            continue
        payload = _response_json(response, context=f"core secret {sid}")
        creds = payload.get("credentials") if isinstance(payload.get("credentials"), dict) else {}
        core_cfg = _core_cfg_from_secret_payload(creds)
        if core_cfg:
            _log(f"USING_CORE_SECRET={sid}")
            return core_cfg
    return None


def _load_core_cfg(
    session: requests.Session,
    *,
    base_url: str,
    timeout: float,
    repo_root: Path,
    core_json: str,
    core_secret_id: str,
) -> dict[str, Any]:
    from_json = _load_core_json(core_json, repo_root=repo_root)
    if from_json is not None:
        _log("CORE_CONFIG=core-json")
        return from_json

    from_secret = _load_core_cfg_from_secret(
        session,
        base_url=base_url,
        timeout=timeout,
        repo_root=repo_root,
        secret_id=core_secret_id,
    )
    if from_secret is not None:
        _log("CORE_CONFIG=secret")
        return from_secret

    if str(core_secret_id or "").strip():
        raise CatalogBatchError("no usable CORE secret found for --core-secret-id", exit_code=11)

    _log("CORE_CONFIG=web-default")
    return {}


def _progress_int(progress: dict[str, Any], key: str) -> int:
    try:
        return int(progress.get(key) or 0)
    except Exception:
        return 0


def _progress_tuple(progress: dict[str, Any]) -> tuple[int, int, int, int, int, int, int]:
    return (
        _progress_int(progress, "total"),
        _progress_int(progress, "completed"),
        _progress_int(progress, "passed"),
        _progress_int(progress, "failed"),
        _progress_int(progress, "incomplete"),
        _progress_int(progress, "skipped"),
        _progress_int(progress, "pending"),
    )


def _format_progress(spec_name: str, status: str, progress: dict[str, Any]) -> str:
    total, completed, passed, failed, incomplete, skipped, pending = _progress_tuple(progress)
    return (
        f"{spec_name}: status={status or 'unknown'} completed={completed}/{total} "
        f"passed={passed} failed={failed} incomplete={incomplete} skipped={skipped} pending={pending}"
    )


def _safe_filename(value: str) -> str:
    text = re.sub(r"[^A-Za-z0-9_.-]+", "-", str(value or "").strip()).strip("-")
    return text or "batch"


def _write_export(
    session: requests.Session,
    *,
    base_url: str,
    spec: BatchSpec,
    run_id: str,
    out_dir: Path | None,
    timeout: float,
) -> Path | None:
    if out_dir is None:
        return None
    response = session.get(f"{base_url}{spec.export_path}", params={"run_id": run_id}, timeout=timeout)
    payload = _response_json(response, context=f"{spec.name} export")
    if response.status_code >= 400 or payload.get("ok") is False:
        raise CatalogBatchError(f"{spec.name} export failed: {payload.get('error') or response.status_code}")

    out_dir.mkdir(parents=True, exist_ok=True)
    path = out_dir / f"{_safe_filename(spec.name)}-{_safe_filename(run_id)}.json"
    path.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    _log(f"{spec.name}: export={path}")
    return path


def _start_payload(args: argparse.Namespace, spec: BatchSpec, core_cfg: dict[str, Any]) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "scope": args.scope,
        "query": str(args.query or ""),
        "include_disabled": bool(args.include_disabled),
        "core": core_cfg,
    }
    if int(args.limit or 0) > 0:
        payload["limit"] = int(args.limit)
    if spec.payload_kind:
        payload["kind"] = spec.payload_kind
    return payload


def _run_batch(
    session: requests.Session,
    *,
    base_url: str,
    args: argparse.Namespace,
    spec: BatchSpec,
    core_cfg: dict[str, Any],
    out_dir: Path | None,
) -> BatchOutcome:
    start_payload = _start_payload(args, spec, core_cfg)
    _log(f"{spec.name}: starting scope={args.scope} limit={int(args.limit or 0) or 'none'}")
    response = session.post(
        f"{base_url}{spec.start_path}",
        json=start_payload,
        timeout=max(float(args.request_timeout), 60.0),
    )
    payload = _response_json(response, context=f"{spec.name} start")
    if response.status_code >= 400 or payload.get("ok") is not True:
        raise CatalogBatchError(f"{spec.name} start failed: {payload.get('error') or response.status_code}")

    run_id = str(payload.get("run_id") or "").strip()
    if not run_id:
        raise CatalogBatchError(f"{spec.name} start failed: missing run_id")
    try:
        selected_count = int(payload.get("selected_count") or 0)
    except Exception:
        selected_count = 0
    _log(f"{spec.name}: run_id={run_id} selected={selected_count}")

    deadline = None
    max_wait = float(args.max_wait_seconds or 0)
    if max_wait > 0:
        deadline = time.monotonic() + max_wait

    last_seen: tuple[int, int, int, int, int, int, int] | None = None
    final_payload: dict[str, Any] = {}
    while True:
        status_response = session.get(f"{base_url}{spec.status_path}", params={"run_id": run_id}, timeout=args.request_timeout)
        status_payload = _response_json(status_response, context=f"{spec.name} status")
        if status_response.status_code >= 400 or status_payload.get("ok") is not True:
            raise CatalogBatchError(f"{spec.name} status failed: {status_payload.get('error') or status_response.status_code}")

        final_payload = status_payload
        progress = status_payload.get("progress") if isinstance(status_payload.get("progress"), dict) else {}
        status = str(status_payload.get("status") or "")
        current = _progress_tuple(progress)
        if current != last_seen:
            _log(_format_progress(spec.name, status, progress))
            last_seen = current
        if bool(status_payload.get("done")):
            break
        if deadline is not None and time.monotonic() >= deadline:
            _log(f"{spec.name}: max wait reached before done")
            break
        time.sleep(max(0.1, float(args.poll_interval)))

    progress = final_payload.get("progress") if isinstance(final_payload.get("progress"), dict) else {}
    status = str(final_payload.get("status") or "")
    export_path = _write_export(
        session,
        base_url=base_url,
        spec=spec,
        run_id=run_id,
        out_dir=out_dir,
        timeout=args.request_timeout,
    )
    return BatchOutcome(
        name=spec.name,
        run_id=run_id,
        selected_count=selected_count,
        done=bool(final_payload.get("done")),
        status=status,
        progress=progress,
        export_path=export_path,
    )


def _out_dir(args: argparse.Namespace, *, repo_root: Path) -> Path | None:
    raw = str(args.out_dir or "").strip()
    if not raw:
        return None
    path = Path(raw).expanduser()
    if not path.is_absolute():
        path = repo_root / path
    return path


def _print_summary(outcomes: list[BatchOutcome], *, allow_skipped: bool) -> None:
    _log("SUMMARY")
    for outcome in outcomes:
        progress = outcome.progress
        _log(
            _format_progress(outcome.name, outcome.status, progress)
            + f" run_id={outcome.run_id} ok={outcome.failed_count(allow_skipped=allow_skipped) == 0}"
        )


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    base_url = str(args.base_url or DEFAULT_BASE_URL).rstrip("/")
    repo_root = Path(args.repo_root).expanduser().resolve()
    out_dir = _out_dir(args, repo_root=repo_root)

    try:
        args.scope = _normalize_scope(args.scope)
        session = requests.Session()
        _login(
            session,
            base_url=base_url,
            username=str(args.username or ""),
            password=str(args.password or ""),
            timeout=float(args.request_timeout),
        )
        core_cfg = _load_core_cfg(
            session,
            base_url=base_url,
            timeout=float(args.request_timeout),
            repo_root=repo_root,
            core_json=str(args.core_json or ""),
            core_secret_id=str(args.core_secret_id or ""),
        )

        outcomes: list[BatchOutcome] = []
        for spec in _target_specs(str(args.target or "all")):
            outcomes.append(
                _run_batch(
                    session,
                    base_url=base_url,
                    args=args,
                    spec=spec,
                    core_cfg=core_cfg,
                    out_dir=out_dir,
                )
            )

        _print_summary(outcomes, allow_skipped=bool(args.allow_skipped))
        failed = sum(outcome.failed_count(allow_skipped=bool(args.allow_skipped)) for outcome in outcomes)
        return 0 if failed == 0 else 20
    except KeyboardInterrupt:
        _log("INTERRUPTED")
        return 130
    except CatalogBatchError as exc:
        _log(f"ERROR={exc}")
        return exc.exit_code


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
