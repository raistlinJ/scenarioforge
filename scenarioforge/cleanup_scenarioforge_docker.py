from __future__ import annotations

import argparse
import ast
import os
import re
import shlex
import sys
from pathlib import Path
from typing import Any


CONFIRMATION_PHRASE = "DELETE ALL REMOTE DOCKER"
_ENV_KEY_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")


def _env_file_candidates() -> list[Path]:
    candidates: list[Path] = []
    explicit = str(os.environ.get("CORETG_ENV_FILE") or "").strip()
    if explicit:
        candidates.append(Path(explicit).expanduser())
    candidates.append(Path.cwd() / ".scenarioforge.env")
    candidates.append(Path(__file__).resolve().parent.parent / ".scenarioforge.env")

    deduped: list[Path] = []
    seen: set[Path] = set()
    for candidate in candidates:
        resolved = candidate.resolve(strict=False)
        if resolved in seen:
            continue
        seen.add(resolved)
        deduped.append(resolved)
    return deduped


def _parse_env_value(raw: str) -> str:
    value = raw.strip()
    if not value:
        return ""
    if value[0] in {'"', "'"} and value[-1:] == value[0]:
        try:
            return str(ast.literal_eval(value))
        except Exception:
            return value[1:-1]
    comment_index = value.find(" #")
    if comment_index >= 0:
        value = value[:comment_index].rstrip()
    return value


def _load_env_file(path: str | Path, *, override: bool = False) -> list[str]:
    env_path = Path(path).expanduser().resolve(strict=False)
    if not env_path.is_file():
        return []
    try:
        lines = env_path.read_text(encoding="utf-8", errors="ignore").splitlines()
    except Exception:
        return []

    loaded: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        if line.startswith("export "):
            line = line[7:].lstrip()
        key, sep, value = line.partition("=")
        if not sep:
            continue
        key = key.strip()
        if not _ENV_KEY_RE.match(key):
            continue
        if override or key not in os.environ:
            os.environ[key] = _parse_env_value(value)
        loaded.append(key)
    return loaded


def _load_runtime_env() -> list[Path]:
    loaded: list[Path] = []
    for candidate in _env_file_candidates():
        if _load_env_file(candidate, override=False):
            loaded.append(candidate)
    if loaded:
        return loaded

    # Backward-compatible fallback for source-tree runs that already have webapp
    # importable. The cleanup command itself remains self-contained above.
    try:
        from webapp.env_loader import load_runtime_env_files

        return list(load_runtime_env_files(include_example=False))
    except Exception:
        return []


def _env_int(name: str, default: int) -> int:
    try:
        return int(str(os.environ.get(name) or "").strip() or default)
    except Exception:
        return default


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="cleanup-scenarioforge-docker",
        description=(
            "Dangerous maintenance command: remove all Docker containers, images, "
            "build cache, and unused Docker volumes/networks from a remote CORE host."
        ),
        epilog=(
            "Configuration is read from exported environment variables, CORETG_ENV_FILE, "
            ".scenarioforge.env in the current directory, or .scenarioforge.env in the ScenarioForge source root."
        ),
    )
    parser.add_argument("--ssh-host", default=None, help="Remote CORE SSH host. Defaults to CORE_SSH_HOST, then CORE_HOST.")
    parser.add_argument("--ssh-port", type=int, default=None, help="Remote CORE SSH port. Defaults to CORE_SSH_PORT or 22.")
    parser.add_argument("--ssh-username", default=None, help="Remote CORE SSH username. Defaults to CORE_SSH_USERNAME.")
    parser.add_argument("--ssh-password", default=None, help="Remote CORE SSH password. Defaults to CORE_SSH_PASSWORD.")
    parser.add_argument("--timeout", type=float, default=900.0, help="Remote cleanup timeout in seconds. Default: 900.")
    parser.add_argument("--dry-run", action="store_true", help="Show remote Docker disk usage/counts without deleting anything.")
    parser.add_argument(
        "--force",
        action="store_true",
        help=(
            "Skip the interactive confirmation prompt. This is still destructive: "
            "all Docker containers and images on the remote host will be removed."
        ),
    )
    return parser


def _resolved_config(args: argparse.Namespace) -> dict[str, Any]:
    _load_runtime_env()
    return {
        "ssh_host": str(args.ssh_host or os.environ.get("CORE_SSH_HOST") or os.environ.get("CORE_HOST") or "").strip(),
        "ssh_port": int(args.ssh_port or _env_int("CORE_SSH_PORT", 22)),
        "ssh_username": str(args.ssh_username or os.environ.get("CORE_SSH_USERNAME") or "").strip(),
        "ssh_password": str(args.ssh_password if args.ssh_password is not None else os.environ.get("CORE_SSH_PASSWORD") or ""),
    }


def _validate_config(cfg: dict[str, Any]) -> list[str]:
    missing: list[str] = []
    if not str(cfg.get("ssh_host") or "").strip():
        missing.append("ssh host")
    if not str(cfg.get("ssh_username") or "").strip():
        missing.append("ssh username")
    if not str(cfg.get("ssh_password") or "").strip():
        missing.append("ssh password")
    return missing


def _danger_warning(cfg: dict[str, Any], *, dry_run: bool) -> str:
    target = f"{cfg.get('ssh_username')}@{cfg.get('ssh_host')}:{cfg.get('ssh_port')}"
    if dry_run:
        return f"DRY RUN: inspecting Docker usage on remote host {target}; no Docker resources will be removed."
    return (
        "DANGER: this will remove ALL Docker containers, images, build cache, "
        f"and unused Docker volumes/networks on remote host {target}."
    )


def _confirm_or_abort(cfg: dict[str, Any], *, force: bool, dry_run: bool, input_stream: Any = None, output_stream: Any = None) -> bool:
    out = output_stream if output_stream is not None else sys.stderr
    print(_danger_warning(cfg, dry_run=dry_run), file=out)
    if dry_run or force:
        return True

    print(f'Type "{CONFIRMATION_PHRASE}" to continue: ', end="", file=out, flush=True)
    try:
        raw = (input_stream if input_stream is not None else sys.stdin).readline()
    except Exception:
        raw = ""
    if str(raw or "").strip() == CONFIRMATION_PHRASE:
        return True
    print("Aborted: confirmation phrase did not match.", file=out)
    return False


def _cleanup_script(*, dry_run: bool) -> str:
    if dry_run:
        return r"""
set -u
echo '== docker system df =='
docker system df || true
echo '== counts =='
printf 'containers=%s\n' "$(docker ps -aq 2>/dev/null | wc -l | tr -d ' ')"
printf 'images=%s\n' "$(docker images -aq 2>/dev/null | sort -u | wc -l | tr -d ' ')"
printf 'volumes=%s\n' "$(docker volume ls -q 2>/dev/null | wc -l | tr -d ' ')"
printf 'networks=%s\n' "$(docker network ls -q 2>/dev/null | wc -l | tr -d ' ')"
""".strip()

    return r"""
set -u
echo '== before cleanup =='
docker system df || true

containers="$(docker ps -aq 2>/dev/null || true)"
if [ -n "$containers" ]; then
  echo "$containers" | xargs -r docker rm -f
else
  echo 'no containers to remove'
fi

images="$(docker images -aq 2>/dev/null | sort -u || true)"
if [ -n "$images" ]; then
  echo "$images" | xargs -r docker rmi -f
else
  echo 'no images to remove'
fi

docker container prune -f || true
docker image prune -af || true
docker builder prune -af || true
docker volume prune -f || true
docker network prune -f || true

echo '== after cleanup =='
docker system df || true
""".strip()


def _sudo_command(script: str, password: str) -> str:
    if str(password or "").strip():
        return f"sudo -S -p '' -k bash -lc {shlex.quote(script)}"
    return f"sudo -n bash -lc {shlex.quote(script)}"


def _decode_stream(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, bytes):
        return value.decode("utf-8", "replace")
    return str(value)


def _run_remote_cleanup(client: Any, cfg: dict[str, Any], *, dry_run: bool, timeout: float) -> tuple[int, str, str]:
    command = _sudo_command(_cleanup_script(dry_run=dry_run), str(cfg.get("ssh_password") or ""))
    stdin = stdout = stderr = None
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout, get_pty=True)
        if str(cfg.get("ssh_password") or "").strip() and stdin is not None:
            try:
                stdin.write(str(cfg.get("ssh_password")) + "\n")
                stdin.flush()
            except Exception:
                pass
        out = stdout.read() if stdout is not None else b""
        err = stderr.read() if stderr is not None else b""
        try:
            code = int(stdout.channel.recv_exit_status()) if stdout is not None and hasattr(stdout, "channel") else 0
        except Exception:
            code = 0
        return code, _decode_stream(out), _decode_stream(err)
    finally:
        for stream in (stdin, stdout, stderr):
            try:
                if stream is not None:
                    stream.close()
            except Exception:
                pass


def _open_ssh_client(cfg: dict[str, Any]) -> Any:
    try:
        import paramiko  # type: ignore
    except Exception as exc:  # pragma: no cover - depends on installed optional package
        raise RuntimeError("cleanup-scenarioforge-docker requires paramiko to connect over SSH.") from exc

    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(
        hostname=str(cfg.get("ssh_host") or ""),
        port=int(cfg.get("ssh_port") or 22),
        username=str(cfg.get("ssh_username") or ""),
        password=str(cfg.get("ssh_password") or ""),
        look_for_keys=False,
        allow_agent=False,
        timeout=20.0,
        banner_timeout=20.0,
        auth_timeout=20.0,
    )
    return client


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    cfg = _resolved_config(args)
    missing = _validate_config(cfg)
    if missing:
        parser.error(
            "missing remote CORE SSH configuration: "
            + ", ".join(missing)
            + ". Provide --ssh-* flags or set CORE_SSH_* in .scenarioforge.env."
        )

    if not _confirm_or_abort(cfg, force=bool(args.force), dry_run=bool(args.dry_run)):
        return 2

    client = None
    try:
        client = _open_ssh_client(cfg)
        code, out, err = _run_remote_cleanup(client, cfg, dry_run=bool(args.dry_run), timeout=float(args.timeout or 900.0))
    except Exception as exc:
        print(f"cleanup-scenarioforge-docker failed: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            if client is not None:
                client.close()
        except Exception:
            pass

    if out:
        print(out, end="" if out.endswith("\n") else "\n")
    if err:
        print(err, file=sys.stderr, end="" if err.endswith("\n") else "\n")
    if code != 0:
        print(f"cleanup-scenarioforge-docker failed with remote exit code {code}", file=sys.stderr)
        return code
    if args.dry_run:
        print("Dry run complete; no Docker resources were removed.")
    else:
        print("Remote ScenarioForge Docker cleanup complete.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
