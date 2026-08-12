from __future__ import annotations

import argparse
import ast
import os
import re
import shlex
import sys
import time
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


def _prerequisite_and_persistent_images() -> list[str]:
    """Images this cleanup must never remove, unless told to.

    Mirrors ``scenarioforge.cli._persistent_images_to_keep`` exactly, but stays
    import-light (no ``scenarioforge.cli``) to match this module's existing
    "self-contained" design -- it is meant to run standalone against a host
    with nothing else importable yet.

    Two sources: images the operator explicitly pinned ``persistent`` in the
    web UI (published for a remote run via the same env-payload channel the
    UI already uses), and the framework's own prerequisites -- the pivot
    provider image and everything ``prerequisite_images()`` names (busybox,
    the wrapper base, inject-copy, generator template bases). Both are cheap
    to keep and expensive to lose: re-provisioning them is exactly what the
    air-gap/offline story exists to avoid, so a cleanup meant to reclaim disk
    space from *residual* scenario content should not undo it.
    """
    keep: list[str] = []
    try:
        from scenarioforge.utils.env_payload import read_env_payload

        import json as _json

        raw = read_env_payload("CORETG_PERSISTENT_IMAGES_JSON")
        data = _json.loads(raw) if raw else []
        if isinstance(data, list):
            keep.extend(str(x).strip() for x in data if str(x or "").strip())
    except Exception:
        pass
    try:
        from scenarioforge.utils.pivot_access import PIVOT_SSH_IMAGE

        if PIVOT_SSH_IMAGE and PIVOT_SSH_IMAGE not in keep:
            keep.append(str(PIVOT_SSH_IMAGE))
    except Exception:
        pass
    try:
        from scenarioforge.utils.prerequisite_images import prerequisite_images

        for image in prerequisite_images():
            if image and image not in keep:
                keep.append(str(image))
    except Exception:
        pass
    return keep


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
            "all non-prerequisite, non-persistent Docker containers and images on "
            "the remote host will be removed."
        ),
    )
    parser.add_argument(
        "--include-prerequisites",
        action="store_true",
        help=(
            "Also remove images the framework needs to stand any node up (busybox, "
            "wrapper bases, inject-copy, the pivot provider image) and any image the "
            "operator pinned `persistent`. Off by default: reclaiming these forces "
            "re-provisioning on the next run, which is exactly what pre-seeding them "
            "for an air-gapped host is meant to avoid. Containers are always removed "
            "regardless of this flag -- only images carry a persistence concept."
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


def _danger_warning(cfg: dict[str, Any], *, dry_run: bool, keep_count: int = 0) -> str:
    target = f"{cfg.get('ssh_username')}@{cfg.get('ssh_host')}:{cfg.get('ssh_port')}"
    if dry_run:
        return f"DRY RUN: inspecting Docker usage on remote host {target}; no Docker resources will be removed."
    scope = (
        f"remove ALL Docker containers, build cache, and unused Docker volumes/networks, "
        f"and every image except {keep_count} prerequisite/persistent image(s)"
        if keep_count
        else "remove ALL Docker containers, images, build cache, and unused Docker volumes/networks"
    )
    return f"DANGER: this will {scope} on remote host {target}."


def _confirm_or_abort(
    cfg: dict[str, Any],
    *,
    force: bool,
    dry_run: bool,
    keep_count: int = 0,
    input_stream: Any = None,
    output_stream: Any = None,
) -> bool:
    out = output_stream if output_stream is not None else sys.stderr
    print(_danger_warning(cfg, dry_run=dry_run, keep_count=keep_count), file=out)
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


def _keep_refs_array(keep_images: list[str]) -> str:
    """A bash array literal for the given image refs, quoted for embedding."""
    return " ".join(shlex.quote(str(ref)) for ref in keep_images if str(ref or "").strip())


def _cleanup_script(*, dry_run: bool, keep_images: list[str] | None = None) -> str:
    keep = [str(r).strip() for r in (keep_images or []) if str(r or "").strip()]

    if dry_run:
        keep_note = (
            f"printf 'kept_by_config=%s\\n' {len(keep)}\n" if keep else ""
        )
        return (
            r"""
set -u
echo '[cleanup] starting dry run'
echo '[cleanup] docker system df'
docker system df || true
echo '[cleanup] counting Docker resources'
printf 'containers=%s\n' "$(docker ps -aq 2>/dev/null | wc -l | tr -d ' ')"
printf 'images=%s\n' "$(docker images -aq 2>/dev/null | sort -u | wc -l | tr -d ' ')"
"""
            + keep_note
            + r"""printf 'volumes=%s\n' "$(docker volume ls -q 2>/dev/null | wc -l | tr -d ' ')"
printf 'networks=%s\n' "$(docker network ls -q 2>/dev/null | wc -l | tr -d ' ')"
echo '[cleanup] dry run complete'
""".strip()
        )

    if keep:
        # Containers carry no persistence concept -- only images do -- so the
        # container sweep is unchanged. For images: resolve each configured
        # keep-ref to the image ID it currently points to on THIS host (a ref
        # that is not pulled here resolves to nothing and is simply skipped,
        # not an error), then remove everything else. `--no-trunc` on both
        # sides is required: `docker images -q` truncates to 12 hex chars by
        # default, while `docker image inspect --format {{.Id}}` never does,
        # so without it nothing would ever match and the keep-list would
        # silently protect nothing.
        images_block = (
            "KEEP_REFS=(" + _keep_refs_array(keep) + ")\n"
            r"""KEEP_IDS=""
for ref in "${KEEP_REFS[@]}"; do
  id="$(docker image inspect --format '{{.Id}}' "$ref" 2>/dev/null || true)"
  if [ -n "$id" ]; then
    KEEP_IDS="$KEEP_IDS $id"
  fi
done
printf '[cleanup] keeping %s of %s configured prerequisite/persistent image ref(s)\n' \
  "$(echo "$KEEP_IDS" | wc -w | tr -d ' ')" "${#KEEP_REFS[@]}"
images="$(docker images -aq --no-trunc 2>/dev/null | sort -u || true)"
to_remove=""
for img in $images; do
  keep_this=0
  for kid in $KEEP_IDS; do
    if [ "$img" = "$kid" ]; then
      keep_this=1
      break
    fi
  done
  if [ "$keep_this" -eq 0 ]; then
    to_remove="$to_remove $img"
  fi
done
if [ -n "$to_remove" ]; then
  echo "$to_remove" | xargs -r docker rmi -f
else
  echo 'no images to remove'
fi
"""
        )
        # `docker image prune -af` removes every unused image regardless of
        # dangling status, which would immediately undo the keep-list above --
        # so it is skipped here rather than run unconditionally.
        prune_images_block = "echo '[cleanup] skipping unused-image prune (keep-list active)'\n"
    else:
        images_block = (
            r"""images="$(docker images -aq 2>/dev/null | sort -u || true)"
if [ -n "$images" ]; then
  echo "$images" | xargs -r docker rmi -f
else
  echo 'no images to remove'
fi
"""
        )
        prune_images_block = "docker image prune -af || true\n"

    return (
        r"""
set -u
echo '[cleanup] starting destructive Docker cleanup'
echo '[cleanup] before cleanup: docker system df'
docker system df || true

echo '[cleanup] removing all containers'
containers="$(docker ps -aq 2>/dev/null || true)"
if [ -n "$containers" ]; then
  echo "$containers" | xargs -r docker rm -f
else
  echo 'no containers to remove'
fi

echo '[cleanup] removing all images'
"""
        + images_block
        + r"""
echo '[cleanup] pruning stopped containers'
docker container prune -f || true
echo '[cleanup] pruning unused images'
"""
        + prune_images_block
        + r"""echo '[cleanup] pruning build cache'
docker builder prune -af || true
echo '[cleanup] pruning unused volumes'
# `-a` is required: since Docker 23.0 a bare `volume prune` skips *named*
# volumes, which is what a scenario creates, so this reclaimed nothing --
# measured on the CORE VM as 44 orphaned volumes surviving a prune reporting
# 0B. An unqualified `-a` is correct here, unlike the per-run cleanup: this
# command's stated contract is to remove everything unused, and every container
# is already gone by this point.
docker volume prune -af || true
echo '[cleanup] pruning unused networks'
docker network prune -f || true

echo '[cleanup] after cleanup: docker system df'
docker system df || true
echo '[cleanup] destructive cleanup complete'
""".strip()
    )


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


def _write_output(stream: Any, text: str) -> None:
    if stream is None or not text:
        return
    try:
        stream.write(text)
        stream.flush()
    except Exception:
        pass


def _stream_channel_output(
    stdout: Any,
    stderr: Any,
    *,
    timeout: float,
    output_stream: Any = None,
    error_stream: Any = None,
) -> tuple[int, str, str]:
    channel = getattr(stdout, "channel", None)
    required = ("recv_ready", "recv", "exit_status_ready", "recv_exit_status")
    if channel is None or any(not hasattr(channel, name) for name in required):
        out = stdout.read() if stdout is not None else b""
        err = stderr.read() if stderr is not None else b""
        out_text = _decode_stream(out)
        err_text = _decode_stream(err)
        _write_output(output_stream, out_text)
        _write_output(error_stream, err_text)
        try:
            code = int(stdout.channel.recv_exit_status()) if stdout is not None and hasattr(stdout, "channel") else 0
        except Exception:
            code = 0
        return code, out_text, err_text

    out_parts: list[str] = []
    err_parts: list[str] = []
    started = time.monotonic()

    def drain() -> bool:
        got_output = False
        try:
            while channel.recv_ready():
                chunk = channel.recv(65536)
                if not chunk:
                    break
                text = _decode_stream(chunk)
                out_parts.append(text)
                _write_output(output_stream, text)
                got_output = True
        except Exception:
            pass
        try:
            if hasattr(channel, "recv_stderr_ready") and hasattr(channel, "recv_stderr"):
                while channel.recv_stderr_ready():
                    chunk = channel.recv_stderr(65536)
                    if not chunk:
                        break
                    text = _decode_stream(chunk)
                    err_parts.append(text)
                    _write_output(error_stream, text)
                    got_output = True
        except Exception:
            pass
        return got_output

    while True:
        drain()
        try:
            if channel.exit_status_ready():
                drain()
                return int(channel.recv_exit_status()), "".join(out_parts), "".join(err_parts)
        except Exception:
            return 0, "".join(out_parts), "".join(err_parts)

        if timeout and timeout > 0 and (time.monotonic() - started) > timeout:
            try:
                channel.close()
            except Exception:
                pass
            raise TimeoutError(f"remote cleanup exceeded timeout of {timeout:g} seconds")

        time.sleep(0.2)


def _run_remote_cleanup(
    client: Any,
    cfg: dict[str, Any],
    *,
    dry_run: bool,
    timeout: float,
    keep_images: list[str] | None = None,
    output_stream: Any = None,
    error_stream: Any = None,
) -> tuple[int, str, str]:
    command = _sudo_command(
        _cleanup_script(dry_run=dry_run, keep_images=keep_images),
        str(cfg.get("ssh_password") or ""),
    )
    stdin = stdout = stderr = None
    try:
        stdin, stdout, stderr = client.exec_command(command, timeout=timeout, get_pty=True)
        if str(cfg.get("ssh_password") or "").strip() and stdin is not None:
            try:
                stdin.write(str(cfg.get("ssh_password")) + "\n")
                stdin.flush()
            except Exception:
                pass
        return _stream_channel_output(
            stdout,
            stderr,
            timeout=timeout,
            output_stream=output_stream,
            error_stream=error_stream,
        )
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

    keep_images: list[str] = [] if args.include_prerequisites else _prerequisite_and_persistent_images()

    if not _confirm_or_abort(
        cfg, force=bool(args.force), dry_run=bool(args.dry_run), keep_count=len(keep_images)
    ):
        return 2

    client = None
    try:
        target = f"{cfg.get('ssh_username')}@{cfg.get('ssh_host')}:{cfg.get('ssh_port')}"
        print(f"[cleanup] connecting to {target}", file=sys.stderr)
        client = _open_ssh_client(cfg)
        print(
            f"[cleanup] connected; starting {'dry run' if args.dry_run else 'destructive cleanup'} "
            f"(timeout={float(args.timeout or 900.0):g}s)",
            file=sys.stderr,
        )
        code, _out, _err = _run_remote_cleanup(
            client,
            cfg,
            dry_run=bool(args.dry_run),
            timeout=float(args.timeout or 900.0),
            keep_images=keep_images,
            output_stream=sys.stdout,
            error_stream=sys.stderr,
        )
    except Exception as exc:
        print(f"cleanup-scenarioforge-docker failed: {exc}", file=sys.stderr)
        return 1
    finally:
        try:
            if client is not None:
                client.close()
        except Exception:
            pass

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
