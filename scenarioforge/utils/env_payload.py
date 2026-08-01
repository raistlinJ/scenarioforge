"""Hand large payloads to a subprocess without breaking execve.

Linux caps a single argv/envp string at MAX_ARG_STRLEN (32 pages = 128 KiB).
Exceed it and *every* execve from that environment fails with E2BIG, including
commands that have nothing to do with the payload. Worse, the failing command
never runs, so it produces no output and the blame lands on whatever ran next.

`CORETG_FLOW_ASSIGNMENTS_JSON` hit 143,712 bytes at 17 challenges and cost four
wrong diagnoses before the cause was found. Route serialized payloads through
here so the size ceiling is enforced in one place.
"""

from __future__ import annotations

import logging
import os
import tempfile
from typing import Any, MutableMapping, Optional

logger = logging.getLogger(__name__)

# The kernel limit is 128 KiB; stay well under it so a payload that grows a
# little between measuring and spawning cannot cross the line.
MAX_ENV_VALUE_BYTES = 64 * 1024

# The kernel's own ceiling, for tests and diagnostics.
MAX_ARG_STRLEN = 128 * 1024


def sidecar_var_name(name: str) -> str:
    """Return the companion variable that carries a path instead of a value."""
    text = str(name or '').strip()
    if text.endswith('_JSON'):
        return text[: -len('_JSON')] + '_PATH'
    return text + '_PATH'


def _write_sidecar(blob: str, *, name: str, sidecar_dir: Optional[str]) -> str:
    """Write `blob` to a file and return its path, or '' if that failed."""
    if sidecar_dir:
        try:
            os.makedirs(sidecar_dir, exist_ok=True)
            path = os.path.join(sidecar_dir, f'{str(name or "payload").lower()}.json')
            with open(path, 'w', encoding='utf-8') as handle:
                handle.write(blob)
            return path
        except Exception:
            pass
    try:
        fd, path = tempfile.mkstemp(prefix=f'{str(name or "payload").lower()}_', suffix='.json')
        with os.fdopen(fd, 'w', encoding='utf-8') as handle:
            handle.write(blob)
        return path
    except Exception:
        return ''


def set_env_payload(
    env: MutableMapping[str, str],
    name: str,
    blob: str,
    *,
    sidecar_dir: Optional[str] = None,
    max_bytes: int = MAX_ENV_VALUE_BYTES,
) -> str:
    """Put `blob` in `env[name]`, spilling to a file when it is too large.

    Returns the sidecar path, or '' when the value travelled in the environment.

    The sidecar is read by whoever consumes the variable, so it must be written
    on the host that will run the subprocess -- which is the host building
    `env`, in every current caller.
    """
    text = '' if blob is None else str(blob)
    path_var = sidecar_var_name(name)

    if len(text.encode('utf-8', 'replace')) <= int(max_bytes):
        env[name] = text
        try:
            env.pop(path_var, None)
        except Exception:
            pass
        return ''

    try:
        env.pop(name, None)
    except Exception:
        pass
    path = _write_sidecar(text, name=name, sidecar_dir=sidecar_dir)
    if path:
        env[path_var] = path
        return path

    # Restoring the oversized value would break every later execve, which is a
    # far worse failure than this payload going missing. Leave it unset and say
    # so loudly.
    try:
        logger.warning(
            '[env-payload] %s is %d bytes and no sidecar could be written; '
            'dropping it rather than breaking every subprocess',
            name, len(text.encode('utf-8', 'replace')),
        )
    except Exception:
        pass
    return ''


def read_env_payload(name: str, env: Optional[MutableMapping[str, str]] = None) -> str:
    """Return the payload for `name`, from the variable or its sidecar file."""
    source: Any = os.environ if env is None else env
    try:
        raw = source.get(name) or ''
    except Exception:
        raw = ''
    if raw:
        return str(raw)
    try:
        path = str(source.get(sidecar_var_name(name)) or '').strip()
    except Exception:
        path = ''
    if not path:
        return ''
    try:
        with open(path, 'r', encoding='utf-8') as handle:
            return handle.read()
    except Exception:
        return ''
