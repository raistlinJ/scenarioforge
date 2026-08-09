"""Accessibility guards for the shared /tmp staging directories.

Generate and Execute both stage artifacts under fixed /tmp paths (``/tmp/vulns``,
``/tmp/traffic``, ...) on the local machine and on the CORE VM.  Those same paths
are created by root-owned writers -- a sudo'd docker bind-mount recreates
``/tmp/traffic`` as root after every reboot -- and once that happens ``mkdir -p``
still succeeds on the existing directory while every later write fails with
EACCES, usually far from the real cause.

Check the directory before staging into it and repair it with ``sudo chmod`` when
it is not usable by the current user.
"""

from __future__ import annotations

import os
import posixpath
import shlex
import subprocess
from typing import Any, Callable, Optional

# Staging roots shared between the webapp, the CLI, and root-owned docker mounts.
TMP_STAGING_DIRS: tuple[str, ...] = (
    '/tmp/vulns',
    '/tmp/traffic',
    '/tmp/segmentation',
    '/tmp/scenarioforge',
)

# Staging dirs are shared with root-owned writers, so they need to be group/other
# writable the same way /tmp itself is.  The sticky bit keeps one writer from
# deleting another's files.
_STAGING_MODE = '1777'


def is_tmp_staging_path(path: Any) -> bool:
    """True for a concrete directory under /tmp that we are allowed to repair.

    Guards the chmod below: /tmp itself and anything outside /tmp is never a
    target, so a bad caller cannot widen permissions on an arbitrary path.
    """
    try:
        text = str(path or '').strip()
    except Exception:
        return False
    if not text:
        return False
    normalized = posixpath.normpath(text)
    if not normalized.startswith('/tmp/'):
        return False
    # Reject /tmp/.. escapes and bare /tmp.
    return len(normalized) > len('/tmp/') and '..' not in normalized.split('/')


def _usable(path: str) -> bool:
    return os.path.isdir(path) and os.access(path, os.W_OK | os.X_OK)


def ensure_local_tmp_writable(
    path: str,
    *,
    logger: Optional[Any] = None,
    sudo: bool = True,
) -> tuple[bool, str]:
    """Ensure a local /tmp staging dir exists and is writable by this user.

    Returns ``(ok, detail)``.  Repair uses ``sudo -n`` so a webapp request can
    never block on a password prompt; when sudo needs a password the caller gets
    an actionable message instead of a hang.
    """
    if not is_tmp_staging_path(path):
        return False, f'refusing to repair non-/tmp path: {path}'

    target = posixpath.normpath(str(path))
    if _usable(target):
        return True, 'already writable'

    if not os.path.exists(target):
        try:
            os.makedirs(target, exist_ok=True)
        except PermissionError:
            # A root-owned ancestor blocks creation; fall through to repair it.
            pass
        except Exception as exc:
            return False, f'mkdir failed: {exc}'
        if _usable(target):
            return True, 'created'

    if not sudo:
        return False, f'{target} is not writable by the current user'

    # Repair the deepest existing ancestor, then the target itself: when
    # /tmp/vulns is root-owned, creating /tmp/vulns/<run> fails at the parent.
    repair = target
    while repair != '/tmp' and not os.path.exists(repair):
        repair = posixpath.dirname(repair)
    if not is_tmp_staging_path(repair):
        return False, f'{target} is not writable and has no repairable /tmp parent'

    cmd = ['sudo', '-n', 'chmod', _STAGING_MODE, repair]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
    except Exception as exc:
        return False, f'sudo chmod failed: {exc}'
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or '').strip() or f'exit={proc.returncode}'
        return False, f'sudo chmod {repair} failed: {detail}'

    if logger is not None:
        try:
            logger.warning('[tmp] Repaired local staging dir permissions: %s', repair)
        except Exception:
            pass

    try:
        os.makedirs(target, exist_ok=True)
    except Exception as exc:
        return False, f'mkdir after chmod failed: {exc}'
    if _usable(target):
        return True, f'repaired via sudo chmod {_STAGING_MODE} {repair}'
    return False, f'{target} still not writable after sudo chmod'


def prepare_output_dir(path: str, *, logger: Optional[Any] = None) -> str:
    """Drop-in replacement for ``os.makedirs(path, exist_ok=True)`` on staging dirs.

    ``makedirs`` happily succeeds on an existing root-owned directory and leaves
    the caller to fail on the first write, so repair /tmp staging dirs first.
    Best-effort: a failed repair is logged and the makedirs still runs, letting
    the caller's own write report the error.
    """
    target = str(path or '')
    if is_tmp_staging_path(target):
        try:
            ok, detail = ensure_local_tmp_writable(target, logger=logger)
            if not ok and logger is not None:
                logger.warning('[tmp] Staging dir %s may not be writable: %s', target, detail)
        except Exception:
            pass
    os.makedirs(target, exist_ok=True)
    return target


def ensure_remote_tmp_writable(
    exec_command: Callable[..., tuple[int, str, str]],
    path: str,
    *,
    exec_sudo: Optional[Callable[..., tuple[int, str, str]]] = None,
    logger: Optional[Any] = None,
) -> tuple[bool, str]:
    """Ensure a /tmp staging dir on the CORE VM is writable by the SSH user.

    ``exec_command`` runs one shell command remotely and returns
    ``(exit_code, stdout, stderr)``; ``exec_sudo`` runs one as root.  Repair needs
    sudo, so a missing ``exec_sudo`` yields a clear failure rather than a silent
    later EACCES.
    """
    if not is_tmp_staging_path(path):
        return False, f'refusing to repair non-/tmp path: {path}'

    target = posixpath.normpath(str(path))
    quoted = shlex.quote(target)
    probe = (
        f"mkdir -p {quoted} 2>/dev/null; "
        f"if [ -d {quoted} ] && [ -w {quoted} ] && [ -x {quoted} ]; then echo OK; else echo DENIED; fi"
    )

    def _probe() -> bool:
        try:
            _code, out, _err = exec_command(f"sh -c {shlex.quote(probe)}", timeout=20.0)
        except Exception:
            return False
        return 'OK' in str(out or '')

    if _probe():
        return True, 'already writable'

    if exec_sudo is None:
        return False, (
            f'{target} on the CORE host is not writable by the SSH user and no sudo '
            'password is configured to repair it'
        )

    try:
        code, out, err = exec_sudo(
            f"mkdir -p {quoted} && chmod {_STAGING_MODE} {quoted}",
            timeout=45.0,
        )
    except Exception as exc:
        return False, f'sudo chmod failed: {str(exc).strip() or repr(exc)}'

    if code != 0:
        detail = (str(err or '') or str(out or '')).strip() or f'exit={code}'
        return False, f'sudo chmod {target} failed: {detail}'

    if logger is not None:
        try:
            logger.warning('[tmp] Repaired CORE staging dir permissions: %s', target)
        except Exception:
            pass

    if _probe():
        return True, f'repaired via sudo chmod {_STAGING_MODE} {target}'
    return False, f'{target} still not writable after sudo chmod'
