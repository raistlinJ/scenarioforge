"""Wrapper start-up hardening and restart-loop visibility.

CORE applies a docker node's address, default route and traffic agent to the
namespace of the container that was live at execute, and nothing reapplies them.
So a container that silently exits or restarts loses its whole network identity,
which surfaces as unrelated routing/traffic failures rather than as a crash.
"""

import re
import subprocess

from scenarioforge.utils import vuln_process as vp
from webapp import artifact_checks as ac


def _shim_body() -> str:
    body = []
    for ln in vp._wrapper_app_user_shim_lines():
        s = ln.strip()
        if not s.startswith("echo '"):
            continue
        s = s[len("echo '"):]
        s = s[:s.rfind("'")] if "'" in s else s
        body.append(s)
    return "\n".join(body) + "\n"


def test_shim_is_valid_posix_shell(tmp_path):
    path = tmp_path / "shim.sh"
    path.write_text(_shim_body(), encoding="utf-8")
    assert subprocess.run(["sh", "-n", str(path)]).returncode == 0


def test_shim_falls_back_instead_of_dying_without_setuidgid():
    """`exec` replaces the shell, so a missing applet would kill the container."""
    body = _shim_body()
    assert 'if "$BB" setuidgid "$tgt" true' in body
    # The unguarded exec must not be the only path any more.
    assert body.index('setuidgid "$tgt" true') < body.index('exec "$BB" setuidgid "$tgt" "$@"')
    assert 'exec "$@"' in body


def test_services_check_fails_a_running_but_restarting_container():
    summary = {"docker_running": ["docker-6", "docker-7"], "docker_not_running": [],
               "docker_missing": [], "docker_start_pending": [],
               "docker_restarting": [{"container": "docker-7", "restart_count": 5}]}
    res = ac.services_result(summary)
    assert res["status"] == "fail"
    assert "stuck restarting" in res["summary"]
    detail = next(i["detail"] for i in res["items"] if i["name"] == "docker-7")
    assert "restarted 5 time(s)" in detail
    assert next(i["status"] for i in res["items"] if i["name"] == "docker-6") == "pass"


def test_services_check_unchanged_without_restart_data():
    summary = {"docker_running": ["docker-6"], "docker_not_running": [],
               "docker_missing": [], "docker_start_pending": []}
    res = ac.services_result(summary)
    assert res["status"] == "pass"


def test_services_check_ignores_a_zero_restart_count():
    summary = {"docker_running": ["docker-6"], "docker_not_running": [],
               "docker_missing": [], "docker_start_pending": [],
               "docker_restarting": [{"container": "docker-6", "restart_count": 0}]}
    assert ac.services_result(summary)["status"] == "pass"


def test_validator_summary_is_not_ok_while_a_container_restarts():
    """`ok: true` alongside a restart loop is how this hid in eval runs.

    The validator's ok flag drove the summary the harness reads, so a node that
    kept losing its address, route and traffic agent still reported success.
    """
    import inspect
    from webapp import app_backend as ab
    src = inspect.getsource(ab)
    marker = src.index("if (\n        summary['missing_nodes']")
    condition = src[marker:marker + 900]
    assert "summary['docker_restarting']" in condition
