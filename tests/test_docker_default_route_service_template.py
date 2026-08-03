import inspect
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from mako.template import Template

SERVICE = Path("on_core_machine/custom_services/DockerDefaultRoute.py")


class _FakeNode:
    id = 7
    name = "docker-2"


def _template() -> str:
    src = SERVICE.read_text(encoding="utf-8")
    match = re.search(r'return r"""(.*?)"""', src, re.S)
    assert match, "could not extract the shell template"
    return match.group(1)


def _script() -> str:
    """The script as CORE actually writes it: cleandoc, then Mako."""
    return Template(inspect.cleandoc(_template())).render_unicode(
        node=_FakeNode(), config={}
    )


def test_docker_default_route_service_uses_absolute_paths() -> None:
    txt = SERVICE.read_text(encoding="utf-8")
    assert 'name: str = "DockerDefaultRoute"' in txt
    assert 'files: list[str] = ["/defaultroute.sh"]' in txt
    # Relative first (namespaced vnode), absolute fallback (Docker node).
    assert "f=defaultroute.sh;" in txt
    assert "f=/defaultroute.sh" in txt
    assert 'validate: list[str] = []' in txt
    assert "grep -q '^default '" not in txt


def test_script_body_is_a_verbatim_mako_block() -> None:
    """CORE renders service files through Mako, which mangles plain shell.

    `<%text>` makes the body verbatim so idioms like `${VAR:-default}` and
    `${count}s` are safe to write. Rendering here proves it round-trips.
    """
    assert "<%text>" in _template()
    rendered = _script()
    assert "<%text>" not in rendered
    # Shell parameter expansion must survive Mako untouched.
    assert '"${CORETG_DEFAULT_ROUTE_WAIT_S:-45}"' in rendered
    assert "${waited}s" in rendered


def test_script_is_valid_posix_shell() -> None:
    assert subprocess.run(["sh", "-n", "-c", _script()]).returncode == 0


def test_script_prefers_core_attached_interface_over_eth0() -> None:
    script = _script()
    # eth0 is commonly a leftover docker bridge, but a CORE-attached interface
    # can also be eth0, so the second pass must accept it.
    assert 'for pass in 1 2' in script
    assert '"$dev" = "eth0"' in script
    assert '"$dev" != "lo"' in script


def test_script_waits_for_a_late_address() -> None:
    """CORE assigns interface addresses concurrently with service startup.

    Without a wait the script exits before the address exists and nothing ever
    re-runs it, leaving a node with a connected route but no default gateway.
    """
    script = _script()
    assert 'CORETG_DEFAULT_ROUTE_WAIT_S' in script
    assert 'find_addr' in script
    assert 'sleep 1' in script


def test_script_retries_and_records_failures() -> None:
    script = _script()
    assert 'route replace default' in script
    assert 'route add default' in script
    # Errors must reach the log rather than /dev/null.
    assert 'replace=[$err] add=[$err2]' in script


@pytest.mark.skipif(shutil.which("sh") is None, reason="POSIX shell required")
@pytest.mark.parametrize(
    "cidr,expected",
    [
        ("10.0.33.2/24", "10.0.33.1"),
        ("10.0.33.2/16", "10.0.0.1"),
        # When the node holds the first host address, shift to the next one.
        ("10.0.33.1/24", "10.0.33.2"),
        ("192.168.194.5/24", "192.168.194.1"),
    ],
)
def test_gateway_derivation_matches_subnet(cidr: str, expected: str) -> None:
    """Exercise the real arithmetic; the old code assumed a /24."""
    script = _script()
    body = script.split("# An explicit override wins", 1)[1]
    body = body.split("has_default()", 1)[0]
    addr, prefix = cidr.split("/")
    a, b, c, d = addr.split(".")
    harness = f"""
CORETG_DEFAULT_GW=""
ipaddr="{addr}"; prefix="{prefix}"
a={a}; b={b}; c={c}; d={d}
log() {{ :; }}
{body}
echo "$gw"
"""
    out = subprocess.run(["sh", "-c", harness], capture_output=True, text=True)
    assert out.returncode == 0, out.stderr
    assert out.stdout.strip() == expected


def test_gateway_override_is_honored() -> None:
    script = _script()
    assert 'gw="${CORETG_DEFAULT_GW:-}"' in script
