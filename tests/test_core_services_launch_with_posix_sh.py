"""The CORE services that run on Docker nodes must not require bash.

A Docker node's container IS the scenario's own image -- a vulnerability, a
generator, a pivot provider -- so a service's startup command runs inside
whatever the author chose. Plenty of those images ship no bash, and when the
launcher asks for one the exec fails before the script's first line: nothing
runs, the script's own log is never written, and the only trace is in the
core-daemon journal. That is exactly how traffic came to be configured,
mounted and enabled on a vulnerability node yet never start.

Bash is not available for the asking either. The one thing that would install
it, CoreTGPrereqs, shells out to apt-get/apk/yum with every install wrapped in
`|| true`, so on an air-gapped host it succeeds while installing nothing.

Neither script body needs bash, so both launch with `sh`. These tests pin that
in two directions: the launcher asks for sh, and the body stays POSIX.
"""

import re
import subprocess
import textwrap
from pathlib import Path

import pytest

SERVICES = ("TrafficService", "Segmentation", "CoreTGPrereqs")


def _source(service: str) -> str:
    return Path(f"on_core_machine/custom_services/{service}.py").read_text(
        "utf-8", errors="ignore"
    )


def _script_body(service: str) -> str:
    """The shell the node actually runs, with Python's escaping resolved.

    The template is a normal (non-raw) Python string, so a line continuation is
    written `\\\\` in source and reaches the node as `\\`. Reading the file text
    without that step yields shell that does not parse, which would make this
    test fail for a reason that has nothing to do with the node.
    """
    template = re.search(r'return r?"""(.*?)"""', _source(service), re.S).group(1)
    if not re.search(r'return r"""', _source(service)):
        template = template.encode().decode("unicode_escape")
    body = re.search(r"<%text>(.*?)</%text>", template, re.S).group(1)
    return textwrap.dedent(body)


@pytest.mark.parametrize("service", SERVICES)
def test_service_launches_with_sh_not_bash(service):
    startup = re.search(r"startup: list\[str\] = \[(.*?)\]", _source(service), re.S).group(1)
    assert "/bin/sh -c" in startup, f"{service} startup must launch with sh"
    assert "/bin/bash" not in startup, (
        f"{service} startup requires bash, which the scenario's own image may not ship"
    )
    assert "exec bash" not in startup


@pytest.mark.parametrize("service", SERVICES)
def test_script_body_parses_under_posix_sh(service, tmp_path):
    script = tmp_path / f"{service}.sh"
    script.write_text(_script_body(service), encoding="utf-8")
    result = subprocess.run(
        ["/bin/sh", "-n", str(script)], capture_output=True, text=True
    )
    assert result.returncode == 0, f"{service} body is not POSIX shell: {result.stderr}"


@pytest.mark.parametrize("service", SERVICES)
def test_script_body_has_no_bashisms(service):
    body = _script_body(service)
    # `sh -n` on a host whose /bin/sh is bash accepts bashisms, so name the
    # common ones outright rather than trusting the parser alone.
    patterns = {
        "[[ ]]": r"\[\[",
        "arithmetic $(( ))": r"\$\(\(",
        "function keyword": r"\bfunction\s+\w+\s*\(",
        "here-string <<<": r"<<<",
        "array subscript": r"\$\{\w+\[",
        "source builtin": r"^\s*source\s",
        "+= assignment": r"^\s*\w+\+=",
        "echo -e": r"echo\s+-e\b",
        "pipefail": r"set\s+-\w*o\s+pipefail|pipefail",
    }
    found = [name for name, pattern in patterns.items() if re.search(pattern, body, re.M)]
    assert not found, f"{service} body uses bash-only syntax: {found}"


@pytest.mark.parametrize("service", ("TrafficService", "Segmentation"))
def test_script_shebang_matches_the_launcher(service):
    # The launcher execs the file explicitly so the shebang is not consulted,
    # but a stale `#!/bin/bash` would mislead the next reader and would break
    # anyone who ran the script directly.
    assert "#!/bin/sh" in _source(service)
