"""The agent binaries must actually reach the CORE VM.

ScenarioForge runs on a workstation and pushes the repo to the CORE VM; the VM
has no git clone. Anything the repo push drops never arrives, and the traffic
service then finds no binary. This was a real failure: the binaries were first
placed in `traffic_agent/dist`, and `dist` is excluded by both `.gitignore` and
`REPO_PUSH_EXCLUDE_DIRS`, so a normal push silently shipped nothing.
"""

import os
from pathlib import Path

import webapp.app_backend as backend
from scenarioforge.utils import traffic


AGENT_DIR = Path("traffic_agent/bin")


def _push_excludes(relpath: str) -> bool:
    """Mirror the repo push walker, which drops any path containing an excluded dir."""
    return any(part in backend.REPO_PUSH_EXCLUDE_DIRS for part in relpath.split(os.sep))


def test_agent_directory_survives_the_repo_push():
    assert not _push_excludes("traffic_agent/bin/traffic-agent-linux-arm64")
    # The original location did not, which is what made this fail silently.
    assert _push_excludes("traffic_agent/dist/traffic-agent-linux-arm64")


def test_agent_directory_is_not_gitignored():
    # A gitignored binary is missing from a fresh clone and from teammates.
    import subprocess

    result = subprocess.run(
        ["git", "check-ignore", "traffic_agent/bin/traffic-agent-linux-arm64"],
        capture_output=True, text=True,
    )
    assert result.returncode != 0, "agent binaries must not be gitignored"


def test_generator_looks_in_the_shipped_directory():
    assert Path(traffic._agent_source_dir()).name == "bin"
    assert Path(traffic._agent_source_dir()).parent.name == "traffic_agent"


def test_both_architectures_are_present():
    # A Docker node may be an emulated amd64 image on an arm64 host, so the
    # node's architecture -- not the host's -- decides which binary is used.
    names = {p.name for p in AGENT_DIR.iterdir()} if AGENT_DIR.is_dir() else set()
    assert "traffic-agent-linux-amd64" in names
    assert "traffic-agent-linux-arm64" in names


def test_binaries_are_executable_and_static():
    for name in ("traffic-agent-linux-amd64", "traffic-agent-linux-arm64"):
        path = AGENT_DIR / name
        assert os.access(path, os.X_OK), f"{name} must be executable"
        header = path.read_bytes()[:4]
        assert header == b"\x7fELF", f"{name} should be an ELF binary"


def test_build_script_writes_to_the_shipped_directory():
    script = Path("traffic_agent/build.sh").read_text(encoding="utf-8")
    assert 'out="$here/bin"' in script
    assert "/src/bin/traffic-agent-linux-$arch" in script
