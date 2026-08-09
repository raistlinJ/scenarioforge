import io
import subprocess
from pathlib import Path
from types import SimpleNamespace

from scenarioforge import cleanup_scenarioforge_docker as cleanup


class _FakeChannel:
    def __init__(self, exit_status=0):
        self.exit_status = exit_status

    def recv_exit_status(self):
        return self.exit_status


class _FakeStream:
    def __init__(self, data=b"", exit_status=0):
        self.data = data
        self.channel = _FakeChannel(exit_status)
        self.closed = False

    def read(self):
        return self.data

    def close(self):
        self.closed = True


class _FakeStdin:
    def __init__(self):
        self.writes = []
        self.closed = False

    def write(self, data):
        self.writes.append(data)

    def flush(self):
        return None

    def close(self):
        self.closed = True


class _FakeSSHClient:
    def __init__(self, exit_status=0):
        self.exit_status = exit_status
        self.commands = []
        self.stdin = _FakeStdin()
        self.closed = False

    def exec_command(self, command, timeout=None, get_pty=False):
        self.commands.append({"command": command, "timeout": timeout, "get_pty": get_pty})
        stdout = _FakeStream(b"cleanup output\n", self.exit_status)
        stderr = _FakeStream(b"", self.exit_status)
        return self.stdin, stdout, stderr

    def close(self):
        self.closed = True


class _StreamingChannel:
    def __init__(self, chunks, err_chunks=None, exit_status=0):
        self.chunks = list(chunks)
        self.err_chunks = list(err_chunks or [])
        self.exit_status = exit_status
        self.closed = False

    def recv_ready(self):
        return bool(self.chunks)

    def recv(self, _size):
        return self.chunks.pop(0)

    def recv_stderr_ready(self):
        return bool(self.err_chunks)

    def recv_stderr(self, _size):
        return self.err_chunks.pop(0)

    def exit_status_ready(self):
        return not self.chunks and not self.err_chunks

    def recv_exit_status(self):
        return self.exit_status

    def close(self):
        self.closed = True


def test_confirmation_requires_exact_phrase():
    cfg = {"ssh_username": "corevm", "ssh_host": "10.0.0.50", "ssh_port": 22}
    output = io.StringIO()

    ok = cleanup._confirm_or_abort(
        cfg,
        force=False,
        dry_run=False,
        input_stream=io.StringIO("nope\n"),
        output_stream=output,
    )

    assert ok is False
    assert "DANGER" in output.getvalue()
    assert cleanup.CONFIRMATION_PHRASE in output.getvalue()


def test_force_cleanup_runs_remote_destructive_docker_commands(monkeypatch, capsys):
    client = _FakeSSHClient()
    opened = []

    def fake_open(cfg):
        opened.append(dict(cfg))
        return client

    monkeypatch.setattr(cleanup, "_open_ssh_client", fake_open)
    # This test is about the container/prune plumbing, not the keep-list --
    # isolate it from whatever prerequisites happen to be importable.
    monkeypatch.setattr(cleanup, "_prerequisite_and_persistent_images", lambda: [])

    code = cleanup.main(
        [
            "--ssh-host",
            "10.0.0.50",
            "--ssh-port",
            "2222",
            "--ssh-username",
            "corevm",
            "--ssh-password",
            "pw",
            "--force",
        ]
    )

    assert code == 0
    assert opened[0]["ssh_host"] == "10.0.0.50"
    assert opened[0]["ssh_port"] == 2222
    assert client.stdin.writes == ["pw\n"]
    assert client.closed is True
    command = client.commands[0]["command"]
    assert client.commands[0]["get_pty"] is True
    assert "sudo -S" in command
    assert "docker ps -aq" in command
    assert "docker rm -f" in command
    assert "docker images -aq" in command
    assert "docker rmi -f" in command
    assert "docker builder prune -af" in command
    assert "docker volume prune -f" in command
    assert "[cleanup] removing all containers" in command
    assert "[cleanup] pruning unused volumes" in command
    captured = capsys.readouterr()
    assert "DANGER" in captured.err
    assert "[cleanup] connecting to corevm@10.0.0.50:2222" in captured.err
    assert "cleanup output" in captured.out
    assert "Remote ScenarioForge Docker cleanup complete." in captured.out


# --------------------------------------------------------------------------- #
# Default behavior now protects prerequisite/persistent images -- the flag's
# own docstring calls it "remove ALL", but the fully-total version of that
# forced every scenario, including ones that changed nothing framework-side,
# to re-provision busybox/wrapper-base/inject-copy/pivot-provider images (and
# anything an operator explicitly pinned `persistent`) from scratch. That is
# exactly what pre-seeding those images for an air-gapped host exists to
# avoid, so the destructive sweep now carries them forward by default.
# --------------------------------------------------------------------------- #

def test_default_cleanup_keeps_prerequisite_and_persistent_images(monkeypatch, capsys):
    client = _FakeSSHClient()
    monkeypatch.setattr(cleanup, "_open_ssh_client", lambda _cfg: client)
    monkeypatch.setattr(
        cleanup,
        "_prerequisite_and_persistent_images",
        lambda: ["busybox:1.36.1-musl", "vulhub/confluence:7.13.6"],
    )

    code = cleanup.main(
        [
            "--ssh-host", "10.0.0.50",
            "--ssh-username", "corevm",
            "--ssh-password", "pw",
            "--force",
        ]
    )

    assert code == 0
    command = client.commands[0]["command"]
    # The whole script is shlex.quote()-wrapped for the outer `sudo ... bash -lc`
    # call, which rewrites every embedded `'` into a `'"'"'` sequence -- so only
    # substrings with no single quotes of their own survive verbatim here.
    assert "KEEP_REFS=(busybox:1.36.1-musl vulhub/confluence:7.13.6)" in command
    assert "docker image inspect --format" in command
    assert "--no-trunc" in command
    # The blanket prune would remove every unused image regardless of the
    # keep-list's exclusions, undoing them immediately after the filtered
    # `docker rmi -f` sweep ran.
    assert "docker image prune -af" not in command
    assert "skipping unused-image prune (keep-list active)" in command
    captured = capsys.readouterr()
    assert "every image except 2 prerequisite/persistent image(s)" in captured.err


def test_include_prerequisites_flag_restores_the_old_remove_everything_behavior(monkeypatch, capsys):
    client = _FakeSSHClient()
    monkeypatch.setattr(cleanup, "_open_ssh_client", lambda _cfg: client)
    monkeypatch.setattr(
        cleanup, "_prerequisite_and_persistent_images", lambda: ["busybox:1.36.1-musl"]
    )

    code = cleanup.main(
        [
            "--ssh-host", "10.0.0.50",
            "--ssh-username", "corevm",
            "--ssh-password", "pw",
            "--force",
            "--include-prerequisites",
        ]
    )

    assert code == 0
    command = client.commands[0]["command"]
    assert "KEEP_REFS=" not in command
    assert "docker image prune -af" in command
    captured = capsys.readouterr()
    assert "remove ALL Docker containers, images, build cache" in captured.err


def test_dry_run_reports_the_configured_keep_count(monkeypatch, capsys):
    client = _FakeSSHClient()
    monkeypatch.setattr(cleanup, "_open_ssh_client", lambda _cfg: client)
    monkeypatch.setattr(cleanup, "_prerequisite_and_persistent_images", lambda: ["a", "b", "c"])

    code = cleanup.main(
        [
            "--ssh-host", "10.0.0.50",
            "--ssh-username", "corevm",
            "--ssh-password", "pw",
            "--dry-run",
        ]
    )

    assert code == 0
    command = client.commands[0]["command"]
    assert "kept_by_config" in command
    assert "docker rmi -f" not in command


# --------------------------------------------------------------------------- #
# _cleanup_script: the shell fragment that actually decides what survives
# --------------------------------------------------------------------------- #

def test_cleanup_script_is_valid_shell(tmp_path):
    for keep_images in (None, ["ref-a", "ref-b"]):
        for dry_run in (False, True):
            script = "set -eu\n" + cleanup._cleanup_script(dry_run=dry_run, keep_images=keep_images)
            path = tmp_path / "script.sh"
            path.write_text(script, encoding="utf-8")
            result = subprocess.run(["bash", "-n", str(path)], capture_output=True, text=True)
            assert result.returncode == 0, (
                f"invalid shell (dry_run={dry_run}, keep_images={keep_images}): {result.stderr}"
            )


def test_cleanup_script_without_keep_images_matches_old_unconditional_sweep():
    script = cleanup._cleanup_script(dry_run=False, keep_images=None)
    assert "docker images -aq 2>/dev/null | sort -u" in script
    assert "docker rmi -f" in script
    assert "docker image prune -af" in script
    assert "KEEP_REFS" not in script


def test_cleanup_script_quotes_keep_refs_for_shell_safety():
    script = cleanup._cleanup_script(dry_run=False, keep_images=['weird ref"with quotes'])
    assert "'weird ref\"with quotes'" in script


def test_cleanup_script_empty_keep_list_behaves_like_no_keep_list():
    # An empty list and None must be equivalent -- both mean "nothing to
    # protect," not "protect nothing found," which would be a no-op anyway
    # but should still take the simpler, well-tested unconditional path.
    assert cleanup._cleanup_script(dry_run=False, keep_images=[]) == cleanup._cleanup_script(
        dry_run=False, keep_images=None
    )


# --------------------------------------------------------------------------- #
# _prerequisite_and_persistent_images: must mirror
# scenarioforge.cli._persistent_images_to_keep without importing cli itself
# --------------------------------------------------------------------------- #

def test_prerequisite_images_module_stays_import_light():
    # A `sys.modules` check would be order-dependent -- any other test in the
    # same run that imports scenarioforge.cli first (several legitimately do)
    # leaves it cached for the rest of the process regardless of what this
    # module itself imports. A static check of this module's own import
    # statements is what actually verifies the property, independent of
    # what else has already run.
    import ast

    source = Path(cleanup.__file__).read_text(encoding="utf-8")
    tree = ast.parse(source)
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            imported.update(alias.name for alias in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            imported.add(node.module)

    cli_imports = {name for name in imported if name == "scenarioforge.cli" or name.endswith(".cli")}
    assert not cli_imports, (
        f"cleanup_scenarioforge_docker.py imports {cli_imports} -- this module is "
        "meant to run standalone without scenarioforge.cli"
    )


def test_prerequisite_and_persistent_images_includes_pivot_and_framework_images(monkeypatch):
    monkeypatch.setattr(
        "scenarioforge.utils.pivot_access.PIVOT_SSH_IMAGE",
        "example/pivot-ssh:latest",
        raising=False,
    )
    monkeypatch.setattr(
        "scenarioforge.utils.prerequisite_images.prerequisite_images",
        lambda: ["busybox:1.36.1-musl", "ubuntu:22.04"],
    )
    monkeypatch.delenv("CORETG_PERSISTENT_IMAGES_JSON", raising=False)

    keep = cleanup._prerequisite_and_persistent_images()

    assert "example/pivot-ssh:latest" in keep
    assert "busybox:1.36.1-musl" in keep
    assert "ubuntu:22.04" in keep


def test_prerequisite_and_persistent_images_includes_operator_pinned_images(monkeypatch):
    import json

    monkeypatch.setattr(
        "scenarioforge.utils.prerequisite_images.prerequisite_images", lambda: []
    )
    monkeypatch.setattr(
        "scenarioforge.utils.pivot_access.PIVOT_SSH_IMAGE", "", raising=False
    )
    monkeypatch.setenv(
        "CORETG_PERSISTENT_IMAGES_JSON", json.dumps(["operator/pinned:v1"])
    )

    keep = cleanup._prerequisite_and_persistent_images()

    assert keep == ["operator/pinned:v1"]


def test_prerequisite_and_persistent_images_deduplicates(monkeypatch):
    monkeypatch.setattr(
        "scenarioforge.utils.prerequisite_images.prerequisite_images", lambda: ["dup:latest"]
    )
    monkeypatch.setattr(
        "scenarioforge.utils.pivot_access.PIVOT_SSH_IMAGE", "dup:latest", raising=False
    )

    keep = cleanup._prerequisite_and_persistent_images()

    assert keep.count("dup:latest") == 1


def test_dry_run_skips_force_and_uses_inspection_only(monkeypatch, capsys):
    client = _FakeSSHClient()
    monkeypatch.setattr(cleanup, "_open_ssh_client", lambda _cfg: client)

    code = cleanup.main(
        [
            "--ssh-host",
            "10.0.0.50",
            "--ssh-username",
            "corevm",
            "--ssh-password",
            "pw",
            "--dry-run",
        ]
    )

    assert code == 0
    command = client.commands[0]["command"]
    assert "docker system df" in command
    assert "docker ps -aq" in command
    assert "[cleanup] starting dry run" in command
    assert "[cleanup] counting Docker resources" in command
    assert "docker rm -f" not in command
    assert "docker rmi -f" not in command
    captured = capsys.readouterr()
    assert "DRY RUN" in captured.err
    assert "[cleanup] connected; starting dry run" in captured.err
    assert "cleanup output" in captured.out
    assert "Dry run complete" in captured.out


def test_stream_channel_output_writes_progress_as_chunks_arrive():
    channel = _StreamingChannel(
        [b"[cleanup] step one\n", b"[cleanup] step two\n"],
        [b"warning line\n"],
        exit_status=7,
    )
    stdout = SimpleNamespace(channel=channel)
    out = io.StringIO()
    err = io.StringIO()

    code, out_text, err_text = cleanup._stream_channel_output(
        stdout,
        None,
        timeout=5,
        output_stream=out,
        error_stream=err,
    )

    assert code == 7
    assert out_text == "[cleanup] step one\n[cleanup] step two\n"
    assert err_text == "warning line\n"
    assert out.getvalue() == out_text
    assert err.getvalue() == err_text


def test_resolved_config_loads_env_file_from_current_directory(tmp_path, monkeypatch):
    env_path = tmp_path / ".scenarioforge.env"
    env_path.write_text(
        "\n".join(
            [
                "CORE_SSH_HOST=10.0.0.77",
                "CORE_SSH_PORT=2207",
                "CORE_SSH_USERNAME=file-user",
                "CORE_SSH_PASSWORD='file password'",
            ]
        ),
        encoding="utf-8",
    )
    for key in ("CORETG_ENV_FILE", "CORE_HOST", "CORE_SSH_HOST", "CORE_SSH_PORT", "CORE_SSH_USERNAME", "CORE_SSH_PASSWORD"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path)

    cfg = cleanup._resolved_config(
        SimpleNamespace(ssh_host=None, ssh_port=None, ssh_username=None, ssh_password=None)
    )

    assert cfg == {
        "ssh_host": "10.0.0.77",
        "ssh_port": 2207,
        "ssh_username": "file-user",
        "ssh_password": "file password",
    }


def test_resolved_config_keeps_exported_env_over_env_file(tmp_path, monkeypatch):
    env_path = tmp_path / ".scenarioforge.env"
    env_path.write_text(
        "\n".join(
            [
                "CORE_SSH_HOST=10.0.0.77",
                "CORE_SSH_PORT=2207",
                "CORE_SSH_USERNAME=file-user",
                "CORE_SSH_PASSWORD=file-password",
            ]
        ),
        encoding="utf-8",
    )
    for key in ("CORETG_ENV_FILE", "CORE_HOST", "CORE_SSH_HOST", "CORE_SSH_PORT", "CORE_SSH_USERNAME", "CORE_SSH_PASSWORD"):
        monkeypatch.delenv(key, raising=False)
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CORE_SSH_HOST", "10.0.0.88")
    monkeypatch.setenv("CORE_SSH_USERNAME", "exported-user")

    cfg = cleanup._resolved_config(
        SimpleNamespace(ssh_host=None, ssh_port=None, ssh_username=None, ssh_password=None)
    )

    assert cfg["ssh_host"] == "10.0.0.88"
    assert cfg["ssh_port"] == 2207
    assert cfg["ssh_username"] == "exported-user"
    assert cfg["ssh_password"] == "file-password"
