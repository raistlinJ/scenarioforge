import io

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
    captured = capsys.readouterr()
    assert "DANGER" in captured.err
    assert "Remote ScenarioForge Docker cleanup complete." in captured.out


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
    assert "docker rm -f" not in command
    assert "docker rmi -f" not in command
    captured = capsys.readouterr()
    assert "DRY RUN" in captured.err
    assert "Dry run complete" in captured.out
