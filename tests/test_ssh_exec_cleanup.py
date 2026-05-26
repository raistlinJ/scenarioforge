from webapp import app_backend as backend


class _FakeChannel:
    def __init__(self, stdout_chunks=None, stderr_chunks=None, exit_status=0):
        self._stdout_chunks = list(stdout_chunks or [])
        self._stderr_chunks = list(stderr_chunks or [])
        self._exit_status = exit_status
        self.closed = False

    def settimeout(self, _timeout):
        return None

    def recv_ready(self):
        return bool(self._stdout_chunks)

    def recv(self, _size):
        return self._stdout_chunks.pop(0)

    def recv_stderr_ready(self):
        return bool(self._stderr_chunks)

    def recv_stderr(self, _size):
        return self._stderr_chunks.pop(0)

    def exit_status_ready(self):
        return not self._stdout_chunks and not self._stderr_chunks

    def recv_exit_status(self):
        return self._exit_status

    def close(self):
        self.closed = True


class _FakeStream:
    def __init__(self, channel, data=b''):
        self.channel = channel
        self._data = data
        self.closed = False

    def read(self):
        return self._data

    def close(self):
        self.closed = True


class _FakeStdin:
    def __init__(self):
        self.closed = False

    def close(self):
        self.closed = True

    def write(self, _data):
        return None

    def flush(self):
        return None


class _FakeSSHClient:
    def __init__(self, stdin, stdout, stderr):
        self._stdin = stdin
        self._stdout = stdout
        self._stderr = stderr

    def exec_command(self, _command, timeout=None, get_pty=False):
        return self._stdin, self._stdout, self._stderr


def test_exec_ssh_command_closes_streams_and_channel(monkeypatch):
    monkeypatch.setattr(backend.time, 'sleep', lambda _seconds: None)

    channel = _FakeChannel(stdout_chunks=[b'hello\n'], stderr_chunks=[b'warn\n'], exit_status=7)
    stdin = _FakeStdin()
    stdout = _FakeStream(channel)
    stderr = _FakeStream(channel)
    client = _FakeSSHClient(stdin, stdout, stderr)

    exit_code, out_text, err_text = backend._exec_ssh_command(client, 'echo test', timeout=1.0)

    assert exit_code == 7
    assert out_text == 'hello\n'
    assert err_text == 'warn\n'
    assert stdin.closed is True
    assert stdout.closed is True
    assert stderr.closed is True
    assert channel.closed is True


def test_exec_ssh_python_probe_closes_streams_and_channel():
    channel = _FakeChannel(exit_status=0)
    stdin = _FakeStdin()
    stdout = _FakeStream(channel, b'OK\n')
    stderr = _FakeStream(channel, b'')
    client = _FakeSSHClient(stdin, stdout, stderr)

    exit_code, out_text, err_text = backend._exec_ssh_python_probe(client, 'python -V', timeout=1.0)

    assert exit_code == 0
    assert out_text == 'OK\n'
    assert err_text == ''
    assert stdin.closed is True
    assert stdout.closed is True
    assert stderr.closed is True
    assert channel.closed is True