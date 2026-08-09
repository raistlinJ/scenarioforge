from webapp import app_backend as ab


def _fake_exec(out, code=0):
    def _f(client, cmd, *, timeout=None, **kw):
        return (code, out, '')
    return _f


_DF = ("Filesystem     1024-blocks      Used Available Capacity Mounted on\n"
       "/dev/sda1         51343840  48900000   1200000      98% /\n")


def test_remote_free_bytes_parses_posix_df(monkeypatch):
    monkeypatch.setattr(ab, '_exec_ssh_command', _fake_exec(_DF))
    assert ab._remote_free_bytes(None, '/tmp') == 1200000 * 1024


def test_remote_free_bytes_handles_a_wrapped_device_name(monkeypatch):
    """-P keeps it on one line, but tolerate a long name if it ever wraps."""
    wrapped = ("Filesystem 1024-blocks Used Available Capacity Mounted on\n"
               "/dev/mapper/a-very-long-volume-name 51343840 48900000 900000 98% /\n")
    monkeypatch.setattr(ab, '_exec_ssh_command', _fake_exec(wrapped))
    assert ab._remote_free_bytes(None, '/tmp') == 900000 * 1024


def test_remote_free_bytes_is_none_when_df_is_unavailable_or_odd(monkeypatch):
    monkeypatch.setattr(ab, '_exec_ssh_command', _fake_exec('', 1))
    assert ab._remote_free_bytes(None, '/tmp') is None
    monkeypatch.setattr(ab, '_exec_ssh_command', _fake_exec('weird\n'))
    assert ab._remote_free_bytes(None, '/tmp') is None
    monkeypatch.setattr(ab, '_exec_ssh_command', _fake_exec('a b\nc d\n'))
    assert ab._remote_free_bytes(None, '/tmp') is None


def test_remote_free_bytes_survives_a_dead_connection(monkeypatch):
    def _boom(*a, **k):
        raise EOFError()
    monkeypatch.setattr(ab, '_exec_ssh_command', _boom)
    assert ab._remote_free_bytes(None, '/tmp') is None
