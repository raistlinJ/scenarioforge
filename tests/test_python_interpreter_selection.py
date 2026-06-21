from webapp import app_backend as backend


def test_select_python_interpreter_prefers_current_process_interpreter(monkeypatch):
    current_python = '/tmp/current-python'

    monkeypatch.delenv('CORE_PY', raising=False)
    monkeypatch.setattr(backend, '_resolve_cli_venv_bin', lambda preferred=None, allow_fallback=True: '')
    monkeypatch.setattr(backend.sys, 'executable', current_python)
    monkeypatch.setattr(backend.os, 'access', lambda path, mode: path == current_python)

    def _unexpected_which(name, path=None):
        raise AssertionError(f'unexpected PATH lookup for {name}')

    monkeypatch.setattr(backend.shutil, 'which', _unexpected_which)

    assert backend._select_python_interpreter() == current_python


def test_select_python_interpreter_respects_named_core_py_override(monkeypatch):
    current_python = '/tmp/current-python'

    monkeypatch.setenv('CORE_PY', 'python9')
    monkeypatch.setattr(backend, '_resolve_cli_venv_bin', lambda preferred=None, allow_fallback=True: '')
    monkeypatch.setattr(backend.sys, 'executable', current_python)
    monkeypatch.setattr(backend.os, 'access', lambda path, mode: path == current_python)
    monkeypatch.setattr(
        backend.shutil,
        'which',
        lambda name, path=None: '/custom/python9' if name == 'python9' else None,
    )

    assert backend._select_python_interpreter() == '/custom/python9'