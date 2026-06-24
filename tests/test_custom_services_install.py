import types

import pytest

from webapp import app_backend as backend


class _FakeChannel:
    def __init__(self, exit_status: int = 0):
        self._exit_status = exit_status

    def recv_exit_status(self):
        return self._exit_status


class _FakeStream:
    def __init__(self, data: bytes = b"", exit_status: int = 0):
        self._data = data
        self.channel = _FakeChannel(exit_status)

    def read(self):
        return self._data


class _FakeStdin:
    def __init__(self):
        self.writes = []

    def write(self, data):
        self.writes.append(data)

    def flush(self):
        return None

    def close(self):
        return None


class _FakeSFTP:
    def __init__(self):
        self.put_calls = []

    def put(self, localpath, remotepath):
        self.put_calls.append((str(localpath), str(remotepath)))

    def close(self):
        return None


class _MemoryRemoteFile:
    def __init__(self, sftp, remote_path):
        self.sftp = sftp
        self.remote_path = str(remote_path)
        self.chunks = []

    def write(self, data):
        self.chunks.append(bytes(data))

    def flush(self):
        return None

    def close(self):
        self.sftp.files[self.remote_path] = b"".join(self.chunks)


class _FlakySFTP(_FakeSFTP):
    def __init__(self):
        super().__init__()
        self.files = {}
        self.fail_first_put = True
        self.stream_uploads = []

    def put(self, localpath, remotepath, confirm=True):
        self.put_calls.append((str(localpath), str(remotepath)))
        if self.fail_first_put:
            self.fail_first_put = False
            self.files[str(remotepath)] = b""
            size = __import__("os").path.getsize(localpath)
            raise OSError(f"size mismatch in put!  0 != {size}")
        with open(localpath, "rb") as handle:
            self.files[str(remotepath)] = handle.read()

    def open(self, remotepath, mode="r"):
        assert "w" in mode
        self.stream_uploads.append(str(remotepath))
        return _MemoryRemoteFile(self, remotepath)

    def stat(self, remotepath):
        return types.SimpleNamespace(st_size=len(self.files.get(str(remotepath), b"")))


class _BrokenStreamSFTP(_FlakySFTP):
    def open(self, remotepath, mode="r"):
        assert "w" in mode
        self.stream_uploads.append(str(remotepath))
        raise OSError("Failure")


class _FakeSSHClient:
    def __init__(
        self,
        *,
        services_dir: str = "/usr/local/lib/python3/dist-packages/core/services",
        core_conf_custom_dir: str | None = None,
        core_conf_custom_lines: list[str] | None = None,
        core_conf_path: str = "/opt/core/etc/core.conf",
        core_conf_exists_without_custom: bool = False,
    ):
        self.commands = []
        self.sftp = _FakeSFTP()
        self.services_dir = services_dir
        self.core_conf_custom_dir = core_conf_custom_dir
        self.core_conf_custom_lines = list(core_conf_custom_lines or [])
        self.core_conf_path = core_conf_path
        self.core_conf_exists_without_custom = core_conf_exists_without_custom

    def open_sftp(self):
        return self.sftp

    def exec_command(self, cmd, timeout=None, get_pty=None):
        self.commands.append(str(cmd))

        stdin = _FakeStdin()
        stdout_data = b""
        stderr_data = b""

        if "import os, core.services" in cmd:
            stdout_data = (self.services_dir + "\n").encode("utf-8")
        elif "core.conf" in cmd and "custom_services" in cmd and self.core_conf_custom_lines:
            lines = [f"__CORECONF_PATH__={self.core_conf_path}", "__CORECONF_READABLE__=1", *self.core_conf_custom_lines]
            stdout_data = ("\n".join(lines) + "\n").encode("utf-8")
        elif "core.conf" in cmd and "custom_services" in cmd and self.core_conf_custom_dir:
            lines = [
                f"__CORECONF_PATH__={self.core_conf_path}",
                "__CORECONF_READABLE__=1",
                f"custom_services_dir = {self.core_conf_custom_dir}",
            ]
            stdout_data = ("\n".join(lines) + "\n").encode("utf-8")
        elif "core.conf" in cmd and "custom_services" in cmd and self.core_conf_exists_without_custom:
            lines = [f"__CORECONF_PATH__={self.core_conf_path}", "__CORECONF_READABLE__=1"]
            stdout_data = ("\n".join(lines) + "\n").encode("utf-8")
        elif "::SERVICESCHECK::" in cmd or "SERVICESCHECK" in cmd or "coretg-services-verify" in cmd:
            # Simulate successful discovery/scan on the remote VM.
            payload = {
                "custom_modules": ["TrafficService", "Segmentation", "DockerComposeService"],
                "module_service_names": {
                    "TrafficService": ["Traffic"],
                    "Segmentation": ["Segmentation"],
                    "DockerComposeService": ["DockerCompose"],
                },
                "custom_service_names": ["DockerCompose", "Segmentation", "Traffic"],
                "missing_modules": [],
                "modules_without_services": [],
                "all_service_names_count": 123,
                "custom_names_missing_from_scan": [],
            }
            stdout_data = ("::SERVICESCHECK::" + __import__("json").dumps(payload) + "\n").encode("utf-8")
        else:
            stdout_data = b""

        return stdin, _FakeStream(stdout_data, 0), _FakeStream(stderr_data, 0)


class _CommandUploadFallbackSSHClient(_FakeSSHClient):
    def __init__(self, *, expected_upload_size: int, **kwargs):
        super().__init__(**kwargs)
        self.expected_upload_size = expected_upload_size
        self.command_uploads = []
        self.command_upload_stdin = []

    def exec_command(self, cmd, timeout=None, get_pty=None):
        if "<coretg-custom-service-upload>" in str(cmd):
            self.commands.append(str(cmd))
            stdin = _FakeStdin()
            self.command_uploads.append(str(cmd))
            self.command_upload_stdin.append(stdin)
            stdout = _FakeStream(f"{self.expected_upload_size}\n".encode("utf-8"), 0)
            return stdin, stdout, _FakeStream(b"", 0)
        return super().exec_command(cmd, timeout=timeout, get_pty=get_pty)


def test_install_custom_services_to_core_vm_copies_and_verifies(tmp_path, monkeypatch):
    # Provide temp custom services so the test does not depend on repo files.
    files = []
    for name in ("TrafficService.py", "Segmentation.py", "DockerComposeService.py"):
        p = tmp_path / name
        p.write_text("# test service\n")
        files.append(str(p))

    monkeypatch.setattr(backend, "_local_custom_service_files", lambda: files)

    client = _FakeSSHClient()
    meta = backend._install_custom_services_to_core_vm(
        client,
        sudo_password="pw",
        logger=types.SimpleNamespace(info=lambda *_a, **_k: None),
    )

    assert meta["services_dir"] == client.services_dir
    assert set(meta["modules"]) == {"DockerComposeService", "Segmentation", "TrafficService"}
    assert set(meta.get("service_names") or []) == {"DockerCompose", "Segmentation", "Traffic"}

    # Uploaded all .py files into /tmp/coretg_custom_services.
    remote_targets = [dst for _src, dst in client.sftp.put_calls]
    assert all(dst.startswith("/tmp/coretg_custom_services/") for dst in remote_targets)
    assert {dst.split("/")[-1] for dst in remote_targets} == {"TrafficService.py", "Segmentation.py", "DockerComposeService.py"}

    # Ran install + restart + import verification.
    assert any("install -m 0644" in cmd for cmd in client.commands)
    assert any("systemctl restart core-daemon" in cmd for cmd in client.commands)
    assert any(("SERVICESCHECK" in cmd or "coretg-services-verify" in cmd) for cmd in client.commands)


def test_install_custom_services_recovers_from_sftp_put_size_mismatch(tmp_path, monkeypatch):
    p = tmp_path / "DockerDefaultRoute.py"
    p.write_text("# test service\nVALUE = 'x'\n", encoding="utf-8")
    monkeypatch.setattr(backend, "_local_custom_service_files", lambda: [str(p)])

    client = _FakeSSHClient()
    client.sftp = _FlakySFTP()

    meta = backend._install_custom_services_to_core_vm(
        client,
        sudo_password="pw",
        logger=types.SimpleNamespace(info=lambda *_a, **_k: None),
    )

    remote_path = "/tmp/coretg_custom_services/DockerDefaultRoute.py"
    assert meta["services_dir"] == client.services_dir
    assert client.sftp.put_calls
    assert client.sftp.stream_uploads == [remote_path]
    assert client.sftp.files[remote_path] == p.read_bytes()


def test_install_custom_services_uses_command_upload_when_sftp_stream_fails(tmp_path, monkeypatch):
    p = tmp_path / "DockerDefaultRoute.py"
    p.write_text("# test service\nVALUE = 'x'\n", encoding="utf-8")
    monkeypatch.setattr(backend, "_local_custom_service_files", lambda: [str(p)])

    client = _CommandUploadFallbackSSHClient(expected_upload_size=p.stat().st_size)
    client.sftp = _BrokenStreamSFTP()

    meta = backend._install_custom_services_to_core_vm(
        client,
        sudo_password="pw",
        logger=types.SimpleNamespace(info=lambda *_a, **_k: None),
    )

    assert meta["services_dir"] == client.services_dir
    assert client.sftp.put_calls
    assert client.sftp.stream_uploads == [
        "/tmp/coretg_custom_services/DockerDefaultRoute.py",
        "/tmp/coretg_custom_services/DockerDefaultRoute.py",
    ]
    assert len(client.command_uploads) == 1
    assert "base64.b64decode" in client.command_uploads[0]
    written = "".join(str(chunk) for chunk in client.command_upload_stdin[0].writes)
    assert __import__("base64").b64decode(written.encode("ascii")) == p.read_bytes()


def test_local_custom_service_names_reads_declared_service_names(tmp_path, monkeypatch):
    service_file = tmp_path / "CustomModule.py"
    service_file.write_text(
        "class CustomService:\n"
        "    name: str = 'CustomDeclaredName'\n",
        encoding="utf-8",
    )
    fallback_file = tmp_path / "FallbackModule.py"
    fallback_file.write_text("class FallbackService:\n    pass\n", encoding="utf-8")

    monkeypatch.setattr(backend, "_local_custom_service_files", lambda: [str(service_file), str(fallback_file)])

    assert backend._local_custom_service_names() == ["CustomDeclaredName", "FallbackModule"]


def test_candidate_remote_python_interpreters_include_nested_core_venv():
    candidates = backend._candidate_remote_python_interpreters({})

    assert "/opt/core/venv/python3.11/bin/python3" in candidates


def test_install_custom_services_configures_core_conf_when_missing_custom_dir(tmp_path, monkeypatch):
    p = tmp_path / "DockerDefaultRoute.py"
    p.write_text("# test\n", encoding="utf-8")
    monkeypatch.setattr(backend, "_local_custom_service_files", lambda: [str(p)])

    client = _FakeSSHClient(core_conf_exists_without_custom=True)
    meta = backend._install_custom_services_to_core_vm(
        client,
        sudo_password="pw",
        logger=types.SimpleNamespace(info=lambda *_a, **_k: None, warning=lambda *_a, **_k: None),
    )

    assert meta.get("core_conf_custom_services_configured") is True
    assert "/opt/core/custom_services" in (meta.get("core_conf_custom_services_dirs") or [])
    assert "/opt/core/custom_services" in (meta.get("services_dirs") or [])
    assert any("custom_services_dir = /opt/core/custom_services" in cmd for cmd in client.commands)
    assert any(("install -m 0644" in cmd and "/opt/core/custom_services" in cmd) for cmd in client.commands)


def test_install_custom_services_requires_sudo_password(tmp_path, monkeypatch):
    p = tmp_path / "TrafficService.py"
    p.write_text("# test\n")
    monkeypatch.setattr(backend, "_local_custom_service_files", lambda: [str(p)])

    client = _FakeSSHClient()
    with pytest.raises(RuntimeError) as exc:
        backend._install_custom_services_to_core_vm(
            client,
            sudo_password=None,
            logger=types.SimpleNamespace(info=lambda *_a, **_k: None),
        )
    assert "requires sudo" in str(exc.value).lower()


def test_install_custom_services_includes_core_conf_custom_dir(tmp_path, monkeypatch):
    p = tmp_path / "DockerDefaultRoute.py"
    p.write_text("# test\n")
    monkeypatch.setattr(backend, "_local_custom_service_files", lambda: [str(p)])

    custom_dir = "/home/core/.coregui/custom_services"
    client = _FakeSSHClient(core_conf_custom_dir=custom_dir)
    meta = backend._install_custom_services_to_core_vm(
        client,
        sudo_password="pw",
        logger=types.SimpleNamespace(info=lambda *_a, **_k: None, debug=lambda *_a, **_k: None),
    )

    assert custom_dir in (meta.get("services_dirs") or [])
    assert meta.get("core_conf_path") == "/opt/core/etc/core.conf"
    assert "/opt/core/etc/core.conf" not in (meta.get("services_dirs") or [])
    assert meta.get("core_conf_readable") is True
    assert custom_dir in (meta.get("core_conf_custom_services_dirs") or [])
    assert any("custom_services" in str(x) for x in (meta.get("core_conf_custom_services_lines") or []))
    assert any(("install -m 0644" in cmd and custom_dir in cmd) for cmd in client.commands)


def test_install_custom_services_includes_all_core_conf_custom_dirs(tmp_path, monkeypatch):
    p = tmp_path / "DockerDefaultRoute.py"
    p.write_text("# test\n")
    monkeypatch.setattr(backend, "_local_custom_service_files", lambda: [str(p)])

    d1 = "/home/core/.coregui/custom_services"
    d2 = "/opt/core/custom_services"
    lines = [f"custom_services = {d1}, {d2}"]
    client = _FakeSSHClient(core_conf_custom_lines=lines)

    meta = backend._install_custom_services_to_core_vm(
        client,
        sudo_password="pw",
        logger=types.SimpleNamespace(info=lambda *_a, **_k: None, debug=lambda *_a, **_k: None),
    )

    targets = set(meta.get("services_dirs") or [])
    assert d1 in targets
    assert d2 in targets
    assert "/opt/core/etc/core.conf" not in targets
    assert meta.get("core_conf_path") == "/opt/core/etc/core.conf"
    assert meta.get("core_conf_readable") is True
    lines_out = meta.get("core_conf_custom_services_lines") or []
    assert any("custom_services" in str(x) for x in lines_out)
    assert any(("install -m 0644" in cmd and d1 in cmd) for cmd in client.commands)
    assert any(("install -m 0644" in cmd and d2 in cmd) for cmd in client.commands)


def test_install_custom_services_ignores_core_conf_file_value(tmp_path, monkeypatch):
    p = tmp_path / "DockerDefaultRoute.py"
    p.write_text("# test\n")
    monkeypatch.setattr(backend, "_local_custom_service_files", lambda: [str(p)])

    bad_value = "/opt/core/etc/core.conf"
    d1 = "/home/core/.coregui/custom_services"
    lines = [f"custom_services = {bad_value}, {d1}"]
    client = _FakeSSHClient(core_conf_custom_lines=lines)

    meta = backend._install_custom_services_to_core_vm(
        client,
        sudo_password="pw",
        logger=types.SimpleNamespace(info=lambda *_a, **_k: None, debug=lambda *_a, **_k: None),
    )

    targets = set(meta.get("services_dirs") or [])
    assert d1 in targets
    assert bad_value not in targets
    assert not any(("install -m 0644" in cmd and bad_value in cmd) for cmd in client.commands)


def test_required_builtin_core_services_for_xml_input_uses_selected_scenario(tmp_path):
        xml_path = tmp_path / "scenario.xml"
        xml_path.write_text(
                """
<Scenarios>
    <Scenario name="Scenario One">
        <ScenarioEditor>
            <section name="Services" density="1.0">
                <item selected="SSH" factor="1.0" />
            </section>
        </ScenarioEditor>
    </Scenario>
    <Scenario name="Scenario Two">
        <ScenarioEditor>
            <section name="Services" density="1.0">
                <item selected="HTTP" factor="1.0" />
            </section>
        </ScenarioEditor>
    </Scenario>
</Scenarios>
""".strip(),
                encoding="utf-8",
        )

        required = backend._required_builtin_core_services_for_xml_input(
                str(xml_path),
                None,
                scenario_name="Scenario Two",
        )

        assert required == {"HTTP"}


def test_required_builtin_core_services_for_xml_input_expands_random_service_from_session_xml():
    session_xml = """
<Scenarios>
    <Scenario name="Scenario Random">
        <ScenarioEditor>
            <section name="Services" density="1.0">
                <item selected="Random" factor="1.0" />
            </section>
        </ScenarioEditor>
    </Scenario>
</Scenarios>
""".strip()

    required = backend._required_builtin_core_services_for_xml_input(
        None,
        session_xml,
        scenario_name="Scenario Random",
    )

    assert required == {"SSH", "HTTP", "DHCPClient"}


def test_required_builtin_core_services_for_xml_input_ignores_zero_density_and_factor(tmp_path):
    xml_path = tmp_path / "scenario.xml"
    xml_path.write_text(
        """
<Scenarios>
    <Scenario name="Scenario Zero">
        <ScenarioEditor>
            <section name="Services" density="0.0">
                <item selected="HTTP" factor="1.0" />
                <item selected="SSH" factor="0.0" />
            </section>
        </ScenarioEditor>
    </Scenario>
</Scenarios>
""".strip(),
        encoding="utf-8",
    )

    required = backend._required_builtin_core_services_for_xml_input(
        str(xml_path),
        None,
        scenario_name="Scenario Zero",
    )

    assert required == set()
