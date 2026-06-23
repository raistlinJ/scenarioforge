import json
import os
import re
import sys
import types
from types import SimpleNamespace

from scenarioforge.builders.topology import _apply_docker_compose_meta, _docker_ifid_start, _docker_node_add_node_kwargs, NodeType
from scenarioforge.utils.vuln_process import prepare_compose_for_assignments


class DummySession:
    def __init__(self):
        self.calls = []

    def edit_node(self, node_id, options=None, **kwargs):
        self.calls.append((node_id, options, kwargs))


def test_docker_ifid_start_defaults_to_core_eth0(monkeypatch):
    monkeypatch.delenv("CORETG_DOCKER_IFID_START", raising=False)

    assert _docker_ifid_start() == 0


def test_docker_ifid_start_allows_explicit_eth1_override(monkeypatch):
    monkeypatch.setenv("CORETG_DOCKER_IFID_START", "1")

    assert _docker_ifid_start() == 1


def test_prepare_compose_for_assignments_records_compose_path(tmp_path, monkeypatch):
    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        """
version: '3'
services:
  app:
    image: nginx:latest
    ports:
      - "8080:80"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    record = {"Type": "docker-compose", "Name": "Example", "Path": str(compose_src)}
    name_to_vuln = {"host-1": record}

    monkeypatch.delenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", raising=False)

    created = prepare_compose_for_assignments(name_to_vuln, out_base=str(tmp_path))

    expected_path = os.path.join(str(tmp_path), "docker-compose-host-1.yml")
    assert expected_path in created
    assert record.get("compose_path") == expected_path

    # Validate iproute2 wrapper injection (best-effort; requires PyYAML)
    try:
        import yaml  # type: ignore
    except Exception:
        yaml = None  # type: ignore
    if yaml is not None:
        obj = yaml.safe_load(open(expected_path, encoding="utf-8"))
        svc = obj["services"]["app"]
        node_svc = obj["services"]["host-1"]

        # Option B: no Docker-managed networking, so no docker eth0/default route.
        assert svc.get("network_mode") == "none"
        assert str(svc.get("user") or "") == "0:0"
        assert str(node_svc.get("user") or "") == "0:0"
        # With network_mode none we should not be publishing ports at all.
        assert "ports" not in svc
        # Preserve container-side port intent for reporting/metadata.
        assert "expose" in svc and "80" in [str(x) for x in (svc.get("expose") or [])]
        # Wrapped services now include an explicit working directory.
        assert isinstance(svc.get("working_dir"), str) and str(svc.get("working_dir") or "").strip()
        # Compose handed to CORE should NOT include `build:`; core-daemon would
        # attempt to build during scenario startup (and therefore pull packages/images).
        assert "build" not in svc
        assert "cap_add" in svc and "NET_ADMIN" in (svc["cap_add"] or [])
        assert "NET_RAW" in (svc["cap_add"] or [])
        labels = svc.get("labels") or {}
        assert isinstance(labels, dict)
        assert labels.get("coretg.wrapper_build_dockerfile") == "Dockerfile"
        wrap_dir = str(labels.get("coretg.wrapper_build_context") or "").strip()
        assert wrap_dir
        dockerfile = os.path.join(wrap_dir, "Dockerfile")
        assert os.path.exists(dockerfile)
        txt = open(dockerfile, encoding="utf-8").read()
        # Wrapper Dockerfile should ensure an `ip` command exists.
        # Default strategy is offline-safe (busybox injection), with legacy
        # package-manager installs available behind an env var.
        assert "ip" in txt
        assert (
            "busybox injection" in txt
            or "COPY --from=coretg_iptools" in txt
            or "apt-get install" in txt
            or "apk add" in txt
            or "yum install" in txt
            or "dnf install" in txt
        )
        assert "USER 0" in txt
        assert "USER root" not in txt
        assert "WORKDIR /" not in txt
        assert "ln -sfn /defaultroute.sh" in txt
        assert "ln -sfn /runtraffic.sh" in txt


def test_apply_docker_compose_meta_pushes_options(tmp_path):
    record = {"Name": "Example Vuln", "compose_path": str(tmp_path / "docker-compose-host-1.yml")}
    node = SimpleNamespace(id=5, name="host-1", options=None, type=NodeType.DOCKER, image="pre-image")
    session = DummySession()

    _apply_docker_compose_meta(node, record, session=session)

    assert getattr(node, "compose") == record["compose_path"]
    assert session.calls, "session.edit_node should be called"
    node_id, options, _ = session.calls[0]
    assert node_id == node.id
    assert getattr(options, "compose") == record["compose_path"]
    assert getattr(node, "options").compose == record["compose_path"]
    assert getattr(node, "type") == NodeType.DOCKER
    assert getattr(node, "image") == ""
    assert getattr(options, "type") == ""
    assert getattr(options, "image") == ""


def test_prepare_compose_wrapper_packages_strategy_keeps_service_script_symlinks(tmp_path, monkeypatch):
    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        """
version: '3'
services:
  app:
    image: nginx:latest
""".strip()
        + "\n",
        encoding="utf-8",
    )

    record = {"Type": "docker-compose", "Name": "Example", "Path": str(compose_src)}
    monkeypatch.setenv("CORETG_IPROUTE2_WRAPPER_STRATEGY", "packages")

    created = prepare_compose_for_assignments({"host-2": record}, out_base=str(tmp_path))
    assert created

    try:
        import yaml  # type: ignore
    except Exception:
        return

    out_path = tmp_path / "docker-compose-host-2.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    svc = (obj or {}).get("services", {}).get("app") or {}
    labels = svc.get("labels") or {}
    wrap_dir = str(labels.get("coretg.wrapper_build_context") or "").strip()
    assert wrap_dir
    dockerfile = os.path.join(wrap_dir, "Dockerfile")
    assert os.path.exists(dockerfile)
    txt = open(dockerfile, encoding="utf-8").read()

    assert "USER 0" in txt
    assert "USER root" not in txt
    assert "WORKDIR /" not in txt
    assert "ln -sfn /defaultroute.sh" in txt
    assert "ln -sfn /runtraffic.sh" in txt
    assert "http://archive.debian.org/debian buster main" in txt
    assert "http://archive.debian.org/debian-security buster/updates main" in txt
    assert "http://archive.debian.org/debian stretch-updates main" not in txt


def test_prepare_compose_docker34_name_keeps_service_script_symlinks(tmp_path, monkeypatch):
    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        """
version: '3'
services:
  app:
    image: nginx:latest
""".strip()
        + "\n",
        encoding="utf-8",
    )

    record = {"Type": "docker-compose", "Name": "Example", "Path": str(compose_src)}
    monkeypatch.delenv("CORETG_IPROUTE2_WRAPPER_STRATEGY", raising=False)

    created = prepare_compose_for_assignments({"docker-34": record}, out_base=str(tmp_path))
    assert created
    assert str(tmp_path / "docker-compose-docker-34.yml") in created

    try:
        import yaml  # type: ignore
    except Exception:
        return

    out_path = tmp_path / "docker-compose-docker-34.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    svc = (obj or {}).get("services", {}).get("app") or {}
    labels = svc.get("labels") or {}
    wrap_dir = str(labels.get("coretg.wrapper_build_context") or "").strip()
    assert wrap_dir
    dockerfile = os.path.join(wrap_dir, "Dockerfile")
    assert os.path.exists(dockerfile)
    txt = open(dockerfile, encoding="utf-8").read()

    assert "ln -sfn /defaultroute.sh" in txt
    assert "ln -sfn /runtraffic.sh" in txt


def test_prepare_compose_repairs_known_bad_craftcms_image_tag(tmp_path):
    compose_src = tmp_path / "docker-compose.yml"
    compose_src.write_text(
        """
services:
  web:
    image: vulhub/craftcms:5.6.16
  db:
    image: mysql:8.4
""".strip()
        + "\n",
        encoding="utf-8",
    )

    record = {
        "Type": "docker-compose",
        "Name": "craftcms/CVE-2025-32432",
        "Path": str(compose_src),
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    try:
        import yaml  # type: ignore
    except Exception:
        return

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    web = (obj or {}).get("services", {}).get("web") or {}
    labels = web.get("labels") or {}

    assert web.get("image") == "coretg/scenario-docker-1:iproute2"
    assert labels.get("coretg.wrapper_base_image") == "vulhub/craftcms:5.5.1.1"


def test_prepare_compose_bypasses_wrapper_for_ingress_nginx_when_image_already_has_ip(tmp_path):
    compose_src = tmp_path / "docker-compose.yml"
    compose_src.write_text(
        """
services:
  k3s:
    image: vulhub/ingress-nginx:1.9.5
    privileged: true
""".strip()
        + "\n",
        encoding="utf-8",
    )

    record = {
        "Type": "docker-compose",
        "Name": "ingress-nginx/CVE-2025-1974",
        "Path": str(compose_src),
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    try:
        import yaml  # type: ignore
    except Exception:
        return

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services", {}) or {}
    svc = services.get("docker-1") or services.get("k3s") or {}
    labels = svc.get("labels") or {}

    assert svc.get("image") == "vulhub/ingress-nginx:1.9.5"
    assert labels.get("coretg.wrapper_bypassed_image") == "vulhub/ingress-nginx:1.9.5"
    assert "already provides ip tooling" in str(labels.get("coretg.wrapper_bypassed_reason") or "")
    assert "coretg.wrapper_build_context" not in labels
    assert "build" not in svc
    assert "NET_ADMIN" in (svc.get("cap_add") or [])
    assert "NET_RAW" in (svc.get("cap_add") or [])
    assert str(svc.get("user") or "") == "0:0"
    assert svc.get("working_dir") == "/"


def test_prepare_compose_overrides_image_or_compose_non_root_user_for_core(tmp_path, monkeypatch):
    compose_src = tmp_path / "docker-compose.yml"
    compose_src.write_text(
        """
services:
  app:
    image: example/nonroot:latest
    user: "1000:1000"
""".strip()
        + "\n",
        encoding="utf-8",
    )

    record = {
        "Type": "docker-compose",
        "Name": "Non-root example",
        "Path": str(compose_src),
        "SkipIproute2Wrapper": "true",
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    try:
        import yaml  # type: ignore
    except Exception:
        return

    obj = yaml.safe_load((tmp_path / "docker-compose-docker-1.yml").read_text("utf-8"))
    services = (obj or {}).get("services") or {}

    assert str((services.get("app") or {}).get("user") or "") == "0:0"
    assert str((services.get("docker-1") or {}).get("user") or "") == "0:0"


def test_prepare_compose_repairs_known_bad_aiohttp_image_to_local_build_context(tmp_path):
    compose_dir = tmp_path / "python" / "CVE-2024-23334"
    compose_dir.mkdir(parents=True)
    compose_src = compose_dir / "docker-compose.yml"
    compose_src.write_text(
        """
services:
  aiohttp-app:
    image: vulhub/aiohttp:3.9.1
""".strip()
        + "\n",
        encoding="utf-8",
    )

    local_ctx = tmp_path / "base" / "python" / "aiohttp" / "3.9.1"
    local_ctx.mkdir(parents=True)
    (local_ctx / "Dockerfile").write_text(
        """
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt aiohttpServer.py /app/
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "aiohttpServer.py"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (local_ctx / "requirements.txt").write_text("aiohttp==3.9.1\n", encoding="utf-8")
    (local_ctx / "aiohttpServer.py").write_text("print('ok')\n", encoding="utf-8")

    record = {
        "Type": "docker-compose",
        "Name": "python/CVE-2024-23334",
        "Path": str(compose_src),
    }

    out_base = tmp_path / "out"
    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(out_base))
    assert created

    try:
        import yaml  # type: ignore
    except Exception:
        return

    out_path = out_base / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    app = (obj or {}).get("services", {}).get("aiohttp-app") or {}
    labels = app.get("labels") or {}
    build = app.get("build") or {}
    build_context = build.get("context") if isinstance(build, dict) else None

    assert "image" not in app
    assert isinstance(build_context, str) and build_context
    assert os.path.exists(os.path.join(build_context, "Dockerfile"))
    assert labels.get("coretg.repaired_catalog_image") == "vulhub/aiohttp:3.9.1"
    dockerfile_text = open(os.path.join(build_context, "Dockerfile"), encoding="utf-8").read()
    assert "FROM python:3.11-slim" in dockerfile_text
    assert "iproute2" in dockerfile_text


def test_prepare_compose_repairs_known_bad_aiohttp_image_from_repo_root_when_compose_relocated(tmp_path, monkeypatch):
    compose_dir = tmp_path / "runs" / "run-123"
    compose_dir.mkdir(parents=True)
    compose_src = compose_dir / "docker-compose.yml"
    compose_src.write_text(
        """
services:
  aiohttp-app:
    image: vulhub/aiohttp:3.9.1
""".strip()
        + "\n",
        encoding="utf-8",
    )

    repo_ctx = tmp_path / "repo" / "base" / "python" / "aiohttp" / "3.9.1"
    repo_ctx.mkdir(parents=True)
    (repo_ctx / "Dockerfile").write_text(
        """
FROM python:3.11-slim
WORKDIR /app
COPY requirements.txt aiohttpServer.py /app/
RUN pip install --no-cache-dir -r requirements.txt
CMD ["python", "aiohttpServer.py"]
""".strip()
        + "\n",
        encoding="utf-8",
    )
    (repo_ctx / "requirements.txt").write_text("aiohttp==3.9.1\n", encoding="utf-8")
    (repo_ctx / "aiohttpServer.py").write_text("print('ok')\n", encoding="utf-8")

    monkeypatch.setenv("CORETG_REPO_ROOT", str(tmp_path))

    record = {
        "Type": "docker-compose",
        "Name": "python/CVE-2024-23334",
        "Path": str(compose_src),
    }

    out_base = tmp_path / "out"
    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(out_base))
    assert created

    try:
        import yaml  # type: ignore
    except Exception:
        return

    out_path = out_base / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    app = (obj or {}).get("services", {}).get("aiohttp-app") or {}
    labels = app.get("labels") or {}
    build = app.get("build") or {}
    build_context = build.get("context") if isinstance(build, dict) else None

    assert "image" not in app
    assert isinstance(build_context, str) and build_context
    assert labels.get("coretg.repaired_catalog_image") == "vulhub/aiohttp:3.9.1"
    assert os.path.exists(os.path.join(build_context, "Dockerfile"))
    dockerfile_text = open(os.path.join(build_context, "Dockerfile"), encoding="utf-8").read()
    assert "FROM python:3.11-slim" in dockerfile_text
    assert "iproute2" in dockerfile_text


def test_prepare_compose_repairs_struts_s2016_to_local_build_context(tmp_path, monkeypatch):
        compose_dir = tmp_path / "runs" / "run-123"
        compose_dir.mkdir(parents=True)
        compose_src = compose_dir / "docker-compose.yml"
        compose_src.write_text(
                """
services:
    struts2:
        build: .
""".strip()
                + "\n",
                encoding="utf-8",
        )

        repo_ctx = tmp_path / "repo" / "base" / "struts2" / "2.3.28"
        repo_ctx.mkdir(parents=True)
        (repo_ctx / "Dockerfile").write_text(
                """
FROM maven:3-jdk-8
COPY ./ /usr/src/
WORKDIR /usr/src
RUN mvn compile jetty:help
CMD ["mvn", "jetty:run"]
""".strip()
                + "\n",
                encoding="utf-8",
        )
        (repo_ctx / "pom.xml").write_text(
                """
<project>
    <dependencies>
        <dependency>
            <groupId>org.apache.struts</groupId>
            <artifactId>struts2-core</artifactId>
            <version>2.3.28</version>
        </dependency>
    </dependencies>
</project>
""".strip()
                + "\n",
                encoding="utf-8",
        )

        monkeypatch.setenv("CORETG_REPO_ROOT", str(tmp_path))

        record = {
                "Type": "docker-compose",
                "Name": "struts2/s2-016",
                "Path": str(compose_src),
        }

        out_base = tmp_path / "out"
        created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(out_base))
        assert created

        try:
                import yaml  # type: ignore
        except Exception:
                return

        out_path = out_base / "docker-compose-docker-1.yml"
        obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
        app = (obj or {}).get("services", {}).get("struts2") or {}
        labels = app.get("labels") or {}
        build = app.get("build") or {}
        build_context = build.get("context") if isinstance(build, dict) else None

        assert isinstance(build_context, str) and build_context
        assert os.path.exists(os.path.join(build_context, "Dockerfile"))
        assert labels.get("coretg.repaired_catalog_template") == "repo/base/struts2/2.3.28"
        assert labels.get("coretg.repaired_catalog_dependency_version") == "2.3.15"

        pom_text = open(os.path.join(build_context, "pom.xml"), encoding="utf-8").read()
        assert "<version>2.3.15</version>" in pom_text
        assert "<version>2.3.28</version>" not in pom_text


def test_prepare_compose_preserves_multiline_command_backslashes_for_rocketchat(tmp_path):
        compose_src = tmp_path / "docker-compose.yml"
        compose_src.write_text(
                """
version: '2'
services:
    rocketchat:
        image: vulhub/rocketchat:3.12.1
    mongo:
        image: mongo:4.0
    mongo-init-replica:
        image: mongo:4.0
        command: >
            bash -c
                "for i in `seq 1 30`; do
                    mongo mongo/rocketchat --eval \"
                        rs.initiate({
                            _id: 'rs0',
                            members: [ { _id: 0, host: 'localhost:27017' } ]})\" &&
                    s=$$? && break || s=$$?;
                    echo \"Tried $$i times. Waiting 5 secs...\";
                    sleep 5;
                done; (exit $$s)"
""".strip()
                + "\n",
                encoding="utf-8",
        )

        record = {
                "Type": "docker-compose",
                "Name": "rocketchat/CVE-2021-22911",
                "Path": str(compose_src),
        }

        created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
        assert created

        out_path = tmp_path / "docker-compose-docker-1.yml"
        raw_text = out_path.read_text("utf-8", errors="ignore")

        try:
                import yaml  # type: ignore
        except Exception:
                return

        obj = yaml.safe_load(raw_text)
        mongo_init = (obj or {}).get("services", {}).get("mongo-init-replica") or {}
        command = str(mongo_init.get("command") or "")
        command_line = next(line for line in raw_text.splitlines() if "mongo mongo/rocketchat --eval" in line)
        echo_line = next(line for line in raw_text.splitlines() if "Tried $$i times. Waiting 5 secs..." in line)

        assert "mongo mongo/rocketchat --eval" in command_line
        assert '\\\\"' not in command_line
        assert '\\\\"' not in echo_line
        assert "Tried $$i times. Waiting 5 secs..." in echo_line
        assert '--eval "' in command or '--eval \\"' in command


def test_prepare_compose_build_only_marks_declared_entrypoint_scripts_executable(tmp_path):
    compose_src = tmp_path / "docker-compose.yml"
    compose_src.write_text(
        """
services:
  docker:
    build: .
""".strip()
        + "\n",
        encoding="utf-8",
    )

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        """
FROM alpine:3.19
COPY docker-entrypoint.sh /
ENTRYPOINT [ "/docker-entrypoint.sh" ]
""".strip()
        + "\n",
        encoding="utf-8",
    )

    entrypoint = tmp_path / "docker-entrypoint.sh"
    entrypoint.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    entrypoint.chmod(0o644)

    record = {
        "Type": "docker-compose",
        "Name": "docker/unauthorized-rce",
        "Path": str(compose_src),
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    try:
        import yaml  # type: ignore
    except Exception:
        return

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    docker_svc = services.get("docker") or {}
    build = docker_svc.get("build") or {}
    build_context = build.get("context") if isinstance(build, dict) else None
    assert isinstance(build_context, str) and build_context

    copied_dockerfile = os.path.join(build_context, "Dockerfile")
    txt = open(copied_dockerfile, encoding="utf-8").read()

    assert "USER 0" in txt
    assert "USER root" not in txt
    assert "chmod 0755 /docker-entrypoint.sh" in txt
    assert "iproute2" in txt
    assert txt.index("chmod 0755 /docker-entrypoint.sh") < txt.index("if command -v ip >/dev/null 2>&1; then exit 0; fi;")


def test_prepare_compose_build_only_includes_buster_archive_fallback(tmp_path):
    compose_src = tmp_path / "docker-compose.yml"
    compose_src.write_text(
        "services:\n  app:\n    build: .\n",
        encoding="utf-8",
    )

    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text(
        "FROM debian:buster\nRUN echo ok >/tmp/ok\n",
        encoding="utf-8",
    )

    record = {
        "Type": "docker-compose",
        "Name": "httpd/CVE-2021-40438",
        "Path": str(compose_src),
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    try:
        import yaml  # type: ignore
    except Exception:
        return

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    app = services.get("app") or {}
    build = app.get("build") or {}
    build_context = build.get("context") if isinstance(build, dict) else None
    assert isinstance(build_context, str) and build_context

    copied_dockerfile = os.path.join(build_context, "Dockerfile")
    txt = open(copied_dockerfile, encoding="utf-8").read()

    assert "if ! apt-get $APT_OPTS update" in txt
    assert "http://archive.debian.org/debian buster main" in txt
    assert "http://archive.debian.org/debian buster-updates main" in txt
    assert "http://archive.debian.org/debian-security buster/updates main" in txt
    assert "http://archive.debian.org/debian stretch-updates main" not in txt
    assert "Acquire::Check-Valid-Until=false" in txt


def test_apply_docker_compose_meta_uses_real_service_name(tmp_path):
    compose_path = tmp_path / "docker-compose-host-1.yml"
    compose_path.write_text(
            """
services:
    app:
        image: nginx:latest
""".strip()
            + "\n",
            encoding="utf-8",
    )

    record = {"Name": "standard-ubuntu-docker-core", "compose_path": str(compose_path)}
    node = SimpleNamespace(id=6, name="host-1", options=None, type=NodeType.DOCKER, image="")
    session = DummySession()

    _apply_docker_compose_meta(node, record, session=session)

    assert getattr(node, "compose_name") == "app"
    assert session.calls, "session.edit_node should be called"
    node_id, options, _ = session.calls[0]
    assert node_id == node.id
    assert getattr(options, "compose_name") == "app"


def test_apply_docker_compose_meta_falls_back_when_service_invalid(tmp_path):
    compose_path = tmp_path / "docker-compose-host-1.yml"
    compose_path.write_text(
            """
services:
    web:
        image: nginx:latest
""".strip()
            + "\n",
            encoding="utf-8",
    )

    record = {
        "Name": "standard-ubuntu-docker-core",
        "compose_path": str(compose_path),
        "compose_service": "standard-ubuntu-docker-core",
    }
    node = SimpleNamespace(id=7, name="host-1", options=None, type=NodeType.DOCKER, image="")
    session = DummySession()

    _apply_docker_compose_meta(node, record, session=session)

    assert getattr(node, "compose_name") == "web"
    assert session.calls, "session.edit_node should be called"
    node_id, options, _ = session.calls[0]
    assert node_id == node.id
    assert getattr(options, "compose_name") == "web"


def test_apply_docker_compose_meta_keeps_requested_service_when_compose_unreadable(tmp_path):
    compose_path = tmp_path / "docker-compose-host-1.yml"
    compose_path.write_text("services:\n  web: [\n", encoding="utf-8")

    record = {
        "Name": "standard-ubuntu-docker-core",
        "compose_path": str(compose_path),
        "compose_service": "standard-ubuntu-docker-core",
    }
    node = SimpleNamespace(id=8, name="host-1", options=None, type=NodeType.DOCKER, image="")
    session = DummySession()

    _apply_docker_compose_meta(node, record, session=session)

    assert getattr(node, "compose_name", None) == "standard-ubuntu-docker-core"
    assert session.calls, "session.edit_node should be called"
    _node_id, options, _ = session.calls[0]
    assert getattr(options, "compose_name", None) == "standard-ubuntu-docker-core"


def test_apply_docker_compose_meta_falls_back_to_node_name_without_requested_service(tmp_path):
    compose_path = tmp_path / "docker-compose-host-1.yml"
    compose_path.write_text("services:\n  web: [\n", encoding="utf-8")

    record = {
        "Name": "standard-ubuntu-docker-core",
        "compose_path": str(compose_path),
    }
    node = SimpleNamespace(id=9, name="host-1", options=None, type=NodeType.DOCKER, image="")
    session = DummySession()

    _apply_docker_compose_meta(node, record, session=session)

    assert getattr(node, "compose_name", None) == "host-1"
    assert session.calls, "session.edit_node should be called"
    _node_id, options, _ = session.calls[0]
    assert getattr(options, "compose_name", None) == "host-1"


def test_docker_node_add_node_kwargs_falls_back_to_node_name_when_compose_unreadable(tmp_path):
    compose_path = tmp_path / "docker-compose-host-9.yml"
    compose_path.write_text("services:\n  web: [\n", encoding="utf-8")

    kwargs = _docker_node_add_node_kwargs(
        "host-9",
        {
            "Name": "Example",
            "compose_path": str(compose_path),
            "compose_service": "web",
        },
    )

    assert kwargs.get("compose") == "/tmp/vulns/docker-compose-host-9.yml"
    assert kwargs.get("compose_name") == "host-9"
    options = kwargs.get("options")
    assert getattr(options, "compose_name", None) == "host-9"


def test_docker_node_add_node_kwargs_prefers_real_core_options_object_when_available(monkeypatch):
    class FakeDockerOptions:
        pass

    class FakeDockerNode:
        @classmethod
        def create_options(cls):
            return FakeDockerOptions()

    fake_core = types.ModuleType("core")
    fake_nodes = types.ModuleType("core.nodes")
    fake_docker = types.ModuleType("core.nodes.docker")
    fake_docker.DockerNode = FakeDockerNode
    fake_docker.DockerOptions = FakeDockerOptions
    fake_nodes.docker = fake_docker
    fake_core.nodes = fake_nodes

    monkeypatch.setitem(sys.modules, "core", fake_core)
    monkeypatch.setitem(sys.modules, "core.nodes", fake_nodes)
    monkeypatch.setitem(sys.modules, "core.nodes.docker", fake_docker)

    kwargs = _docker_node_add_node_kwargs("host-10", {"Name": "Example"})

    options = kwargs.get("options")
    assert isinstance(options, FakeDockerOptions)
    assert getattr(options, "compose", None) == "/tmp/vulns/docker-compose-host-10.yml"
    assert getattr(options, "compose_name", None) == "host-10"
    assert getattr(options, "image", None) == ""
    assert getattr(options, "type", None) == ""


def test_apply_docker_compose_meta_prefers_real_core_options_object_when_available(tmp_path, monkeypatch):
    class FakeDockerOptions:
        pass

    class FakeDockerNode:
        @classmethod
        def create_options(cls):
            return FakeDockerOptions()

    fake_core = types.ModuleType("core")
    fake_nodes = types.ModuleType("core.nodes")
    fake_docker = types.ModuleType("core.nodes.docker")
    fake_docker.DockerNode = FakeDockerNode
    fake_docker.DockerOptions = FakeDockerOptions
    fake_nodes.docker = fake_docker
    fake_core.nodes = fake_nodes

    monkeypatch.setitem(sys.modules, "core", fake_core)
    monkeypatch.setitem(sys.modules, "core.nodes", fake_nodes)
    monkeypatch.setitem(sys.modules, "core.nodes.docker", fake_docker)

    compose_path = tmp_path / "docker-compose-host-11.yml"
    compose_path.write_text("services:\n  host-11:\n    image: nginx:latest\n", encoding="utf-8")

    record = {"Name": "Example", "compose_path": str(compose_path)}
    node = SimpleNamespace(id=11, name="host-11", options=None, type=NodeType.DOCKER, image="")
    session = DummySession()

    _apply_docker_compose_meta(node, record, session=session)

    assert session.calls, "session.edit_node should be called"
    _node_id, options, _ = session.calls[0]
    assert isinstance(options, FakeDockerOptions)
    assert getattr(options, "compose", None) == "/tmp/vulns/docker-compose-host-11.yml"
    assert getattr(options, "compose_name", None) == "host-11"


def test_prepare_compose_escapes_mako_shell_vars(tmp_path):
        compose_src = tmp_path / "base-compose-airflow.yml"
        compose_src.write_text(
                """
version: '3'
services:
    app:
        image: apache/airflow:2.9.0
        environment:
            - AIRFLOW_UID=${AIRFLOW_UID:-50000}
                healthcheck:
                    test: ["CMD-SHELL", "echo $${HOSTNAME}"]
""".strip()
                + "\n",
                encoding="utf-8",
        )

        record = {"Type": "docker-compose", "Name": "Airflow", "Path": str(compose_src)}
        name_to_vuln = {"docker-3": record}
        created = prepare_compose_for_assignments(name_to_vuln, out_base=str(tmp_path))

        out_path = os.path.join(str(tmp_path), "docker-compose-docker-3.yml")
        assert out_path in created
        text = open(out_path, encoding="utf-8").read()

        # `${VAR:-default}` interpolation is resolved to a plain literal so docker-compose
        # (and CORE's Mako templating) can both process the generated compose.
        assert 'AIRFLOW_UID=50000' in text
        assert '${' not in text
        assert '$${HOSTNAME}' not in text
        assert '$HOSTNAME' in text
        assert "\\${AIRFLOW_UID:-50000}" not in text
        assert "$${AIRFLOW_UID:-50000}" not in text
        assert re.search(r"(?<![\"'])\$\{AIRFLOW_UID:-50000\}(?![\"'])", text) is None
        # Wrapper form should not be present after literal resolution.
        assert re.search(r"\$\{\s*[\"']\$\{AIRFLOW_UID:-50000\}[\"']\s*\}", text) is None


def test_prepare_compose_normalizes_bare_environment_entries_for_core(tmp_path, monkeypatch):
        compose_src = tmp_path / "base-compose-env.yml"
        compose_src.write_text(
                """
version: '3'
services:
    app:
        image: nginx:latest
        environment:
            - DISPLAY
            - SSH_AUTH_SOCK
            - LANG=C.UTF-8
""".strip()
                + "\n",
                encoding="utf-8",
        )

        monkeypatch.setenv("DISPLAY", ":99")
        monkeypatch.delenv("SSH_AUTH_SOCK", raising=False)

        record = {"Type": "docker-compose", "Name": "EnvApp", "Path": str(compose_src)}
        created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))

        out_path = os.path.join(str(tmp_path), "docker-compose-docker-1.yml")
        assert out_path in created
        text = open(out_path, encoding="utf-8").read()

        assert "DISPLAY=:99" in text
        assert "SSH_AUTH_SOCK=" in text
        assert "LANG=C.UTF-8" in text
        assert re.search(r"^\s*-\s*DISPLAY\s*$", text, flags=re.MULTILINE) is None
        assert re.search(r"^\s*-\s*SSH_AUTH_SOCK\s*$", text, flags=re.MULTILINE) is None


def test_prepare_compose_local_template_dot_bind_isolation(tmp_path):
    """Regression: isolating local templates must not recurse copying base_dir into base_dir/node-*.

    This pattern happens with node-generator outputs like:
      volumes:
        - .:/exports
    """
    # Create a local compose that references '.' so it will be absolutized and then isolated.
    src_dir = tmp_path / "local"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "payload.txt").write_text("hello\n", encoding="utf-8")
    compose_src = src_dir / "docker-compose.yml"
    compose_src.write_text(
        (
            "services:\n"
            "  node:\n"
            "    image: alpine:3.19\n"
            "    command: ['sh','-lc','sleep 2']\n"
            "    volumes:\n"
            "      - .:/exports\n"
        ),
        encoding="utf-8",
    )

    record = {"Type": "docker-compose", "Name": "LocalDot", "Path": str(compose_src)}
    out_base = tmp_path / "out"
    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(out_base))
    out_path = out_base / "docker-compose-docker-1.yml"
    assert str(out_path) in created
    assert out_path.exists()

    # Ensure the rewritten compose refers to a bind source under the isolated node dir.
    try:
        import yaml  # type: ignore
    except Exception:
        yaml = None  # type: ignore
    if yaml is None:
        return

    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    svc = (obj.get("services") or {}).get("docker-1") or (obj.get("services") or {}).get("node")
    assert isinstance(svc, dict)
    vols = svc.get("volumes")
    assert isinstance(vols, list)
    # Should be absolute path bind, not '.'
    vol0 = str(vols[0])
    assert vol0.split(":", 1)[0].startswith(str(out_base)), vol0


def test_prepare_compose_replaces_stale_directory_at_file_bind_paths(tmp_path):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    src_dir = tmp_path / "apisix-src"
    src_dir.mkdir(parents=True, exist_ok=True)
    (src_dir / "config.yml").write_text("node_listen: 9080\n", encoding="utf-8")
    compose_src = src_dir / "docker-compose.yml"
    compose_src.write_text(
        (
            "services:\n"
            "  apisix:\n"
            "    image: vulhub/apisix:2.11.0\n"
            "    volumes:\n"
            "      - ./config.yml:/usr/local/apisix/conf/config.yaml:ro\n"
        ),
        encoding="utf-8",
    )

    out_base = tmp_path / "out"
    base_dir = out_base / "apisix-cve-2020-13945"
    node_dir = base_dir / "node-docker-1"
    (base_dir / "config.yml").mkdir(parents=True, exist_ok=True)
    (node_dir / "config.yml").mkdir(parents=True, exist_ok=True)

    record = {"Type": "docker-compose", "Name": "apisix/CVE-2020-13945", "Path": str(compose_src)}
    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(out_base))

    out_path = out_base / "docker-compose-docker-1.yml"
    assert str(out_path) in created
    assert (base_dir / "config.yml").is_file()
    assert (node_dir / "config.yml").is_file()

    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    svc = (obj.get("services") or {}).get("docker-1") or (obj.get("services") or {}).get("apisix")
    assert isinstance(svc, dict)
    vols = svc.get("volumes") or []
    assert isinstance(vols, list)
    vol0 = str(vols[0])
    assert vol0.split(":", 1)[0] == str(node_dir / "config.yml")


def test_prepare_compose_prefers_local_path_over_cached(tmp_path):
    # Two different local compose sources but same Name (so same safe base_dir).
    src1 = tmp_path / "run1"
    src1.mkdir(parents=True, exist_ok=True)
    (src1 / "docker-compose.yml").write_text(
        "services:\n  app:\n    image: alpine:3.19\n    command: ['sh','-lc','echo one; sleep 1']\n",
        encoding="utf-8",
    )

    src2 = tmp_path / "run2"
    src2.mkdir(parents=True, exist_ok=True)
    (src2 / "docker-compose.yml").write_text(
        "services:\n  app:\n    image: alpine:3.19\n    command: ['sh','-lc','echo two; sleep 1']\n",
        encoding="utf-8",
    )

    out_base = tmp_path / "out"
    rec1 = {"Type": "docker-compose", "Name": "SameName", "Path": str((src1 / 'docker-compose.yml'))}
    rec2 = {"Type": "docker-compose", "Name": "SameName", "Path": str((src2 / 'docker-compose.yml'))}

    # First run creates base_dir cached compose.
    prepare_compose_for_assignments({"n1": rec1}, out_base=str(out_base))

    # Corrupt/overwrite the cached compose to something else to ensure we don't reuse it.
    safe_dir = out_base / "samename"
    safe_dir.mkdir(parents=True, exist_ok=True)
    (safe_dir / "docker-compose.yml").write_text(
        "services:\n  app:\n    image: alpine:3.19\n    command: ['sh','-lc','echo STALE; sleep 1']\n",
        encoding="utf-8",
    )

    created = prepare_compose_for_assignments({"n2": rec2}, out_base=str(out_base))
    out_path = out_base / "docker-compose-n2.yml"
    assert str(out_path) in created
    txt = out_path.read_text("utf-8", errors="ignore")
    assert "echo two" in txt
    assert "echo STALE" not in txt


def test_prepare_compose_inject_copy_uses_busybox_entrypoint_for_wrapper(tmp_path, monkeypatch):
    """Regression: inject_copy must work even if base image lacks /bin/sh/cp.

    When we wrap services into `coretg/*:iproute2`, the wrapper injects a BusyBox
    binary at /usr/local/coretg/bin/busybox. The inject_copy init service should
    use that BusyBox as entrypoint.
    """
    # Create a minimal compose.
    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        (
            "services:\n"
            "  app:\n"
            "    image: nginx:latest\n"
            "    command: ['sh','-lc','sleep 1']\n"
        ),
        encoding="utf-8",
    )

    # Prepare a fake artifacts dir with a file we will inject.
    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "flag.txt").write_text("FLAG{X}\n", encoding="utf-8")

    # Force wrapper strategy to busybox injection (default) and enable inject copy mode.
    monkeypatch.setenv("CORETG_INJECT_FILES_MODE", "copy")
    monkeypatch.setenv("CORETG_COMPOSE_SET_CONTAINER_NAME", "1")

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
        "InjectFiles": ["flag.txt -> /tmp"],
        "InjectSourceDir": str(artifacts),
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    try:
        import yaml  # type: ignore
    except Exception:
        return

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    assert "inject_copy" in services or any(str(k).startswith("inject_copy") for k in services.keys())
    # Find the inject_copy service key.
    ik = "inject_copy" if "inject_copy" in services else sorted([k for k in services.keys() if str(k).startswith("inject_copy")])[0]
    inject = services[ik]
    assert isinstance(inject, dict)
    # When the target service is wrapped, inject_copy should use BusyBox entrypoint.
    # We don't assert the exact wrapper tag here, just the entrypoint behavior.
    ep = inject.get("entrypoint")
    if ep is not None:
        # compose can represent entrypoint as list or string
        text = " ".join(ep) if isinstance(ep, list) else str(ep)
        assert "/usr/local/coretg/bin/busybox" in text


def test_prepare_compose_flow_injects_default_to_flow_injects_dir(tmp_path, monkeypatch):
    """Regression: flow inject specs without explicit dest should default to /flow_injects."""
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  app:\n    image: nginx:latest\n    command: ['sh','-lc','sleep 1']\n",
        encoding="utf-8",
    )

    # Emulate a Flow artifacts run directory structure.
    flow_root = tmp_path / "tmp" / "vulns" / "flag_generators_runs" / "flow-x" / "01_gen" / "artifacts"
    flow_root.mkdir(parents=True, exist_ok=True)
    (flow_root / "payload.bin").write_text("x\n", encoding="utf-8")
    # Also include an outputs.json so expansion sees a plausible artifact key.
    (flow_root / "outputs.json").write_text('{"outputs": {"File(path)": "payload.bin"}}\n', encoding="utf-8")

    monkeypatch.setenv("CORETG_INJECT_FILES_MODE", "copy")

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
        "ArtifactsDir": str(flow_root),
        "ArtifactsMountPath": "/flow_artifacts",
        # No explicit dest
        "InjectFiles": ["File(path)"],
        "InjectSourceDir": str(flow_root),
        "OutputsManifest": str(flow_root / "outputs.json"),
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created
    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    # Find inject_copy service and verify volumes include /flow_injects volume mount.
    ikeys = [k for k in services.keys() if str(k).startswith("inject_copy")]
    assert ikeys, "expected inject_copy service"
    # Target service should mount an inject volume at /flow_injects.
    target = services.get("docker-1") or services.get("app")
    assert isinstance(target, dict)
    vols = target.get("volumes") or []
    assert any(str(v).endswith(":/flow_injects") for v in vols), vols


def test_prepare_compose_ignores_legacy_tmp_flag_container_path(tmp_path, monkeypatch):
    """Regression: /tmp/flag.txt is an in-container fallback path, not a host source."""
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  app:\n    image: nginx:latest\n    command: ['sh','-lc','sleep 1']\n",
        encoding="utf-8",
    )

    flow_artifacts = tmp_path / "tmp" / "vulns" / "flag_generators_runs" / "flow-z" / "01_gen" / "artifacts"
    flow_artifacts.mkdir(parents=True, exist_ok=True)
    (flow_artifacts / "hint.txt").write_text("hint\n", encoding="utf-8")

    monkeypatch.setenv("CORETG_INJECT_FILES_MODE", "copy")

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
        "InjectFiles": ["/tmp/flag.txt", "hint.txt"],
        "InjectSourceDir": str(flow_artifacts),
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    target = services.get("docker-1") or services.get("app")
    assert isinstance(target, dict)

    labels = target.get("labels") or {}
    assert isinstance(labels, dict)
    raw_map = str(labels.get("coretg.inject.map") or "[]")
    inject_map = json.loads(raw_map)
    assert isinstance(inject_map, list)
    assert any(str(item.get("src") or "") == "hint.txt" for item in inject_map if isinstance(item, dict))


def test_prepare_compose_drops_missing_legacy_flag_fallback_when_flow_inject_exists(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  app:\n    image: nginx:latest\n    command: ['sh','-lc','sleep 1']\n",
        encoding="utf-8",
    )

    flow_artifacts = tmp_path / "tmp" / "vulns" / "flag_generators_runs" / "flow-z" / "02_gen" / "artifacts"
    flow_artifacts.mkdir(parents=True, exist_ok=True)
    (flow_artifacts / "secrets.txt").write_text("secret\n", encoding="utf-8")

    monkeypatch.setenv("CORETG_INJECT_FILES_MODE", "copy")

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
        "InjectFiles": ["secrets.txt -> /flow_injects", "flag.txt -> /tmp"],
        "InjectSourceDir": str(flow_artifacts),
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    target = services.get("docker-1") or services.get("app")
    assert isinstance(target, dict)

    labels = target.get("labels") or {}
    assert isinstance(labels, dict)
    raw_map = str(labels.get("coretg.inject.map") or "[]")
    inject_map = json.loads(raw_map)
    assert isinstance(inject_map, list)
    assert inject_map == [{"src": "secrets.txt", "dest": "/flow_injects"}]

    rendered = out_path.read_text("utf-8", errors="ignore")
    assert "flag.txt" not in rendered
    assert not any(str(item.get("src") or "") == "flag.txt" for item in inject_map if isinstance(item, dict))


def test_prepare_compose_vuln_text_auto_injects_flag(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  app:\n    image: nginx:latest\n    command: ['sh','-lc','sleep 1']\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("CORETG_INJECT_FILES_MODE", "copy")
    monkeypatch.setenv("CORETG_VULN_FLAG_TYPE", "text")

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "CoreTGVulnAssignment": "1",
        "FlagType": "text",
    }

    created = prepare_compose_for_assignments({"docker-5": record}, out_base=str(tmp_path))
    assert created

    host_flag = tmp_path / "flag_injects" / "docker-5" / "flag.txt"
    assert host_flag.exists(), "expected auto-generated host flag source"

    out_path = tmp_path / "docker-compose-docker-5.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    ikeys = [k for k in services.keys() if str(k).startswith("inject_copy")]
    assert ikeys, "expected inject_copy service"

    target = services.get("docker-5") or services.get("app")
    assert isinstance(target, dict)
    vols = target.get("volumes") or []
    assert any(str(v).endswith(":/tmp") for v in vols), vols


def test_prepare_compose_inject_copy_runtime_guard_nonfatal_by_default(tmp_path, monkeypatch):
    """Regression: inject_copy command should guard missing runtime sources by default."""
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  app:\n    image: nginx:latest\n    command: ['sh','-lc','sleep 1']\n",
        encoding="utf-8",
    )

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "present.txt").write_text("ok\n", encoding="utf-8")

    monkeypatch.setenv("CORETG_INJECT_FILES_MODE", "copy")
    monkeypatch.delenv("CORETG_INJECT_COPY_STRICT", raising=False)

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
        "InjectFiles": ["present.txt"],
        "InjectSourceDir": str(artifacts),
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created
    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    ikeys = [k for k in services.keys() if str(k).startswith("inject_copy")]
    assert ikeys, "expected inject_copy service"
    inject = services[ikeys[0]]
    assert isinstance(inject, dict)
    cmd = inject.get("command")
    cmd_text = " ".join(cmd) if isinstance(cmd, list) else str(cmd or "")
    assert "if [ -e" in cmd_text
    assert "missing /src/" in cmd_text
    assert "skipping" in cmd_text
    assert "exit 1" not in cmd_text


def test_prepare_compose_inject_copy_runs_as_root_for_volume_writes(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  app:\n    image: vulhub/weblogic:12.2.1.3-2018\n",
        encoding="utf-8",
    )

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "challenge.bin").write_text("ok\n", encoding="utf-8")

    monkeypatch.setenv("CORETG_INJECT_FILES_MODE", "copy")

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
        "InjectFiles": ["challenge.bin"],
        "InjectSourceDir": str(artifacts),
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created
    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    ikeys = [k for k in services.keys() if str(k).startswith("inject_copy")]
    assert ikeys, "expected inject_copy service"
    inject = services[ikeys[0]]
    assert isinstance(inject, dict)
    assert str(inject.get("user") or "") == "0:0"
    assert str(inject.get("image") or "") == "alpine:3.19"


def test_prepare_compose_inject_copy_can_reuse_target_image_by_opt_in(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  app:\n    image: vulhub/coldfusion:2018.0.15\n",
        encoding="utf-8",
    )

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "loader_diag.bin").write_text("ok\n", encoding="utf-8")

    monkeypatch.setenv("CORETG_INJECT_FILES_MODE", "copy")
    monkeypatch.setenv("CORETG_INJECT_COPY_REUSE_TARGET_IMAGE", "1")

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
        "InjectFiles": ["loader_diag.bin"],
        "InjectSourceDir": str(artifacts),
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created
    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    ikeys = [k for k in services.keys() if str(k).startswith("inject_copy")]
    assert ikeys, "expected inject_copy service"
    inject = services[ikeys[0]]
    assert isinstance(inject, dict)
    assert str(inject.get("image") or "") == "vulhub/coldfusion:2018.0.15"


def test_prepare_compose_inject_copy_dependency_nonblocking_by_default(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  app:\n    image: nginx:latest\n",
        encoding="utf-8",
    )

    artifacts = tmp_path / "artifacts"
    artifacts.mkdir(parents=True, exist_ok=True)
    (artifacts / "flag.txt").write_text("FLAG{demo}\n", encoding="utf-8")

    monkeypatch.setenv("CORETG_INJECT_FILES_MODE", "copy")
    monkeypatch.delenv("CORETG_INJECT_COPY_REQUIRE_SUCCESS", raising=False)

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "InjectFiles": ["flag.txt -> /tmp"],
        "InjectSourceDir": str(artifacts),
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    target = services.get("docker-1") or services.get("app")
    assert isinstance(target, dict)

    depends_on = target.get("depends_on")
    if isinstance(depends_on, dict):
        inject_keys = [k for k in depends_on.keys() if str(k).startswith("inject_copy")]
        assert not inject_keys
    elif isinstance(depends_on, list):
        inject_keys = [k for k in depends_on if str(k).startswith("inject_copy")]
        assert not inject_keys


def test_prepare_compose_root_workdir_auto_mode_skips_app_images(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  web:\n    image: vulhub/wordpress:6.0\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", raising=False)

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    target = services.get("docker-1")
    assert isinstance(target, dict)
    assert target.get("working_dir") != "/"


def test_prepare_compose_forces_no_network_for_multi_service_dependencies_by_default(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        """
services:
    nginx:
        image: nginx:latest
        depends_on:
            - php
        ports:
            - "8080:80"
    php:
        image: php:8.2-fpm
""".strip()
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", raising=False)
    monkeypatch.delenv("CORETG_COMPOSE_FORCE_NO_NETWORK", raising=False)
    monkeypatch.delenv("CORETG_COMPOSE_ALLOW_INTERNAL_NETWORKING", raising=False)

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}

    target = services.get("docker-1")
    php = services.get("php")
    assert isinstance(target, dict)
    assert isinstance(php, dict)

    assert target.get("network_mode") == "none"
    assert php.get("network_mode") == "none"
    assert "ports" not in target
    assert "ports" not in php
    assert "80" in [str(entry) for entry in (target.get("expose") or [])]
    assert "depends_on" in target


def test_prepare_compose_can_opt_in_to_internal_networking_for_multi_service_dependencies(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        """
services:
    nginx:
        image: nginx:latest
        depends_on:
            - php
        ports:
            - "8080:80"
    php:
        image: php:8.2-fpm
""".strip()
        + "\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", raising=False)
    monkeypatch.delenv("CORETG_COMPOSE_FORCE_NO_NETWORK", raising=False)
    monkeypatch.setenv("CORETG_COMPOSE_ALLOW_INTERNAL_NETWORKING", "1")

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}

    target = services.get("docker-1")
    php = services.get("php")
    assert isinstance(target, dict)
    assert isinstance(php, dict)

    assert target.get("network_mode") != "none"
    assert php.get("network_mode") != "none"
    ports = target.get("ports") or []
    assert all(':' not in str(entry) for entry in ports)
    assert "depends_on" in target


def test_prepare_compose_root_workdir_default_preserves_relative_command_paths(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  app:\n    image: apache/ofbiz:latest\n    command: ['java','-jar','./build/libs/ofbiz.jar']\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", raising=False)
    monkeypatch.delenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR_STRICT", raising=False)

    record = {
        "Type": "docker-compose",
        "Name": "OFBiz",
        "Path": str(compose_src),
    }

    created = prepare_compose_for_assignments({"docker-5": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-5.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    target = services.get("docker-5")
    assert isinstance(target, dict)
    working_dir = target.get("working_dir")
    # Relative command paths need image-defined workdir; do not force '/'.
    assert working_dir != "/"


def test_prepare_compose_root_workdir_default_preserves_ofbiz_image_workdir(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  app:\n    image: vulhub/ofbiz:18.12.10\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", raising=False)
    monkeypatch.delenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR_STRICT", raising=False)

    record = {
        "Type": "docker-compose",
        "Name": "OFBiz",
        "Path": str(compose_src),
    }

    created = prepare_compose_for_assignments({"docker-5": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-5.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    target = services.get("docker-5")
    assert isinstance(target, dict)
    assert target.get("working_dir") != "/"


def test_prepare_compose_root_workdir_auto_mode_does_not_force_nextjs(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  web:\n    image: vulhub/nextjs:15.5.6\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", raising=False)

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    target = services.get("docker-1")
    assert isinstance(target, dict)
    assert target.get("working_dir") != "/"


def test_prepare_compose_root_workdir_auto_mode_forces_base_os(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  node:\n    image: ubuntu:22.04\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", raising=False)

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    target = services.get("docker-1")
    assert isinstance(target, dict)
    assert target.get("working_dir") == "/"


def test_prepare_compose_root_workdir_auto_mode_forces_weblogic(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  web:\n    image: vulhub/weblogic:12.2.1.3-2018\n",
        encoding="utf-8",
    )

    monkeypatch.delenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", raising=False)

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    target = services.get("docker-1")
    assert isinstance(target, dict)
    assert target.get("working_dir") == "/"


def test_prepare_compose_root_workdir_can_force_all_with_env(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  web:\n    image: vulhub/nextjs:15.5.6\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", "1")

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    target = services.get("docker-1")
    assert isinstance(target, dict)
    assert target.get("working_dir") == "/"


def test_prepare_compose_can_disable_root_workdir_with_env(tmp_path, monkeypatch):
    try:
        import yaml  # type: ignore
    except Exception:
        return

    compose_src = tmp_path / "base-compose.yml"
    compose_src.write_text(
        "services:\n  web:\n    image: vulhub/nextjs:15.5.6\n",
        encoding="utf-8",
    )

    monkeypatch.setenv("CORETG_COMPOSE_FORCE_ROOT_WORKDIR", "0")

    record = {
        "Type": "docker-compose",
        "Name": "Example",
        "Path": str(compose_src),
        "ScenarioTag": "test",
    }

    created = prepare_compose_for_assignments({"docker-1": record}, out_base=str(tmp_path))
    assert created

    out_path = tmp_path / "docker-compose-docker-1.yml"
    obj = yaml.safe_load(out_path.read_text("utf-8", errors="ignore"))
    services = (obj or {}).get("services") or {}
    target = services.get("docker-1")
    assert isinstance(target, dict)
    assert "working_dir" not in target
