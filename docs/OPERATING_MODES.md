# ScenarioForge Operating Modes

ScenarioForge can run in VM mode, native/non-VM mode, and CLI-only workflows. The README is VM-mode first; this page collects the other launch paths and when to use them.

Native mode is not a separate "local-only" deployment. It is the default non-VM application mode, and CORE may be on the same machine or on another reachable host. The launcher has `auto`, `local`, and `remote` CORE target selectors; those choose the CORE endpoint, while `CORETG_WEBUI_MODE=native` keeps VM-mode HITL defaults disabled.

## Mode Summary

| Mode | Best For | CORE Target |
| --- | --- | --- |
| VM mode | Proxmox labs with a separate CORE 9.2 VM and participant machine | Remote CORE VM over gRPC and SSH |
| Native mode, local CORE | Local development and quick previews | Autodetected/default local CORE endpoint |
| Native mode, remote CORE | Non-Proxmox remote CORE hosts | Explicit remote CORE host over gRPC and SSH |
| CLI mode | Scripted topology generation and reports | Any reachable CORE endpoint |

## Native Mode

Native mode is the non-VM mode. Use it whenever you are not asking ScenarioForge to pre-seed VM/HITL behavior. CORE can be local or remote.

### Local CORE Autodetect

When CORE 9.2 is running on the same machine and no `CORE_HOST` override is set, the auto/default launch path uses the local CORE endpoint. You can usually leave `CORETG_WEBUI_MODE=native` and avoid setting a remote host.

1. Start CORE 9.2 and ensure `core-daemon` is listening on `127.0.0.1:50051`.
2. Copy the local env override file if you want persistent defaults:

```bash
cp .scenarioforge.env.example .scenarioforge.env
```

3. Set the local values:

```dotenv
CORE_HOST=127.0.0.1
CORE_PORT=50051
CORETG_WEBUI_MODE=native
CORETG_HOST=0.0.0.0
CORETG_PORT=9090
```

4. Launch the Web UI directly:

```bash
uv sync --extra dev
uv run python webapp/app_backend.py
```

With pip/venv:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python webapp/app_backend.py
```

5. Open `http://localhost:9090`.

You can also use the local helper script:

```bash
bash scripts/run_webui_local.sh --web-port 9090
```

### Explicit Remote CORE Target

Use an explicit remote CORE target when CORE is on another host but you are not using the full VM-mode Proxmox/HITL workflow. This is still native mode unless you set `CORETG_WEBUI_MODE=vm`.

```bash
bash scripts/run_webui_remote.sh --core-host 10.0.0.50 --core-port 50051 --web-port 9090
```

Use `.scenarioforge.env` for persistent defaults:

```dotenv
CORE_HOST=10.0.0.50
CORE_PORT=50051
CORE_SSH_HOST=10.0.0.50
CORE_SSH_PORT=22
CORE_SSH_USERNAME=corevm
CORETG_WEBUI_MODE=native
```

Set `CORETG_WEBUI_MODE=vm` only when you want the VM-mode UI defaults and HITL workflows described in the README.

## Docker Compose Notes

The Compose stack runs the web app behind nginx with TLS termination:

```bash
docker compose up -d --build
```

- Open `https://localhost`.
- Verify HTTPS health with `curl -k https://localhost/healthz`.
- The backend is also published at `http://localhost:9090`.
- Stop the stack with `docker compose down`.
- Compose reads `.scenarioforge.env.example` first and `.scenarioforge.env` as optional local overrides.
- Compose publishes nginx on `80/443` and the backend on `127.0.0.1:9090`. In native Docker bridge mode, container-local CORE targets such as `127.0.0.1` are treated as `host.docker.internal`; in VM mode, `127.0.0.1` is preserved because it means core-daemon on the remote CORE host reached over SSH. Set `CORETG_KEEP_CONTAINER_LOCAL_CORE=1` only when CORE really runs inside the web container.
- The image includes Graphviz, so attack graph PDF export works without installing Graphviz on the application host.

## CLI Mode

Run the CLI with uv:

```bash
uv run python -m scenarioforge.cli --xml examples/sample.xml --seed 42 --verbose
```

With pip/venv:

```bash
python -m scenarioforge.cli --xml examples/sample.xml --seed 42 --verbose
```

Useful options:

- `--xml` points to a ScenarioForge XML file.
- `--scenario` selects a named scenario from a multi-scenario XML file.
- `--host` / `--port` override the CORE gRPC endpoint.
- `--layout-density` adjusts preview map spacing.
- `--traffic-pattern`, `--traffic-rate`, and `--traffic-content` override traffic defaults.

## Shared Environment File

Docker Compose reads `.scenarioforge.env.example` and then optional `.scenarioforge.env` values. Direct Python launches read `.scenarioforge.env` when present and otherwise use built-in defaults. Prefer `.scenarioforge.env` for local changes; it is ignored by git.

For Compose, configuration precedence is:

1. Real process environment variables
2. `.scenarioforge.env`
3. `.scenarioforge.env.example`
4. Built-in Python defaults

For direct Python, `.scenarioforge.env.example` is documentation and a copy source; copy it to `.scenarioforge.env` when you want file-based runtime overrides.
