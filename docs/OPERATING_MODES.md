# ScenarioForge Operating Modes

ScenarioForge can run in VM mode, native mode, and CLI-only workflows. The README is VM-mode first; this page collects the other launch paths and when to use them.

## Mode Summary

| Mode | Best For | CORE Target |
| --- | --- | --- |
| VM mode | Proxmox labs with a separate CORE 9.2 VM and participant machine | Remote CORE VM over gRPC and SSH |
| Native mode | Local development and quick previews | CORE daemon on the same machine |
| Remote CORE mode | Non-Proxmox remote CORE hosts | Remote CORE host over gRPC and SSH |
| CLI mode | Scripted topology generation and reports | Any reachable CORE endpoint |

## Native Mode

Native mode assumes ScenarioForge and CORE run on the same host.

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

## Remote CORE Mode

Remote CORE mode is useful when CORE is on another host but you are not using the full VM-mode Proxmox/HITL workflow.

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

Set `CORETG_WEBUI_MODE=vm` when you want the VM-mode UI defaults and HITL workflows described in the README.

## Docker Compose Notes

The Compose stack runs the web app behind nginx with TLS termination:

```bash
docker compose up -d --build
```

- Open `https://localhost`.
- Verify HTTPS health with `curl -k https://localhost/healthz`.
- Stop the stack with `docker compose down`.
- Compose reads `.scenarioforge.env.example` first and `.scenarioforge.env` as optional local overrides.
- In host-network mode, nginx serves `80/443` while the backend binds to `127.0.0.1:9090`.
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

Both direct Python launches and Docker Compose read `.scenarioforge.env.example` and optional `.scenarioforge.env` values. Prefer `.scenarioforge.env` for local changes; it is ignored by git.

Configuration precedence is:

1. Real process environment variables
2. `.scenarioforge.env`
3. `.scenarioforge.env.example`
4. Built-in Python defaults
