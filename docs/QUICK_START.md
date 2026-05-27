# Quick Start

## Prerequisites
- Python 3.10+ (3.11 recommended)
- [uv](https://docs.astral.sh/uv/)
- [CORE](https://www.nrl.navy.mil/Our-Work/Areas-of-Research/CORE/) 9.2 or newer with `core-daemon` running
- Docker (optional) for nginx reverse proxy or vulnerability compose targets
- Graphviz `dot` (optional, required for attack graph PDF export)
	- macOS: `brew install graphviz`
	- Debian/Ubuntu: `sudo apt-get install graphviz`

## Install dependencies
Using **uv**:
```bash
uv sync --extra dev
```

Using **pip**:
```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
```

## HTTPS via Docker Compose
Run the web app behind nginx with TLS termination:
```bash
docker compose up -d --build
```
- Open `https://localhost`.
- Verify HTTPS health: `curl -k https://localhost/healthz`
- The backend is also published at `http://localhost:9090`.
- The Compose web image includes Graphviz, so attack graph PDF export is available without extra host setup.
- Stop the stack: `docker compose down`
- Compose publishes nginx on `80/443` and the web backend on `127.0.0.1:9090`.
- Safety: in Execute → Advanced, `Delete all docker containers` is disabled when the Web UI is running in Docker.

## Launch the Web UI
Run the backend directly for local development:
```bash
uv run python webapp/app_backend.py
```
With **pip**:
```bash
python webapp/app_backend.py
```
- Visit `http://localhost:9090`.
- The Scenarios editor can be empty. If you delete the last scenario, the UI keeps an empty project until you create or import another scenario.
- Saving an empty editor snapshot preserves that state, but no scenario XML is generated until at least one scenario exists.
- For HTTPS + reverse proxy mode, use [HTTPS via Docker Compose](#https-via-docker-compose).
- HITL editor note: the “Attach to” dropdown offers `Existing Router`, `Existing Switch`, or `New Router`. Once Proxmox credentials and VM selections are validated, use **Apply Internal Bridge** to create/update a Proxmox bridge and retarget both the CORE VM and external VM interfaces in one step.

## Run the CLI
With **uv**:
```bash
uv run python -m scenarioforge.cli --xml examples/sample.xml --seed 42 --verbose
```
With **pip**:
```bash
python -m scenarioforge.cli --xml examples/sample.xml --seed 42 --verbose
```
Popular options:
- Replace `examples/sample.xml` with your own ScenarioForge XML file when you are ready to run a custom scenario.
- `--scenario NAME` pick a specific scenario entry
- `--host / --port` override the CORE gRPC endpoint (defaults `127.0.0.1:50051`)
- `--layout-density {compact|normal|spacious}` adjust map spacing
- `--seg-include-hosts`, `--seg-allow-docker-ports`, `--nat-mode`, `--dnat-prob` fine-tune segmentation
- `--traffic-pattern`, `--traffic-rate`, `--traffic-content` override traffic defaults

## Runtime validation
Runtime validation is built into Execute and CLI runs.

- Web runs expose validation details in `GET /run_status/<run_id>` as `validation_summary` while the run is retained in memory.
- Report artifacts under `./reports/` persist validation details for later review.
- A healthy strict validation has `validation_summary.ok == true` and zero issue counters such as `missing_nodes`, `docker_not_running`, `injects_missing`, `generator_outputs_missing`, and `generator_injects_missing`.
- An empty editor project does not create scenario XML or runtime validation artifacts until at least one scenario exists and is executed.

## Live generator smoke
Live CORE credential parity smoke for flag tests:

- Script: `python scripts/flag_test_core_e2e_check.py`
	- Logs into Web UI, reads a CORE secret from `outputs/secrets/core`, runs both `/flag_generators_test/run` and `/flag_node_generators_test/run` with `core` credentials payload, polls outputs, and performs cleanup.
	- Useful env vars: `CORETG_WEB_BASE`, `CORETG_WEB_USER`, `CORETG_WEB_PASS`, `CORETG_CORE_SECRET_ID`, `CORETG_SMOKE_POLL_SECONDS`.
- Pytest gate for CI/live infra:
	- `CORETG_RUN_LIVE_FLAG_CORE_SMOKE=1 pytest -q tests/test_flag_test_core_e2e_smoke.py`
	- Skipped by default unless `CORETG_RUN_LIVE_FLAG_CORE_SMOKE=1` is set.
