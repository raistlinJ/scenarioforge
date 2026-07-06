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
Saved XML from the Web UI can be executed directly the same way:
```bash
python -m scenarioforge.cli --xml /abs/path/outputs/scenarios-06-04-26-16-31-25/scenarios.xml --scenario "Scenario 1" --verbose
```
Explicit phase commands are also available:
```bash
python -m scenarioforge.cli new --xml /abs/path/scenarios.xml --scenario "Scenario 1"
python -m scenarioforge.cli preview-plan --xml /abs/path/scenarios.xml --scenario "Scenario 1"
python -m scenarioforge.cli flag-sequencing --xml /abs/path/scenarios.xml --scenario "Scenario 1" --flow-mode resolve --flow-length 3
python -m scenarioforge.cli topo --xml /abs/path/scenarios.xml --scenario "Scenario 1" --host 127.0.0.1 --port 50051
python -m scenarioforge.cli execute --xml /abs/path/scenarios.xml --scenario "Scenario 1" --host 127.0.0.1 --port 50051
```

Seed a starter scenario in one command:

```bash
python -m scenarioforge.cli new \
	--xml /abs/path/myscen.xml \
	--scenario "myscen" \
	--density-count 10 \
	--seed-role Workstation=2 \
	--seed-role Docker=3 \
	--seed-routing OSPFv2=2 \
	--seed-service SSH=2 \
	--seed-traffic TCP \
	--seed-traffic UDP=density \
	--seed-segmentation Firewall=density \
	--seed-vulnerability jboss/CVE-2017-12149=1 \
	--seed-random-vulnerability-count 1 \
	--seed 42
```

Seed a starter scenario and embed CORE SSH credentials in the XML:

```bash
python -m scenarioforge.cli new \
	--xml /abs/path/myscen.xml \
	--scenario "myscen" \
	--host 10.0.0.50 \
	--port 50051 \
	--ssh-host 10.0.0.50 \
	--ssh-port 22 \
	--ssh-username corevm \
	--ssh-password change-me \
	--venv-bin /opt/core/venv/bin
```
Popular options:
- Replace `examples/sample.xml` with your own ScenarioForge XML file when you are ready to run a custom scenario.
- `--scenario NAME` pick a specific scenario entry
- `--seed N` make planner/build randomness deterministic. Reuse the same seed across `preview-plan`, `flag-sequencing`, `topo`, and `execute` when you want repeatable results.
- `--host / --port` override the CORE gRPC endpoint. If omitted, the CLI uses the same env-/backend-backed defaults as the Web UI, typically `localhost:50051` unless overridden by `.scenarioforge.env` or real environment variables.
- `--preview-plan PATH` override the preview source for `execute`/`topo`. If omitted, the CLI automatically reuses embedded `PlanPreview` from `--xml` when present.
- The file passed with `--xml` is the execution ground truth, including the CORE VM identity. WebUI Execute synchronizes its validated CORE selection into that XML before invoking the runner.
- `--layout-density {compact|normal|spacious}` adjust map spacing
- `--seg-include-hosts`, `--seg-allow-docker-ports`, `--nat-mode`, `--dnat-prob` fine-tune segmentation
- `--traffic-pattern`, `--traffic-rate`, `--traffic-content` override traffic defaults

Saved-XML execute notes:
- `execute` and `topo` usually do not need `--preview-plan` when the scenario XML already embeds `PlanPreview`; the CLI now reuses that embedded preview automatically.
- If you need separate CLI runs to recompute the same planner-owned randomness, keep the same `--seed` you used when persisting `PlanPreview` or resolving Flow.
- If the XML contains embedded `PlanPreview`, the CLI uses it for the same preview/slot alignment that the Web UI execute path expects.
- If the XML contains `FlagSequencing/FlowState`, the CLI now enforces the same prerequisite as Web Execute: resolved Flow runtime values and referenced local artifacts must already exist before the run starts.
- If the embedded preview metadata no longer matches the current XML-derived plan, the CLI stops early and asks you to regenerate/save preview metadata first instead of executing a stale plan.
- Avoid long-lived CLI execute runs against `outputs/tmp-preview-*` XMLs. Those files are temporary staging artifacts; use a saved scenario XML under `outputs/scenarios-*` or rerun Generate/resolve and Save before executing.

Phase command notes:
- `new` creates a starter ScenarioForge XML with one scenario and canonical section keys using the same XML builder as the Web UI.
- `--density-count` sets the scenario-level Count for Density base host pool used by density-based planning for routing, services, traffic, segmentation, and vulnerabilities. If omitted, it defaults to the same starter value used by the Web UI (`10`).
- `new` can also seed basic scenario rows with `--seed-role`, `--seed-routing`, `--seed-service`, `--seed-traffic`, `--seed-segmentation`, `--seed-vulnerability`, and `--seed-random-vulnerability-count`.
- `--seed-role` is repeatable and always uses `ROLE=COUNT` semantics for Node Information rows.
- `--seed-routing`, `--seed-service`, `--seed-traffic`, `--seed-segmentation`, and `--seed-vulnerability` are repeatable and accept `NAME`, `NAME=density`, or `NAME=COUNT`.
- Omitting `=COUNT` on those section seed flags uses density semantics; `=density` is an explicit alias for the same behavior.
- When you provide multiple density-style seed rows in the same section, the CLI assigns equal `factor` weights that add up to `1.0` for that section.
- `new` can also embed top-level CORE SSH connection details directly into the XML with `--ssh-host`, `--ssh-port`, `--ssh-username`, and `--ssh-password`.
- `preview-plan` persists embedded `PlanPreview` metadata back into the XML and prints the resulting preview payload as JSON.
- During remote `execute`/`topo`, the CLI now forwards the resolved scenario name and preview-plan context to the delegated remote CLI so the remote path matches the Web UI more closely.
- `flag-sequencing` runs the same preview/resolve helper used by the Web UI and persists the resulting `FlowState` back into the XML.
- In generator-running Flow modes such as `resolve`, the CLI now treats remote-capable CORE VM execution as required unless you explicitly pass `--flow-run-local`; it no longer silently falls back to local generator execution when remote setup fails.
- `flag-sequencing` JSON output now includes `generator_execution_requested` and `generator_execution_mode` so you can confirm whether generator work ran in `remote` or `local` mode.
- `topo` builds the topology in CORE and stops before segmentation, traffic, report generation, and session start.
- `execute` is the full default run; the phase name is optional.
- `python -m scenarioforge.cli <phase> --help` now shows phase-specific help instead of every flag for every phase.
- Core connection defaults shown in CLI help are computed the same way as the Web UI defaults, including values loaded from `.scenarioforge.env` and real environment variables.

Need more detail: see [CLI Execution Deep Dive](CLI_EXECUTION_DEEP_DIVE.md).

Saved XML parity notes:
- Direct CLI launches load `.scenarioforge.env` from the repo root when present, so the same default CORE host, SSH endpoint, VM-mode settings, and HITL-related env values used by the Web UI are available to the CLI.
- For `execute` and `topo`, the CLI now resolves the saved scenario CORE connection from the XML first, fills missing fields from env/defaults, applies any saved CORE secret reference, and uses that configuration automatically.
- When `execute` or `topo` delegates to a remote CORE VM, the CLI forwards the resolved scenario name plus the effective preview-plan source, including the implicit embedded-`PlanPreview` case, to the remote CLI process.
- When that saved scenario targets a remote CORE VM, the terminal CLI delegates the run to a remote CLI process over SSH so uploaded XML, compose files, and Flow artifacts live on the same host as `core-daemon`.
- If the XML does not carry a saved `CoreConnection`, the CLI can still use env-only remote defaults from `.scenarioforge.env` for `execute`, `topo`, and remote `flag-sequencing` generator runs.

Dangerous remote Docker cleanup:
- `uv run cleanup-scenarioforge-docker --dry-run` inspects Docker usage on the configured remote CORE SSH host.
- `uv run cleanup-scenarioforge-docker --force` removes every Docker container, image, build cache, and unused Docker volume/network on that remote host. Use this only for disposable ScenarioForge/CORE VMs used by batch evaluation; it is not safe for shared Docker hosts.

VM mode note:
- When `CORETG_WEBUI_MODE=vm`, the CLI now errors early if required CORE VM connection data is missing or still using template placeholder values. In VM mode, saved XML should carry the scenario’s CORE connection info.

## Runtime validation
Runtime validation is built into Execute and CLI runs.

- Add `--post-execution-validation` (or `-post-execution-validation`) to CLI `execute` to copy Flow injects into stable running containers, verify each destination, export the live CORE session, and run the same detailed post-run validation used by the Web UI. Container replacement triggers copy retries, and a remaining missing-inject result triggers one automatic repair/revalidation pass. The CLI prints red errors, yellow warnings, emits `VALIDATION_SUMMARY_JSON`, and saves the complete result under `core-post/validation-session-<id>.json` beside the scenario XML.
- Before running full Execute, use `uv run preflight-vuln-catalog --repo-root .` for a fast local vulnerability catalog/inject-plan check and `uv run catalog-rest-batch-test --target all --scope all` for live Web UI batch tests.
- Web runs expose validation details in `GET /run_status/<run_id>` as `validation_summary` while the run is retained in memory.
- Report artifacts under `./reports/` persist validation details for later review.
- A healthy strict validation has `validation_summary.ok == true` and zero issue counters such as `missing_nodes`, `docker_not_running`, `injects_missing`, `generator_outputs_missing`, and `generator_injects_missing`.
- An empty editor project does not create scenario XML or runtime validation artifacts until at least one scenario exists and is executed.

## Catalog preflight and batch tests

Run these before Execute when you want to catch catalog start or inject issues early.

Fast local vulnerability catalog preflight:

```bash
uv run preflight-vuln-catalog --repo-root .
```

Live Web UI batch tests for vulnerability items and both flag generator families:

```bash
uv run catalog-rest-batch-test --target all --scope untested
uv run catalog-rest-batch-test --target all --scope failed
uv run catalog-rest-batch-test --target all --scope all
```

Narrow the run when needed:

```bash
uv run catalog-rest-batch-test --target vulns --scope all --query jboss
uv run catalog-rest-batch-test --target flag-generators --scope failed --limit 25
uv run catalog-rest-batch-test --target flag-node-generators --scope all --allow-skipped
```

`catalog-rest-batch-test` logs into the Web UI, starts the existing batch routes, polls progress, and writes JSON exports under `outputs/catalog-rest-batch-tests/`. It can read saved Web UI CORE secrets or take explicit CORE config with `--core-json @core.json`.

Need more detail: see [Catalog Batch Testing](CATALOG_BATCH_TESTING.md).

## Live generator smoke
Live CORE credential parity smoke for flag tests:

- Script: `python scripts/flag_test_core_e2e_check.py`
	- Logs into Web UI, reads a CORE secret from `outputs/secrets/core`, runs both `/flag_generators_test/run` and `/flag_node_generators_test/run` with `core` credentials payload, polls outputs, and performs cleanup.
	- Useful env vars: `CORETG_WEB_BASE`, `CORETG_WEB_USER`, `CORETG_WEB_PASS`, `CORETG_CORE_SECRET_ID`, `CORETG_SMOKE_POLL_SECONDS`.
- Pytest gate for CI/live infra:
	- `CORETG_RUN_LIVE_FLAG_CORE_SMOKE=1 pytest -q tests/test_flag_test_core_e2e_smoke.py`
	- Skipped by default unless `CORETG_RUN_LIVE_FLAG_CORE_SMOKE=1` is set.
