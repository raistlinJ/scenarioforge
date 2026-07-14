# ScenarioForge Web UI

Flask Web UI for building, previewing, and executing CORE topology scenarios.

Key capabilities:
- Upload/edit scenarios and generate a Full Preview (roles, routers, links, services, vulnerabilities, segmentation).
- Execute the CLI to create/start CORE sessions and write Markdown reports under `./reports/`.
- Manage Generator Packs (flag-generators + flag-node-generators) and build Attack Flows.
- Manage Vulnerability Catalog Packs (docker-compose templates), test individual catalog items, and run catalog batch tests from the UI/API.

Remote CORE VM support:
- Scenario Execute can run remotely on a CORE VM via SSH.
- Generator **Test** runs can optionally execute on the CORE VM (via SSH) to reduce Test-vs-Execute drift.
- Vulnerability catalog item **Test** runs execute on the CORE VM and use offline-friendly preflight steps (build wrapper images, pull pull-only images, start with `--no-build`).
- REST batch CLI wrapper: `uv run catalog-rest-batch-test --target all --scope all` logs into the Web UI and runs the same vuln/flag catalog batch routes before full Execute.

## Local dev

From the repo root:

```bash
uv sync --extra dev
CORETG_USE_RELOADER=0 uv run python webapp/app_backend.py
open http://localhost:9090
```

For native VM deployments, keep `CORETG_USE_RELOADER=0`. The Web UI writes XML previews, Flow state, generator artifacts, and logs while requests are active; automatic Flask reloads can interrupt those requests.

## Docker

```bash
docker build -t scenarioforge-webapp ./webapp
docker run --rm -p 9090:9090 \
	-e CORE_HOST=host.docker.internal -e CORE_PORT=50051 \
	-v "$(pwd)":/work -w /work \
	scenarioforge-webapp
```
