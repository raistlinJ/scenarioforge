# Troubleshooting

- **`core-python` not found`** – set `WEBUI_PY` before `make host-web` or rely on `python3`; the backend falls back to `sys.executable` if needed.
- **`Attack graph PDF unavailable (Graphviz not installed)`** – install Graphviz so the `dot` executable is on `PATH`. On macOS run `brew install graphviz`; on Debian/Ubuntu run `sudo apt-get install graphviz`. Docker Compose runs include Graphviz after rebuilding the web image.
- **Empty TLS cert folder (`nginx/certs`)** – run `scripts/dev_gen_certs.sh` or `make dev-certs` before composing nginx.
- **`core-daemon` unreachable`** – verify daemon status and host/port; GUI run modal will surface connection issues immediately.
- **Docker vulnerabilities skipped** – ensure images are downloaded/pulled via the Vulnerabilities catalog and Docker is available to the host.
- **Log dock won’t auto-scroll** – click the “Follow Off/On” toggle to re-enable auto-follow.
- **Proxmox validate returns 502 (nginx)** – the expected backend route is `POST /api/proxmox/validate`. A JSON validation/authentication error means the request reached Flask; a 502 usually points to the nginx container not reaching the Web UI backend, so check `docker compose ps`, `docker compose logs web nginx`, and `/healthz`.
- **Runtime validation reports issues** – inspect the run's `validation_summary` from `GET /run_status/<run_id>` while the run is retained in memory, or use the Markdown/JSON report artifacts under `./reports/`. Strict success requires `validation_summary.ok == true` and zero issue counters such as `missing_nodes`, `docker_not_running`, `injects_missing`, `generator_outputs_missing`, and `generator_injects_missing`.
