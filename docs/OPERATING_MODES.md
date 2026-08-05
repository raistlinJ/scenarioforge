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

## Image Retention And Offline Runs

A repeat run on unchanged content should not need a registry. Three kinds of
image live on the CORE VM and they are treated differently, because only some of
them can be restored without the network.

| Kind | Example | Keyed by | On cleanup |
| --- | --- | --- | --- |
| Upstream base image | `alpine:3.19`, `vulhub/solr:8.11.0` | registry digest | **kept** — only a pull could restore it |
| Generator image | `coretg-gen-<pack>-<service>-<source-digest>` | digest of the generator source | **kept** — a source edit yields a new tag |
| Wrapper image | `coretg/scenarios-<scenario>-<node>-<hash>:iproute2` | hash of the wrapper identity | **kept** — preflight rebuilds it each run anyway |
| CORE session build | `core-<session>-<node>-<name>-<service>` | project name only | **always removed** before the topology build |

That last row is the one that must not survive. CORE builds it with
`docker compose up -d`, which builds only when the tag is absent, and session and
node ids repeat between runs — so a retained image silently runs a previous
run's code.

What this means in practice:

- Preflight skips `docker compose pull` entirely when every pull-only image for a
  node is already present, so a cached run contacts no registry.
- Cleanup deletes locally built images that are not pinned, and never deletes an
  image carrying a repo digest.
- Generator images are reused when their source digest is unchanged; the
  Generate and Execute progress modals report the split as
  `Pulling: x images / Using: y cached / Pending: z`.
- **"Kept" means selected by digest, never by pattern.** Flow cleanup removes a
  `coretg-gen-*` image only when no installed generator source still produces
  that tag, computed with the same digest the runner uses
  (`scenarioforge/utils/generator_images.py`, shared with
  `scripts/run_flag_generator.py` so the two cannot drift). A blanket
  `grep coretg-gen- | xargs docker rmi` emptied the cache on every run, which
  made `Using: 0 cached` permanent and, on an air-gapped host, meant a rebuild
  that could not fetch its base image. If `cached` is 0 on a second identical
  Generate, something is deleting images rather than the digest changing.
- `Pending` counts runs that reported neither outcome. It should normally be 0:
  a non-zero value means a generator's output did not carry its
  `[compose] … cached` / `… will build now` line, not that work is outstanding.
- A cached generator image still produces different flags, filenames and injects
  every run: the image holds the generator's code, while the values come from the
  per-run configuration (seed, node name, scenario).

### Pinning An Image As Persistent

Marking a vulnerability-catalog or generator item **persistent** adds its images
to a keep set that no ScenarioForge cleanup will remove. The set is computed
where the catalog state lives and handed to the remote run, which has no view of
it. If the list ever grows past what can be passed safely, it is dropped for that
run with a warning explaining how to reduce it — the run still succeeds, but
pinned images may be removed and pulled again next time.

Pinning is not required for ordinary caching: base images and content-addressed
builds already survive. Pin an item when you want its images kept even though
they are locally built and unpinned images of that kind are cleared.

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

Inspect and validate running sessions without a Web UI:

```bash
# What is running, and which scenario/XML it came from
python -m scenarioforge.cli list-sessions

# Validate a running session (add --strict to fail on warnings)
python -m scenarioforge.cli check-artifacts --session-id 1 --xml "$XML" \
  --check-artifacts-delay 45
```

See [CLI Execution Deep Dive](CLI_EXECUTION_DEEP_DIVE.md#check-artifacts-phase).

## Validation And Solvability Across Modes

Two post-deployment checks behave slightly differently per mode.

**Artifact checks** (CORE page button, or the `check-artifacts` CLI phase) validate a running session's containers, services, ports, injects, segmentation, traffic scripts, and reachability.

| Mode | How the checks reach the session |
| --- | --- |
| VM mode | Probe scripts run on the CORE VM over SSH using the saved `CORE_SSH_*` credentials. This is the primary path. |
| Native mode, remote CORE | Same as VM mode; the checks use the explicit remote CORE host's SSH settings. |
| Native mode, local CORE | The same probes run against the local CORE host. SSH settings must still resolve to that host. |

In every mode the probes reach Docker-backed nodes with `docker exec` and namespaced CORE vnodes (routers, PCs) with `vcmd`. Port reachability is always measured across the CORE-emulated network rather than through host-published ports, so results do not depend on Docker port publishing.

**The Solutions Script** (Reports page → Downloads) verifies that a deployed scenario is actually solvable. It runs from wherever you launch it:

- Run it directly when the host routes to the CORE node subnet — typical for native/local CORE, a bridged participant machine, or running it on the CORE VM itself.
- In VM mode, pass `--ssh-host`/`--ssh-user`/`--ssh-key` so each step is tunneled through the CORE VM, which can reach the emulated subnet.

## Shared Environment File

Docker Compose reads `.scenarioforge.env.example` and then optional `.scenarioforge.env` values. Direct Python launches read `.scenarioforge.env` when present and otherwise use built-in defaults. Prefer `.scenarioforge.env` for local changes; it is ignored by git.

For Compose, configuration precedence is:

1. Real process environment variables
2. `.scenarioforge.env`
3. `.scenarioforge.env.example`
4. Built-in Python defaults

For direct Python, `.scenarioforge.env.example` is documentation and a copy source; copy it to `.scenarioforge.env` when you want file-based runtime overrides.
