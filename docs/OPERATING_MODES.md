# ScenarioForge Operating Modes

ScenarioForge can run in VM mode, native/non-VM mode, and CLI-only workflows. The README is VM-mode first; this page collects the other launch paths and when to use them.

Whatever the mode, install CORE from our fork, <https://github.com/raistlinJ/core>, which already carries the fixes and updates ScenarioForge depends on; with an upstream/vanilla CORE install you must apply those updates yourself. The [coreemu-minimal](https://github.com/raistlinJ/coreemu-minimal) installer is the quickest way to get one. See [CORE Install](CORE_INSTALL.md).

For step-by-step setup, see [VM Mode Setup](VM_MODE_SETUP.md) and [Native Mode Setup](NATIVE_MODE_SETUP.md). Both include a full `.scenarioforge.env` reference; the native page also covers Proxmox credentials, privileges, and the VM / Access workflow.

Native mode is not a separate "local-only" deployment. It is the default non-VM application mode, and CORE may be on the same machine or on another reachable host. The launcher has `auto`, `local`, and `remote` CORE target selectors; those choose the CORE endpoint, while `CORETG_WEBUI_MODE=native` keeps VM-mode HITL defaults disabled.

## Mode Summary

| Mode | Best For | CORE Target |
| --- | --- | --- |
| VM mode | Labs with a separate CORE 9.2 VM and participant machine, on any hypervisor | Remote CORE VM over gRPC and SSH |
| Native mode, local CORE | Local development and quick previews | Autodetected/default local CORE endpoint |
| Native mode, remote CORE | Remote CORE hosts you select from the UI | Explicit remote CORE host over gRPC and SSH |
| CLI mode | Scripted topology generation and reports | Any reachable CORE endpoint |

## Native Mode

Native mode is the non-VM mode. Use it whenever you are not asking ScenarioForge to pre-seed VM/HITL behavior. CORE can be local or remote.

### Local CORE Autodetect

When CORE 9.2 is running on the same machine and no `CORE_HOST` override is set, the auto/default launch path uses the local CORE endpoint. You can usually leave `CORETG_WEBUI_MODE=native` and avoid setting a remote host.

1. Start CORE 9.2 — installed from [our fork](https://github.com/raistlinJ/core), or vanilla CORE with the [ScenarioForge updates applied](CORE_INSTALL.md#using-upstream-core-instead) — and ensure `core-daemon` is listening on `127.0.0.1:50051`.
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

Image retention is explicit. Scenario content survives cleanup only when its
catalog or generator entry is marked `persistent`; ScenarioForge's own
prerequisite images are the sole automatic exception.

| Kind | Example | Keyed by | On cleanup |
| --- | --- | --- | --- |
| Scenario base image | `vulhub/solr:8.11.0` | registry digest | **removed unless persistent** |
| Framework prerequisite | `busybox:1.36.1-musl`, inject-copy/pivot images | framework inventory | **kept automatically** |
| Generator image | `coretg-gen-<pack>-<service>-<source-digest>` | digest of the generator source | **removed unless persistent** |
| Wrapper image | `coretg/scenarios-<scenario>-<node>-<hash>:iproute2` | hash of the wrapper identity | **removed unless persistent** |
| CORE session build | `core-<session>-<node>-<name>-<service>` | project name only | **always removed** before the topology build |

The last row must be removed before the next topology build. CORE builds it with
`docker compose up -d`, which builds only when the tag is absent, and session and
node ids repeat between runs — so a retained image silently runs a previous
run's code. Generator and wrapper images are also disposable, but their tags do
not carry that same stale-session risk.

What this means in practice:

- Preflight skips `docker compose pull` for each base image already present and
  asks Compose for only the services whose bases are missing. A mixed node no
  longer refreshes all of its cached bases because one service is cold.
- Cleanup deletes locally built generator, wrapper, and session images that are
  not pinned. An ordinary pulled image is also removable: a repo digest records
  provenance but does not imply persistence.
- Framework prerequisites are always added to the keep set. This includes
  BusyBox, inject-copy, pivot-provider, and shipped-template runtime images,
  including environment-configured mirror replacements.
- Generator images can still be reused by later assignments in the same
  generation pass. The Generate progress modal calls the cold outcome
  `Building`, not `Pulling`, because it is a local build from a cached base.
- `Pending` counts runs that reported neither outcome. It should normally be 0:
  a non-zero value means a generator's output did not carry its
  `[compose] … cached` / `… will build now` line, not that work is outstanding.
- Rebuilding a generator image still produces different flags, filenames and
  injects every run: the image holds the generator's code, while the values come
  from the per-run configuration (seed, node name, scenario).

### Pinning An Image As Persistent

Marking a vulnerability-catalog or generator item **persistent** adds its images
to a keep set that no ScenarioForge cleanup will remove. The set is computed
where the catalog state lives and handed to the remote run, which has no view of
it. If the list ever grows past what can be passed safely, it is dropped for that
run with a warning explaining how to reduce it — the run still succeeds, but
pinned images may be removed and pulled again next time.

Pin an item when its scenario images must remain available between runs. Without
that flag, ordinary pulled bases and locally built outputs are eligible for
cleanup; only framework prerequisites are retained automatically.

Items and generators arrive **persistent** when they are imported, so a freshly
imported catalog keeps whatever gets cached for it. An export carries each
item's own pin state, so reinstalling a catalog curated elsewhere restores that
curation instead of re-pinning everything. To clear a pinned item's image, unmark
it first (**Unmark Persistent** on the catalog tab), then run **Clear Cache**.

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
