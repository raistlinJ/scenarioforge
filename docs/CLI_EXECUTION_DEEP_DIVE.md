# CLI Execution Deep Dive

This guide explains how the ScenarioForge CLI behaves end-to-end, how each phase works, how saved XML from the Web UI is reused, and how env-backed remote CORE execution is resolved.

## Mental Model

The CLI works from a ScenarioForge scenario XML, not from a pre-built CORE session XML.

- A ScenarioForge XML contains planning sections such as Node Information, Routing, Services, Traffic, Vulnerabilities, Segmentation, optional HITL metadata, optional embedded `PlanPreview`, and optional embedded `FlagSequencing/FlowState`.
- A CORE session XML is the output of a running or exported CORE session. That is not the intended input for CLI planning phases.
- The CLI computes or reuses the scenario plan, optionally resolves Flow state, builds the topology in CORE, and can run the full execute path.

## Phase Summary

The CLI supports these phases:

- `new`: create a starter ScenarioForge XML with one scenario and empty section rows.
- `preview-plan`: compute and persist embedded `PlanPreview` metadata into the XML.
- `flag-sequencing`: compute or reuse a Flow chain and optionally resolve generator outputs into embedded `FlowState`.
- `topo`: compute the topology and build it in CORE, then stop before segmentation, traffic, report generation, and session start.
- `execute`: run the full legacy/default execute path.

If you omit the phase name, the CLI uses `execute`.

## New Phase

Use `new` to create a canonical starter ScenarioForge XML file.

Example:

```bash
python -m scenarioforge.cli new --xml /abs/path/labs/my-lab.xml --scenario "My Lab"
```

Seeded example:

```bash
python -m scenarioforge.cli new \
  --xml /abs/path/labs/myscen.xml \
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

Starter XML with explicit CORE SSH credentials:

```bash
python -m scenarioforge.cli new \
  --xml /abs/path/labs/myscen.xml \
  --scenario "myscen" \
  --host 10.0.0.50 \
  --port 50051 \
  --ssh-host 10.0.0.50 \
  --ssh-port 22 \
  --ssh-username corevm \
  --ssh-password change-me \
  --venv-bin /opt/core/venv/bin
```

Behavior:

- Creates parent directories when needed.
- Uses the same default scenario payload and XML builder as the Web UI.
- Writes a top-level `CoreConnection` block using current defaults, including values loaded from `.scenarioforge.env`.
- Creates one scenario with empty planning rows and the standard sections.
- Sanitizes the stored scenario name the same way the shared XML builder does.
- Refuses to overwrite an existing file unless `--force` is provided.

Useful `new` seeding flags:

- `--density-count N`: set the scenario-level Count for Density base host pool used by density-based planning. If omitted, the CLI uses the same starter default as the Web UI (`10`).
- `--seed-role ROLE=COUNT`: add Node Information count rows, for example `Workstation=2` or `Docker=3`.
- `--seed-routing NAME`, `NAME=density`, or `NAME=COUNT`: add one Routing row; repeat the flag to add multiple rows.
- `--seed-service NAME`, `NAME=density`, or `NAME=COUNT`: add one Services row; repeat the flag to add multiple rows.
- `--seed-traffic NAME`, `NAME=density`, or `NAME=COUNT`: add one Traffic row; repeat the flag to add multiple rows.
- `--seed-segmentation NAME`, `NAME=density`, or `NAME=COUNT`: add one Segmentation row; repeat the flag to add multiple rows.
- `--seed-vulnerability NAME`, `NAME=density`, or `NAME=COUNT`: add one Specific vulnerability row resolved against the active enabled catalog; repeat the flag to add multiple rows.
- `--seed-random-vulnerability-count 1`: add one or more random vulnerability targets.
- `--seed`: use a deterministic seed when concretizing random placeholders.

Seed semantics:

- `--density-count` is the base pool multiplied by density-style rows. For example, routing density uses roughly `floor(routing_density * density_count)` routers before additive Count rows are applied.
- `--seed-role` always uses Count semantics because Node Information host-role seeding is count-only.
- For Routing, Services, Traffic, Segmentation, and specific Vulnerabilities, omitting `=COUNT` uses density semantics.
- `NAME=density` is an explicit alias for the same density behavior.
- If you seed multiple density rows in the same section, their `factor` values are equalized so the rows in that section sum to `1.0`.
- Count rows (`NAME=COUNT`) remain additive and do not participate in that density-weight split.

Useful CORE connection flags for `new`:

- `--host` / `--port`: top-level CORE gRPC endpoint stored in XML. If omitted, defaults come from the same env-/backend-backed sources as the Web UI, usually `localhost:50051` unless overridden.
- `--ssh-host` / `--ssh-port`: CORE SSH endpoint stored in XML. If omitted, defaults come from the same Web UI/core backend defaults and environment variables.
- `--ssh-username` / `--ssh-password`: CORE SSH credentials stored in XML. If omitted, defaults come from the same Web UI/core backend defaults and environment variables.
- `--venv-bin`: remote CORE Python environment path stored in XML. If omitted, the CLI uses the same Web UI/core backend default resolution, including `CORE_VENV_BIN` and the standard CORE venv path.

If `--scenario` is omitted, the CLI uses the XML file stem as the initial scenario name.

## Preview-Plan Phase

Use `preview-plan` to persist the full preview into the XML.

Example:

```bash
python -m scenarioforge.cli preview-plan --xml /abs/path/labs/my-lab.xml --scenario "MyLab" --seed 42
```

Behavior:

- Computes the unified planner output.
- Builds the embedded `PlanPreview` payload.
- Writes the preview back into the same XML.
- Prints the resulting preview payload as JSON.
- `execute` and `topo` later reuse that embedded preview automatically when `--preview-plan` is omitted, so a separate persisted JSON preview file is usually unnecessary.

Seed note:

- `--seed` controls planner/build randomness for preview generation, topology layout, routing/vulnerability placement, and other seeded decisions.
- If you pass an explicit `--preview-plan` and omit `--seed`, the CLI reuses the seed saved in that preview payload when available.
- If you want separate CLI runs to recompute the same planner-owned decisions, reuse the same `--seed` across `preview-plan`, `flag-sequencing`, `topo`, and `execute`.

This is the normal prerequisite for Flow work when the XML does not already contain a preview.

Help note:

- `python -m scenarioforge.cli --help` shows shared options.
- `python -m scenarioforge.cli <phase> --help` shows only the flags relevant to that phase, with defaults rendered in the help output from the same env-/backend-backed sources the Web UI uses.

## Flag-Sequencing Phase

Use `flag-sequencing` to work with the same Flow prepare/resolve pipeline the Web UI uses.

Example:

```bash
python -m scenarioforge.cli flag-sequencing \
  --xml /abs/path/labs/my-lab.xml \
  --scenario "MyLab" \
  --flow-mode resolve \
  --flow-length 5 \
  --flow-best-effort
```

Important behavior:

- If no explicit `--flow-chain-id` values are provided, the helper can pick a chain automatically from the preview plan.
- If saved Flow chain ids already exist in the XML, they may be reused before a fresh chain is picked.
- In `resolve`-style modes, generator outputs are materialized and persisted back into `FlagSequencing/FlowState`.
- If remote CORE execution is configured, Flow generator runs use that remote context by default unless you explicitly pass `--flow-run-local`.
- In generator-running modes, remote-capable CLI runs now fail fast on remote sync/SSH/runtime problems instead of silently falling back to local generator execution.
- Success payloads include `generator_execution_requested` and `generator_execution_mode` so you can verify whether the generator runtime was `remote` or `local`.
- Legacy embedded previews that contain `Routing` as a protocol/service placeholder are repaired to an unset protocol before topology creation; ScenarioForge does not invent a protocol unless the input explicitly requests one.

Useful flags:

- `--flow-mode resolve`: pick or reuse a chain and resolve generator outputs.
- `--flow-mode preview`: pick or reuse a chain without resolving generator outputs.
- `--flow-chain-id`: force one or more explicit chain node ids.
- `--flow-run-remote`: force remote generator execution.
- `--flow-run-local`: force local generator execution even when remote-capable CORE config exists.
- `--flow-best-effort`: allow the helper to clamp to available eligible nodes.

Preview prerequisite behavior:

- The CLI `flag-sequencing` phase first asks the planner to persist `PlanPreview` into the XML, so a separate `preview-plan` run is usually not required.
- An explicit `preview-plan` run is still useful when you want to inspect or save preview metadata before moving on to Flow work.

## Topo Phase

Use `topo` when you want the planning XML turned into a built CORE topology but do not want the rest of the execute pipeline yet.

Example:

```bash
python -m scenarioforge.cli topo --xml /abs/path/labs/my-lab.xml --scenario "MyLab"
```

Behavior:

- Reads the ScenarioForge planning XML.
- Computes the topology plan.
- Builds routers, switches, hosts, and Docker-backed nodes in CORE.
- Stops before segmentation, traffic, report generation, and session start.

This phase does not assume the XML already contains a built topology. It computes the topology from the planning sections in the XML.

## Execute Phase

Use `execute` for the full run, or omit the phase entirely.

Examples:

```bash
python -m scenarioforge.cli execute --xml /abs/path/labs/my-lab.xml --scenario "MyLab" --verbose

python -m scenarioforge.cli --xml /abs/path/labs/my-lab.xml --scenario "MyLab" --verbose

python -m scenarioforge.cli execute \
  --xml /abs/path/labs/my-lab.xml \
  --scenario "MyLab" \
  --post-execution-validation
```

Behavior:

- Parses the scenario XML.
- Computes planning and preview alignment.
- Validates embedded Flow runtime values when Flow is active.
- Builds the topology.
- Applies segmentation.
- Generates traffic.
- Writes the report.
- Starts and validates the CORE session.
- With `-post-execution-validation` or `--post-execution-validation`, exports the started CORE session and runs the same node, Docker, Flow, generator, and inject validation used by the Web UI.

Before validating, the CLI performs the same post-run Flow artifact copy as the Web UI so generated injects are populated inside running containers. Copy success requires a stable container identity and verified destination paths; container replacement or missing destinations trigger bounded retries. If validation still detects missing injects, CLI and WebUI perform one repair-and-revalidate pass. Post-execution validation then prints a terminal summary, emits the complete `VALIDATION_SUMMARY_JSON`, and writes `core-post/validation-session-<id>.json` beside the scenario XML. Errors are red and return a nonzero CLI status. WebUI-style warnings, such as unexpected extra nodes, are yellow and preserve the successful execute status. Set `NO_COLOR=1` to disable ANSI colors.

The configured CORE start timeout is honored up to 600 seconds; the default is
120 seconds. If session startup fails before the detailed validator can run,
`execute --post-execution-validation` still emits a final
`VALIDATION_SUMMARY_JSON` with `validation_unavailable=true`, the startup error,
the session id when known, and any recognized `core-daemon` runtime hint.

Execute parity notes:

- If `--preview-plan` is omitted and `--xml` already contains embedded `PlanPreview`, the CLI automatically reuses that embedded preview during `execute` and `topo`.
- `--xml` is authoritative. Direct CLI runs use exactly that file and do not silently substitute a newer catalog XML or a different saved CORE VM. The WebUI updates its selected validated CORE connection in the XML before launching execute.
- `--seed` is still the clearest way to force deterministic recomputation across separate CLI runs. Embedded `PlanPreview` helps with saved preview alignment, but it does not replace an explicit seed when you want repeatable planner randomness end to end.
- If the resolved CORE target is remote, the terminal CLI delegates to a remote CLI process and now forwards the resolved scenario name and effective preview-plan source to that remote process, matching the Web UI path more closely.
- Avoid using `outputs/tmp-preview-*` XMLs as long-lived execute targets. They are temporary staging artifacts; use a saved scenario XML under `outputs/scenarios-*` or rerun preview/Flow resolve and Save before executing.

## Recommended Workflows

### New Scenario From Scratch

The CLI can create the starter XML, but it does not fully author scenario content for you. After `new`, you still need to populate the planning rows either in the Web UI or by editing the XML.

Recommended sequence:

```bash
python -m scenarioforge.cli new --xml /abs/path/labs/my-lab.xml --scenario "My Lab"

# Populate scenario sections in the Web UI or by editing the XML.

python -m scenarioforge.cli preview-plan --xml /abs/path/labs/my-lab.xml --scenario "MyLab" --seed 42

python -m scenarioforge.cli flag-sequencing --xml /abs/path/labs/my-lab.xml --scenario "MyLab" --flow-mode resolve --flow-length 5 --flow-best-effort

python -m scenarioforge.cli execute --xml /abs/path/labs/my-lab.xml --scenario "MyLab" --verbose
```

### Saved XML From the Web UI

If the XML already came from the Web UI and already contains `PlanPreview` and `FlowState`, you can usually run it directly.

```bash
python -m scenarioforge.cli execute --xml /abs/path/outputs/scenarios-06-04-26-16-31-25/scenarios.xml --scenario "Scenario 1" --verbose
```

Notes:

- You usually do not need `--preview-plan` for those saved XMLs because the CLI automatically reuses the embedded `PlanPreview` from the XML itself.
- Prefer saved `outputs/scenarios-*` XMLs for standalone CLI runs. `outputs/tmp-preview-*` files are ephemeral and may no longer point at valid Flow runtime artifacts by the time you execute them later.

### Topology-Only Bring-Up

```bash
python -m scenarioforge.cli topo --xml /abs/path/labs/my-lab.xml --scenario "MyLab"
```

### Flow-Only Refresh

```bash
python -m scenarioforge.cli preview-plan --xml /abs/path/labs/my-lab.xml --scenario "MyLab"
python -m scenarioforge.cli flag-sequencing --xml /abs/path/labs/my-lab.xml --scenario "MyLab" --flow-mode resolve --flow-length 5
```

## Configuration Resolution

Direct CLI launches load `.scenarioforge.env` from the repo root when present.

For CLI execution, config resolution works like this:

- Start with env/default runtime values.
- If the XML contains saved `CoreConnection` or scenario HITL core settings, use those.
- Fill missing SSH and runtime fields from saved secret-backed CORE credentials when available.
- Apply explicit CLI `--host` and `--port` overrides when provided.
- If execution is delegated to a remote CORE VM, forward the resolved scenario name and preview-plan source so the remote CLI sees the same effective execute context as the local CLI.

This gives the terminal CLI the same practical target selection model as the Web UI.

## VM Mode Requirements

VM mode is treated more strictly than native mode.

- If `CORETG_WEBUI_MODE=vm`, the CLI expects scenario XML used for `execute`, `topo`, and `flag-sequencing` to carry saved CORE VM connection data, typically through `CoreConnection` or `HardwareInLoop/CoreConnection`.
- In VM mode, the CLI does not silently fall back to env-only placeholder values when required VM connection data is missing from the XML.
- If required VM connection fields are missing, the CLI stops early and reports what is missing.

Examples of required VM-mode data:

- CORE gRPC host and port
- SSH host and port
- SSH username and password
- for VM-mode HITL defaults, a configured `CORETG_VM_MODE_HITL_CORE_IFX_NAME`

Native mode behaves differently:

- native mode can still rely on `.scenarioforge.env` defaults without requiring saved VM-specific XML metadata
- missing HITL config in native mode does not block normal CLI topology or execute phases; it just means no HITL attachment is created

## Remote CORE Behavior

When the resolved CORE configuration points at a remote CORE VM with usable SSH credentials, the CLI can delegate execution remotely.

This matters because:

- vulnerability compose files live under `/tmp/vulns`
- Flow artifacts may need to be uploaded alongside the XML
- remote `core-daemon` needs those files on the same host where it runs

For `execute` and `topo`, the CLI may start a remote CLI process over SSH so the XML and artifacts are staged on the CORE VM first.

For `flag-sequencing`, env-only or XML-saved remote CORE configuration can also drive remote generator execution.

If you need to suppress env-driven remote delegation, set:

```bash
CORETG_CLI_DISABLE_REMOTE_DELEGATION=1
```

In VM mode, remote delegation still requires the scenario XML to carry saved CORE VM connection metadata. Env-only VM defaults are not enough for `execute`, `topo`, or `flag-sequencing` when the XML lacks saved CORE connection data.

## Flow Preflight Notes

When active Flow state is embedded in the XML, execute-time preflight checks can fail early for reasons such as:

- missing Flow artifact directories
- missing injected source files
- stale `PlanPreview` metadata that no longer matches the XML-derived plan

This is intentional and mirrors the Web UI execute path.

## Troubleshooting

`flag-sequencing` says no preview plan exists:

- Run `preview-plan` first for that XML/scenario.

`execute` fails with Flow runtime path errors:

- Re-run `flag-sequencing --flow-mode resolve` to regenerate and persist Flow runtime values.

`topo` or `execute` unexpectedly use a remote CORE VM:

- Check saved `CoreConnection` data in the XML.
- Check `.scenarioforge.env` for remote CORE/SSH defaults.
- Use `CORETG_CLI_DISABLE_REMOTE_DELEGATION=1` to suppress env-only remote delegation.

`new` refuses to write the file:

- Re-run with `--force` if you want to overwrite an existing XML file.

## Current Limits

- There is no single `run-all` phase yet.
- `new` creates a starter XML but does not populate scenario rows for you.
- `flag-sequencing` depends on an existing preview plan.
- The CLI is designed for ScenarioForge planning XML, not for raw CORE session XML as a planning input.
