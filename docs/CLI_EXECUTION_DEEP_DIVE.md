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
  --seed-role Workstation=2 \
  --seed-role Docker=3 \
  --seed-routing Random \
  --seed-traffic Random \
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

- `--seed-role ROLE=COUNT`: add Node Information count rows, for example `Workstation=2` or `Docker=3`.
- `--seed-routing Random`: add a Routing row, optionally with `--seed-routing-density`.
- `--seed-traffic Random`: add a Traffic row, optionally with `--seed-traffic-density`.
- `--seed-random-vulnerability-count 1`: add one or more random vulnerability targets.
- `--seed`: use a deterministic seed when concretizing random placeholders.

Useful CORE connection flags for `new`:

- `--host` / `--port`: top-level CORE gRPC endpoint stored in XML.
- `--ssh-host` / `--ssh-port`: CORE SSH endpoint stored in XML.
- `--ssh-username` / `--ssh-password`: CORE SSH credentials stored in XML.
- `--venv-bin`: remote CORE Python environment path stored in XML.

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

This is the normal prerequisite for Flow work when the XML does not already contain a preview.

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
- If remote CORE execution is configured, Flow generator runs can also use that remote context.

Useful flags:

- `--flow-mode resolve`: pick or reuse a chain and resolve generator outputs.
- `--flow-mode preview`: pick or reuse a chain without resolving generator outputs.
- `--flow-chain-id`: force one or more explicit chain node ids.
- `--flow-run-remote`: force remote generator execution.
- `--flow-run-local`: force local generator execution.
- `--flow-best-effort`: allow the helper to clamp to available eligible nodes.

Prerequisite:

- The XML must already contain an embedded preview plan, or `flag-sequencing` will fail and ask you to run `preview-plan` first.

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