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
- `check-artifacts`: validate a running CORE session against its scenario (containers, services, ports, injects, segmentation, traffic, reachability).
- `list-sessions`: list running CORE sessions with the scenario and source XML each one came from.

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
  --seed-role VulnerabilitySlot=2 \
  --seed-role Docker=3 \
  --seed-routing OSPFv2=2 \
  --seed-service SSH=2 \
  --seed-traffic TCP \
  --seed-traffic UDP=density \
  --seed-segmentation Firewall=density \
  --seed-vulnerability jboss/CVE-2017-12149=1 \
  --seed-random-vulnerability-count 1 \
  --seed-flag-node-generator git_deploy_key_repo=1 \
  --seed-random-flag-node-generator-count 1 \
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
- `--seed-role ROLE=COUNT`: add Node Information count rows, for example `Workstation=2` or `Docker=3`. `ROLE` is one of `Server`, `Workstation`, `PC`, `Docker`, `VulnerabilitySlot`, `FlagGenSlot`.

  `Docker` hosts are the catch-all challenge target: flag-sequencing may place either a vulnerability or a flag-node-generator on them. `VulnerabilitySlot` and `FlagGenSlot` reserve Docker-backed capacity for one challenge kind only — a vulnerability never lands on a `FlagGenSlot`, and a flag-node-generator never lands on a `VulnerabilitySlot`.

  Slot counts are independent of the counts declared in the Vulnerabilities and Flag Node Generators sections and are **additional** capacity: 5 `FlagGenSlot` rows plus 5 declared generators yields 10 challenge hosts, not 5. Declared card rows fill the Docker hosts added for them; slots stay free for flag-sequencing to place further challenges into, and remain in the topology as empty Docker-backed hosts if sequencing does not use them.
- `--seed-routing NAME`, `NAME=density`, or `NAME=COUNT`: add one Routing row; repeat the flag to add multiple rows.
- `--seed-service NAME`, `NAME=density`, or `NAME=COUNT`: add one Services row; repeat the flag to add multiple rows.
- `--seed-traffic NAME`, `NAME=density`, or `NAME=COUNT`: add one Traffic row; repeat the flag to add multiple rows.
- `--seed-segmentation NAME`, `NAME=density`, or `NAME=COUNT`: add one Segmentation row; repeat the flag to add multiple rows.
- `--seed-vulnerability NAME`, `NAME=density`, or `NAME=COUNT`: add one Specific vulnerability row resolved against the active enabled catalog; repeat the flag to add multiple rows.
- `--seed-random-vulnerability-count 1`: add one or more random vulnerability targets.
- `--seed-flag-node-generator ID` or `ID=COUNT`: add one or more topology-selected Docker challenge slots bound to an enabled flag-node-generator.
- `--seed-random-flag-node-generator-count 1`: add one or more random topology-selected flag-node-generator slots.
- `--seed`: use a deterministic seed when concretizing random placeholders.

Seed semantics:

- `--density-count` is the base pool multiplied by density-style rows. For example, routing density uses roughly `floor(routing_density * density_count)` routers before additive Count rows are applied.
- `--seed-role` always uses Count semantics because Node Information host-role seeding is count-only.
- For Routing, Services, Traffic, Segmentation, and specific Vulnerabilities, omitting `=COUNT` uses density semantics.
- `NAME=density` is an explicit alias for the same density behavior.
- If you seed multiple density rows in the same section, their `factor` values are equalized so the rows in that section sum to `1.0`.
- Count rows (`NAME=COUNT`) remain additive and do not participate in that density-weight split.
- Specific and random flag-node-generator rows are additive Docker challenge slots, like vulnerability rows: they do not reduce or consume the Docker host count seeded through `--seed-role Docker=COUNT`. The CLI writes them into the XML `Flag Node Generators` section, which remains the execution ground truth for preview, Flow, topology, guides, and Execute.
- `--seed-role VulnerabilitySlot=COUNT` and `--seed-role FlagGenSlot=COUNT` declare dedicated challenge capacity in Node Information. Like the additive rows above they raise the host count, and they never reduce the counts declared in the Vulnerabilities or Flag Node Generators sections. Their purpose is headroom for flag-sequencing: a `FlagGenSlot` accepts only flag-node-generators and a `VulnerabilitySlot` only vulnerabilities, so sequencing can add challenges of a chosen kind without opening the topology to the other. Both kinds materialize empty and are filled from the installed catalog only when the requested chain length reaches them, so declaring a slot does not raise the minimum chain length; an unused slot stays a plain Docker-backed host. See [Challenge slot roles](reference/SCENARIO_XML_SCHEMA.md#challenge-slot-roles).

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
- Legacy embedded previews that contain `Routing` as a protocol/service placeholder are repaired to an unset protocol before topology creation. If a realized topology has multiple routers and no protocol was selected anywhere, the topology builder applies OSPFv2 as an operational default so attached LANs can exchange routes; explicit protocol assignments are never replaced.

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

The phase JSON includes a `pivot_access` block when the scenario enables
"accessible by pivot": one entry per walled-off subnet naming the provider, its
address, its entry (`ssh:2222`, `vulnerability:8080`, ...), whether a node was
added for it and from which image, plus anything `unresolved` — a subnet with no
way in at all — and any `nested_candidates`. Provider nodes are **created**
during this phase: the container runs, on its pinned image, with its service
listening. Their CORE interfaces are not addressed until the session starts, so
`topo` shows you the node, the image and the planned address, while the address
is only *on* the node after `execute`.

`--plan-output` is best-effort. In VM mode the run is delegated to the CORE VM,
so the path is resolved there — a directory from your own machine may not exist
on it. The phase result is always on stdout, and a path that cannot be written
is reported without failing a phase that otherwise succeeded.

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
- Removes the Docker images this application built — iproute2 wrappers (`coretg/<slug>:iproute2`), generator-pack builds (`p_<stamp>__<n>-generator`), CORE's per-node compose builds (`docker-27conf-docker-27`, `docker-11-node`), and per-session `core-<session>-<node>-*` images — and prunes the entire Docker build cache. Conflict cleanup also removes ordinary scenario images even when they came from a registry; a repo digest is not a retention flag. Images from catalog/generator items marked **persistent** are never removed, and framework prerequisites such as BusyBox, inject-copy, pivot-provider, and shipped-template images are automatically protected. Unrelated host images remain outside ScenarioForge's cleanup scope. Removal is not forced, so an image still referenced by a container (a session that is still up) is skipped rather than pulled out from under it. Expect unpinned scenario content to be pulled or rebuilt again after cleanup.
- Empties the shared runtime scratch directories (`/tmp/traffic`, `/tmp/segmentation`), so a scenario with no traffic or no segmentation does not inherit the previous scenario's artifacts. These directories are bind-mounted read-only into nodes and hold only the current run's live scripts and summaries, so their contents are removed wholesale; the directories themselves are kept (and created when absent) because compose bind-mounts reference the paths. `topo` does not do this, because it generates neither. Treat these directories as scratch owned by the newest run — do not park anything there you want to keep.
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

## List-Sessions Phase

`list-sessions` shows what is currently running on the configured CORE target, together with the scenario name and the saved source XML each session was started from. It does not need `--xml`.

```bash
python -m scenarioforge.cli list-sessions
python -m scenarioforge.cli list-sessions --scenario "MyLab"
```

```text
SESSION  STATE    SCENARIO   XML
-------  -------  ---------  --------------------------------------------------
1        RUNTIME  Scenario2  /abs/path/outputs/scenarios-08-01-26-15-26-34/Scenario2.xml
```

The XML column deliberately prefers a saved *source* scenario XML (one carrying `ScenarioEditor`) over an exported `outputs/core-sessions/session-<id>.xml`, so the path it prints is the one `check-artifacts` and the other phases expect.

## Check-Artifacts Phase

`check-artifacts` validates a **running** session against what the scenario said it should be. It runs nine ordered checks:

1. Containers are running on the correct nodes.
2. Services are running.
3. Service ports are open and reachable across the CORE network.
4. Inject files are present in the right location on the nodes.
5. Firewall/segmentation rules are in place.
6. Traffic agents are running where they should be.
7. Each traffic source can reach its destination, **on that flow's own protocol and port**. Never with ping: a default-deny segmentation policy drops ICMP on paths that are working perfectly.
8. Each Flow `Pivot(source)` relationship required by the generated challenge chain is traversable from that source node to its target at runtime.
9. Every pivot provider is reachable from the participant, so the challenges behind a segmentation boundary stay solvable.

Configured traffic and Flow pivot paths are hard requirements. A required
endpoint with no live agent, a missing runtime probe result, a TCP refusal, an
unreachable path, or UDP without destination-side delivery evidence is a
`fail` in both normal and strict mode. The live probes make three bounded
attempts and match every IPv4 address on multi-homed nodes before declaring a
path broken.

The list lives in `artifact_checks.CHECK_ORDER` and the CLI runs the same
orchestrator the web UI does, so the two never drift.

Checks 3, 8, and 9 are the ones most often misread:

- **Check 3** probes each listening port from a node that *should* reach it: the
  source of the flow that uses that exact port, or a peer on the port's own
  subnet when no flow does. A drop is reported as configured behaviour when a
  segmentation rule explains it, or when the default-deny policy does and
  nothing was supposed to open the path. It warns only when an allow rule opens
  the path and the packets were dropped anyway — the case worth investigating.
- **Check 8** enters each Flow pivot source's Docker or CORE namespace and
  connects to its required chain target. It uses Flow's declared target port
  when present, otherwise a non-loopback TCP listener discovered on the target;
  a closed-port RST also proves the path works in both directions. This is the
  runtime counterpart to Flow's logical `Pivot(node)` dependency validation.
- **Check 9** reads the rules rather than sending packets, because the
  participant's vantage point cannot be probed from: the HITL node is an RJ45
  bound to a physical interface, not a namespace. It therefore still runs with
  nothing plugged in.

```bash
# Standalone against a running session
python -m scenarioforge.cli check-artifacts \
  --session-id 1 \
  --xml /abs/path/outputs/scenarios-.../Scenario2.xml

# Give routing convergence and slow services time to settle first
python -m scenarioforge.cli check-artifacts --session-id 1 --xml "$XML" \
  --check-artifacts-delay 45

# Fail the run on warnings too
python -m scenarioforge.cli check-artifacts --session-id 1 --xml "$XML" --strict
```

Behavior and options:

- `--session-id` is optional. When omitted, the most recent session recorded for the scenario in `outputs/core_sessions.json` is used. The session is confirmed to be live before any checks run, so a stale or wrong id fails immediately instead of silently validating a different session.
- `--check-artifacts-delay SECONDS` waits before probing. Use it whenever routing needs to converge or slow containers are still starting.
- `--strict` promotes advisory warnings to failures. Required traffic and pivot
  connectivity already use `fail`, so they exit nonzero in both modes. Warnings
  are reserved for non-required observations such as stale extra traffic agents
  or unrelated service-port anomalies.
- The XML you pass may be either a saved source scenario XML or the deployed session XML; the CLI recovers the real source XML from the session store when needed.

Checks 1-4 reuse the same validator as `--post-execution-validation`. Checks
5-8 include live probes executed on the CORE VM over SSH, reaching Docker-backed
nodes with `docker exec` and namespaced CORE vnodes (routers/PCs) with `vcmd`.

Output is a per-check table followed by a single machine-readable marker line, `CHECK_ARTIFACTS_SUMMARY_JSON: {...}`, matching the `VALIDATION_SUMMARY_JSON` convention:

```text
[PASS ] Containers running on correct nodes: All 22 expected containers present.
[PASS ] Ports open: All 32 stable service port target(s) reachable (33 listening across 24 node(s)).
[SKIP ] Required traffic agents running: No traffic configured for this scenario.
------------------------------------------------------------------------
Overall: pass — 4 pass, 3 skip
CHECK_ARTIFACTS_SUMMARY_JSON: {"ok": true, "overall": "pass", ...}
```

The console table lists only actionable detail rows (`warn`/`fail`); the marker payload retains every row for downstream harnesses.

### Running checks automatically after execute

`execute` accepts the same flags so a full run can validate itself:

```bash
python -m scenarioforge.cli execute --xml "$XML" --scenario "MyLab" \
  --post-execution-validation \
  --check-artifacts --check-artifacts-delay 45
```

The checks run after execute and post-execution validation, so they add findings rather than masking an earlier failure. `--strict` applies here too.

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

### Catalog Preflight And Batch Checks

These standalone commands are not `scenarioforge.cli` phases. They are pre-execute checks for catalog health.

Fast local vulnerability catalog preflight:

```bash
uv run preflight-vuln-catalog --repo-root .
```

This checks the active installed vulnerability catalog without starting CORE or Docker. It validates compose/template compatibility and inject-plan wiring, then writes `outputs/vuln-catalog-preflight/latest.json` by default.

Live Web UI batch tests:

```bash
uv run catalog-rest-batch-test --target all --scope untested
uv run catalog-rest-batch-test --target all --scope failed
uv run catalog-rest-batch-test --target all --scope all
```

Targets are `vulns`, `flag-generators`, `flag-node-generators`, and `all`. Scope aliases match the Web UI filters: `untested`, `failed`, and `all`. The command logs into the Web UI, starts the existing batch routes, polls progress, and exports JSON reports under `outputs/catalog-rest-batch-tests/`.

See [Catalog Batch Testing](CATALOG_BATCH_TESTING.md) for full usage, CORE credential options, and exit codes.

## The plan is what runs

Execute does not re-derive anything the plan already decided. Segmentation and
traffic are both planned at `preview-plan` time and **replayed** at execute:

- Every planned segmentation rule carries its own policy script, so execute
  writes that script and enables the recorded service rather than drawing a new
  policy. You will see `Segmentation: enforcing the N rule(s) the saved plan
  decided; not planning again` in the log.
- The plan's traffic flows are written out directly: `Traffic: writing the N
  flow(s) the saved plan decided; no new flows were drawn`.

This matters because both planners draw from the global `random` module, so
running either a second time produces a *different* plan, not the same one — a
live run had the preview walling off three subnets and the same scenario walling
off two others. Since the plan is what you review, what Flow builds its chain
against, and what pivot access places provider nodes for, the plan's decisions
are the ones that survive.

Consequences for the command line:

- The settings that shape segmentation are **plan-time** inputs. `--nat-mode`,
  `--seg-include-hosts`, `--dnat-prob`, `--allow-src-subnet-prob`,
  `--allow-dst-subnet-prob`, `--seg-accessible-by-pivot` and
  `--seg-pivot-provider` are applied when the plan is computed, and each also has
  an attribute on the Segmentation section (`nat_mode`, `include_hosts`,
  `dnat_probability`, `allow_src_subnet_prob`, `allow_dst_subnet_prob`,
  `accessible_by_pivot`, `pivot_provider`) so the setting travels with the
  scenario. Every plan-shaping setting has both forms; a test enforces that, so a
  new one cannot arrive XML-only.
- Passing one of them to `execute` against a plan built without it cannot be
  honoured. Execute says so, naming the settings it is ignoring and the values
  the plan holds, and uses the plan's. Regenerate the plan to change them.
- `--seg-allow-docker-ports` stays a run-time flag: it opens ports belonging to
  containers, which do not exist until execute.
- A plan saved before rules carried their scripts, or whose flow list was
  truncated for payload size, is refused with a logged reason and the planner
  runs as it used to. The run still succeeds; the mismatch is stated rather than
  hidden.

## Pivot access from the command line

When the scenario turns on "accessible by pivot" (or you pass
`--seg-accessible-by-pivot`), every subnet segmentation walls off is guaranteed
one reachable **provider**. The editor writes that switch as `pivot_enabled` on a
Segmentation **row**, not as a section attribute — a scenario-wide
`accessible_by_pivot` on the section is honoured too and outranks the rows, but
nothing in the UI produces it. Which kind of provider is tried first comes from
the row's `pivot_provider` (or `--seg-pivot-provider`); it reorders the default
preference rather than restricting it, so a subnet whose only way in is a
vulnerability still gets one. Provider nodes that have to be *added* are created
during the topology build, so they exist by `topo` — not at segmentation time.

What to look for in an execute log:

```
Pivot provider images ready: lscr.io/linuxserver/openssh-server:latest=cached
Pivot access: 1 provider(s) across 1 walled-off subnet(s) (0 reused, 0 need SSH, 1 to add)
Pivot access: pivot-10-42-249-0 is reachable at 10.42.249.4 (ssh:2222) [node added for this], opening 10.42.249.0/24
```

A subnet that could not be given a provider is logged at WARNING, naming the
subnet and the reason — that scenario has challenges nobody can start.

Two things worth knowing:

- The provider's port follows its **image**, and the default image is a rootless
  sshd on **2222**, not 22. Override both together
  (`CORETG_PIVOT_SSH_IMAGE` / `CORETG_PIVOT_SSH_PORT`) if you mirror your own.
- Docker nodes never need the internet at execute: the image is resolved
  present, then from a pre-seeded `docker save` tarball in
  `CORETG_PIVOT_IMAGE_CACHE_DIR` (default `/opt/coretg/images`), then pulled
  once. Images are resolved **before** the topology build, because CORE starts a
  Docker node the moment it is added.

Nested pivots — a provider you can only reach by working through another — are
not supported. Every provider is opened to `0.0.0.0/0` on its entry port, so all
of them are directly reachable and the ordering between them is carried by the
challenges. Where a scenario's segmentation implies an ordering, it is reported
as `nested_candidates` and logged.

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
- HITL is controlled by the scenario XML. `execute` and `topo` require a saved `HardwareInLoop/Interface` only when that XML has `HardwareInLoop enabled="true"`. A missing or disabled HITL section means no HITL attachment, even if VM-mode HITL defaults exist in the environment.
- If required VM connection fields are missing, the CLI stops early and reports what is missing.

Examples of required VM-mode data:

- CORE gRPC host and port
- SSH host and port
- SSH username and password
- for `new` XML generation when VM-mode HITL defaults are enabled, a configured `CORETG_VM_MODE_HITL_CORE_IFX_NAME`

Native mode behaves differently:

- native mode can still rely on `.scenarioforge.env` defaults without requiring saved VM-specific XML metadata
- missing or disabled HITL config in native mode does not block normal CLI topology or execute phases; it just means no HITL attachment is created

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

- Run `preview-plan` first for that XML/scenario. The resulting `PlanPreview` is embedded in the XML; pass that same XML to subsequent Flow commands.

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
- `flag-sequencing` depends on an existing XML-embedded `PlanPreview`.
- The CLI is designed for ScenarioForge planning XML, not for raw CORE session XML as a planning input.
- Nested pivots are not supported: a provider behind another provider is flattened, and the ordering is carried by the challenges rather than the network.
- Segmentation settings supplied only at execute cannot be honoured against a plan built without them; execute names them and uses the plan's values.
