## Scenario XML Schema (Application-Level)

This document is the current wire-format reference for scenario editor XML
consumed and emitted by the Web UI and CLI. It covers the planning sections and
the runtime metadata persisted by the application.

`schemas/xml/scenarios.xsd` models the full current format, including the
runtime metadata blocks (`CoreConnection`, `HardwareInLoop`, `AIGenerator`,
`PlanPreview`, `FlagSequencing`) and the `Flag Node Generators` section. The
JSON payloads inside `AIGenerator`, `FlowState`, `FlowExpansion`, and
`PlanPreview` are opaque strings at the XSD level, and cross-attribute
semantics are not enforceable in XSD 1.0, so the application parser and its
preview/Flow/execute preflight checks remain authoritative for semantics.

### Root Elements

Two root forms are accepted:

1. `<Scenarios>` containing one or more `<Scenario>` elements and an optional
   document-level `<CoreConnection>`.
2. A lone `<ScenarioEditor>` root (single-scenario/legacy files). Its scenario
   name is inferred from the file name and it cannot carry a document-level
   `<CoreConnection>`.

The XML is namespace-less. Unknown runtime attributes are generally preserved
only when explicitly handled by the application; do not use the file as a
general extension container.

### `<Scenario>` Attributes

| Attribute | Type | Purpose |
|-----------|------|---------|
| `name` | string (required) | Scenario display / selection name. |
| `density_count` | non-negative int (optional) | Base host-pool count used with Node Information rows. |
| `density_count_min_enabled`, `density_count_min` | boolean + non-negative int (optional) | Enabled lower bound for the scenario host pool. |
| `density_count_max_enabled`, `density_count_max` | boolean + non-negative int (optional) | Enabled upper bound for the scenario host pool. |
| `scenario_total_nodes` | non-negative int (derived) | Aggregate planned node count written by the UI. It is informational; the planner recalculates counts. |
| `base_nodes` | non-negative int (derived) | Legacy/summary field written by the UI. Do not use it as the source of planned counts. |

### `<ScenarioEditor>`
Wraps a base scenario reference and a sequence of planning sections.

The Web UI emits these children in this order; readers should locate them by
element name rather than depending on order:

| Child | Occurrence | Contents |
|-------|------------|----------|
| `<BaseScenario filepath="..."/>` | required in files emitted by the UI | Optional absolute or relative CORE session XML base-layout path. |
| `<HardwareInLoop>` | optional | Per-scenario CORE, HITL, Proxmox, participant, and interface configuration. |
| `<AIGenerator>` | optional | JSON object containing sanitized AI-generator draft/provider state. It is UI state, not executable scenario logic. |
| `<FlagSequencing>` | optional | Flow state and zero or more Flow expansion audit records, each JSON encoded. |
| `<PlanPreview>` | optional | JSON object containing the generated plan and full topology preview. |
| `<section>` | zero or more | Planning-section rows. |

`PlanPreview`, `FlowState`, `FlowExpansion`, and `AIGenerator` contain JSON as
element text. A malformed JSON value is retained as raw text by tolerant reads,
but it cannot be used for preview/Flow execution.

### Runtime Metadata And Ground Truth

Saved WebUI XML is the ground truth for later CLI phases. A normal saved file
has a document-level CORE connection plus a named scenario:

```xml
<Scenarios>
  <CoreConnection host="localhost" port="50051"
    ssh_enabled="true" ssh_host="core-vm.example" ssh_port="22"
    ssh_username="corevm" venv_bin="/opt/core/venv/bin" />
  <Scenario name="Scenario 1">
    <ScenarioEditor>
      <BaseScenario filepath="" />
      <HardwareInLoop enabled="false">
        <CoreConnection ... />
      </HardwareInLoop>
      <FlagSequencing>
        <FlowState>{"flags_enabled":false,"chain_ids":[]}</FlowState>
        <FlowExpansion>{"request_id":"..."}</FlowExpansion>
      </FlagSequencing>
      <PlanPreview>{"full_preview":{},"metadata":{"seed":12345}}</PlanPreview>
      <!-- planning sections -->
    </ScenarioEditor>
  </Scenario>
</Scenarios>
```

#### `<CoreConnection>`

The document-level connection supplies the default execution target. A nested
`HardwareInLoop/CoreConnection` supplies the scenario-specific target and is
merged with the document-level connection when needed. The UI writes the common
attributes `host`, `port`, `ssh_enabled`, `ssh_host`, `ssh_port`,
`ssh_username`, and `venv_bin`; it writes `ssh_password` only when a password
is configured. It can also preserve connection/VM metadata such as
`vm_key`, `vm_name`, `vm_node`, `core_secret_id`, `validated`, and
`venv_user_override`.

`host`/`port` are the CORE gRPC endpoint. `ssh_*` attributes are the remote
management endpoint and should not be inferred from a gRPC address. At execute
time the Web UI synchronizes its validated target into the saved XML before
invoking the CLI.

#### `<HardwareInLoop>`

This optional element is emitted when HITL is enabled or when per-scenario
connection, interface, Proxmox, or participant information exists. Its
attributes are `enabled`, optional `bridge_validated` and
`bridge_validated_at`, and optional `participant_proxmox_url`. It may contain:

* `<CoreConnection .../>` — the per-scenario target described above.
* `<ProxmoxConnection .../>` — Proxmox UI state: `url`, `port`, `verify_ssl`,
  `secret_id`, `validated`, `last_validated_at`, `stored_at`, `username`,
  `remember_credentials`, and `last_message` when available.
* `<Interface .../>` — one physical/external attachment. `name` is required;
  supported attributes include `alias`, `mac`, `core_bridge`, `attachment`,
  comma-separated `ipv4`/`ipv6`, `pve_*` target fields, and `ext_*` external
  VM fields. `attachment` normalizes to `existing_router`, `existing_switch`,
  `new_router`, or `proxmox_vm`; the default is `existing_router`.

#### Preview and Flow JSON

`PlanPreview` is the saved topology preview used by `preview-plan`, `topo`, and
`execute` when no separate preview file is supplied. `FlagSequencing/FlowState`
is the authoritative saved Flow state, including the selected chain,
assignments, resolved values, and runtime artifact/inject locations.
`PlanPreview.metadata.flow`, when present, is a mirror for UI compatibility and
must agree with `FlowState`; the persistence path writes both atomically.
`FlowExpansion` is a repeatable JSON audit record for a confirmed Flow-driven
Docker-capacity expansion.

Do not regenerate or replace the XML between Generate, Flow, and Execute. A
stale preview, a `topology_dirty` Flow state, or missing Flow artifacts is an
execute preflight error.

### Credential Handling

`CoreConnection/@ssh_password` is intentionally embedded when remote standalone
CLI execution needs it. Credential-bearing XML must be treated as a secret:

* write it atomically with file mode `0600`
* keep its containing output directory private
* redact the password before adding XML to logs, AI prompts, reports, archives,
  or issue attachments

The WebUI backend helper `_write_xml_tree_atomic` applies the required file mode
when a password is present.

### `<section>` Attributes

All sections share a common element name and are distinguished by `name`. The
current writer emits:

| Section name | Purpose |
|--------------|---------|
| `Node Information` | Host role/count planning. |
| `Routing` | Router protocol/count and aggregation policy. |
| `Services` | Service selection/count planning. |
| `Traffic` | Traffic generator selection and parameters. |
| `Vulnerabilities` | Vulnerability selection/count planning. |
| `Flag Node Generators` | Optional topology-node generator selection. |
| `Segmentation` | Segmentation and optional pivot requirements. |
| `Notes` | Free-form user notes; contains `<notes>` rather than `<item>`. |

`Events` is accepted by legacy planning-only XSD files but is not emitted by the
current Web UI writer.

Common attributes:
| Attribute | Applies | Meaning |
|-----------|--------|---------|
| `name` | all (required) | Section discriminator. |
| `density` | Routing, Services, Traffic, Vulnerabilities, Flag Node Generators, Segmentation | Planning density. Routing treats values `>= 1` as an absolute derived router count; Vulnerabilities and Flag Node Generators clamp density-derived count to 1.0. Other consumers apply section-specific behavior. |
| `node_count_min_enabled`, `node_count_min` | Any non-Notes section | Enabled lower bound for that section's count. |
| `node_count_max_enabled`, `node_count_max` | Any non-Notes section | Enabled upper bound for that section's count. |

Additive planning metadata (optional – written by UI for round‑trip):
| Attribute | Section(s) | Meaning |
|-----------|------------|---------|
| `base_nodes` | Node Information | Base (density) host pool before proportional distribution. |
| `additive_nodes` | Node Information | Sum of host Count rows. |
| `combined_nodes` | Node Information | `base_nodes + additive_nodes`. |
| `weight_rows` | Node Info, Routing, Vulnerabilities, Services, Traffic, Segmentation | Count of Weight (factor) rows. |
| `count_rows` | Same as above | Count of Count (absolute) rows. |
| `weight_sum` | Same as above | Raw sum of weight factors (pre-normalization). |
| `explicit_count` | Routing, Vulnerabilities (+ future) | Sum of absolute row counts. |
| `derived_count` | Routing, Vulnerabilities | Density-derived contribution. |
| `total_planned` | Routing, Vulnerabilities | `explicit_count + derived_count`. |
| `normalized_weight_sum` | Node Information | Summary written after normalizing Weight rows; normally `1.000` when Weight rows exist. |

### `<section name="Notes">`

May contain a single `<notes/>` element (empty or with textual content as element text). No `<item>` children here.

### `<item>` Rows

Each planning row across most sections is represented as `<item/>` with a superset of attributes (XSD 1.0 limitation). Unused attributes for a section are ignored.

Core multi-section attributes:
| Attribute | Meaning |
|-----------|---------|
| `selected` | Role/protocol/type name, depends on section. |
| `factor` | Weight (non-normalized) for proportional allocation (Weight rows). |
| `v_metric` | Either `Weight` or `Count`. When `Count`, `v_count` becomes an additive absolute amount. |
| `v_count` | Absolute amount (hosts, routers, vulnerabilities, etc.) depending on section context when `v_metric="Count"`. |

Routing-specific connectivity aggregation attributes:
| Attribute | Meaning |
|-----------|---------|
| `r2r_mode` | Router-to-router (R2R) connectivity style (`Uniform | NonUniform | Exact | Min`). Fallback: global mesh style. |
| `r2r_edges` | Degree/edge target when `r2r_mode="Exact"` (per-router degree goal). |
| `r2s_mode` | Router-to-switch (R2S) host aggregation mode (`Exact | NonUniform | aggregate | ratio`). Planner currently distinguishes special Exact=1 semantics, non-exact grouped modes, and generic ratio. |
| `r2s_edges` | Target switches (Exact) or approximate hosts-per-switch (aggregate/ratio) depending on mode. |
| `r2s_hosts_min` | Lower bound for hosts per generated switch (NonUniform grouping preview & builder). |
| `r2s_hosts_max` | Upper bound for hosts per generated switch. |

Traffic attributes (subset used by planner / future extensions):
| Attribute | Meaning |
|-----------|---------|
| `pattern` | Traffic pattern (`continuous|periodic|burst|poisson|ramp`). |
| `rate_kbps` | Rate in kilobytes per second (>=0). |
| `period_s` | Period (seconds). |
| `jitter_pct` | Jitter percentage (0–100). |

Vulnerabilities attributes (mode-dependent):
| Attribute | Applies when |
|-----------|-------------|
| `v_name`, `v_path` | `selected="Specific"` |

Vulnerabilities section attributes:
| Attribute | Meaning |
|-----------|---------|
| `flag_type` | Flag/artifact type for CTF-style injection (`text | image | file | custom`). Currently only `text` is implemented. |

Flag Node Generators item attributes (mode-dependent):

| Attribute | Applies when | Meaning |
|-----------|-------------|---------|
| `g_id` | `selected="Specific"` | Required selected flag-node-generator identifier. |
| `g_name` | `selected="Specific"` | Optional human-readable generator name. |

Segmentation pivot item attributes (when `pivot_enabled="true"`):

| Attribute | Meaning |
|-----------|---------|
| `pivot_provider` | Required or preferred provider role/node. `auto`, `none`, and `manual` read back as `random`. |
| `requires`, `produces` | Fact signatures used to express pivot input/output needs. |

The reader also recognizes legacy segmentation aliases and additional target
fields, but the current writer emits only the attributes above.

### Example (Current Single Scenario Without Preview or Flow State)

```xml
<Scenarios>
  <CoreConnection host="localhost" port="50051" ssh_enabled="false"
    ssh_host="localhost" ssh_port="22" ssh_username="" venv_bin="/opt/core/venv/bin" />
  <Scenario name="Scenario 1" density_count="50" scenario_total_nodes="56" base_nodes="0">
    <ScenarioEditor>
      <BaseScenario filepath=""/>
      <section name="Node Information" density_count="50" base_nodes="50" additive_nodes="2" combined_nodes="52" weight_rows="1" count_rows="2" weight_sum="1.000" normalized_weight_sum="1.000">
        <item selected="Random" factor="1.000"/>
        <item selected="Random" v_metric="Count" v_count="1"/>
        <item selected="Random" v_metric="Count" v_count="1"/>
      </section>
      <section name="Routing" density="0.050" explicit_count="4" derived_count="0" total_planned="4" weight_rows="0" count_rows="1" weight_sum="0.000">
        <item selected="RIP" v_metric="Count" v_count="4" r2r_mode="NonUniform" r2s_mode="NonUniform" r2s_hosts_min="3" r2s_hosts_max="3" />
      </section>
      <section name="Services" density="0.500" />
      <section name="Traffic" density="0.500" />
      <section name="Vulnerabilities" density="0.500" flag_type="text" />
      <section name="Flag Node Generators" density="0.500" />
      <section name="Segmentation" density="0.500" />
      <section name="Notes">
        <notes/>
      </section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>
```

### Planning-Core XSD Validation

The provided XSD can validate XML limited to its planning-section subset:

```bash
python - <<'PY'
import lxml.etree as ET
schema = ET.XMLSchema(file='schemas/xml/scenarios.xsd')
doc = ET.parse('examples/sample.xml')
schema.assertValid(doc)
print('OK')
PY
```

Do not use this XSD as the acceptance test for a current saved WebUI XML. It
will reject document-level `CoreConnection`, runtime metadata, and current
`Flag Node Generators` sections. For a full saved file, the acceptance checks
are application parsing plus the relevant preview, Flow, and execute preflight
validation.

### Forward Compatibility Guidance

If you add new per-item planning knobs, prefer optional attributes on `<item>` (keeps XSD adjustments localized). Document semantic constraints (e.g., value ranges, interactions with modes) in this file and extend `schemas/xml/scenarios.xsd` accordingly.

### Change Log (Schema Related)

| Date | Change |
|------|--------|
| 2026-07-20 | Reconciled this reference with the current writer/parser: document and scenario runtime metadata, AI/Flow expansion JSON, HITL/Proxmox interfaces, current planning sections, and count-bound attributes. |
| 2026-06-22 | Documented authoritative CoreConnection, HardwareInLoop, embedded PlanPreview/FlowState lifecycle, XSD coverage limits, and credential handling. |
| 2025-09-30 | Added routing connectivity attributes (r2r_mode, r2r_edges, r2s_mode, r2s_edges, r2s_hosts_min, r2s_hosts_max) and planning metadata attributes to XSD; published this schema summary. |

---
For deeper semantics (e.g., determinism guarantees, grouping preview) see `README.md` sections on Full Preview and Router Connectivity & Switch Aggregation.
