# Flag Generators: Vocabulary + Chaining

A **flag generator** is a runnable workload (currently `docker-compose`) that produces *information/capability* needed to reach the next node(s) in an Attack Flow.

For AI-assisted authoring templates and scaffolding workflow, start with:
- [docs/AI_PROMPT_TEMPLATES.md](AI_PROMPT_TEMPLATES.md)
- [Node-generator starter message](AI_PROMPT_TEMPLATES.md#starter-message-flag-node-generator-copypaste)
- [docs/GENERATOR_AUTHORING.md](GENERATOR_AUTHORING.md)

The Flow system treats each generator as a small contract:

- **inputs**: runtime config fields defined in `manifest.yaml` (`inputs[]`). These are not artifacts; `required: false` marks them optional.
- **artifacts.requires** / **artifacts.optional_requires**: artifact keys the generator needs (required vs optional for chaining).
- **artifacts.produces**: artifact keys the generator provides.
- **hint_levels**: low, medium, and high human-readable hints that tell the user where to go next.

Flow also supports **Initial Facts** and **Goal Facts** to steer sequencing. Initial facts are treated
as already-known inputs (including synthesized fields like `seed`, `node_name`, `flag_prefix`), while
Goal facts bias the sequencing algorithm toward outputs that satisfy them. Flag facts (`Flag(...)`) are
filtered from Initial/Goal facts.

UI note: the Flow Inputs table renders a `*` next to required items. Runtime inputs are required unless
`required: false` is explicitly set; artifact inputs are required when listed under `artifacts.requires`.
For any solver-facing runtime input a participant must use on sequence 1 or the first step of a parallel branch but cannot reasonably discover yet, set
`flow_supply_when_first: true`; Flow will supply and hint the value for that start sequence.

## Standard Key Vocabulary

Use these keys consistently so chains can be validated and composed.

### SSH
- `Credential(user)`
- `Credential(user, password)`
- `Credential(user, hash)`

### HTTP / Web
- `Credential(user, password)`
- `Token(service)`
- `APIKey(service)`

### Progress / Targets
- `Flag(flag_id)`
- `PartialFlag(flag_id, part)`

### Filesystem / Files
- `File(path)` (path to a generated file, typically under `artifacts/...`; store the value relative to `/outputs`, not as `/outputs/...`)
- `Directory(host, path)`

### Networking
- `Knowledge(value)` (e.g., an IP address)
- `Pivot(host)`
- `PortForward(host, port)`
- `InternalNetwork(subnet)`

## Pivoting Scenarios

Pivoting is configured as a Flow capability plus a segmentation exposure rule. The first challenge should produce an access artifact such as `WebRCE(app)`, `Shell(host)`, or `Pivot(host)`. Downstream internal targets should require that artifact, while their docker-compose service ports are marked as reachable only from the pivot source.

Scenario XML can include a `Pivoting` section:

```xml
<section name="Pivoting" density="1.0">
	<item
		selected="RCE Pivot"
		factor="1.0"
		pivot_node="jump-web"
		target_node="internal-db"
		target_ports="5432"
		target_protocols="tcp"
		target_exposure="pivot-only"
		source_scope="host"
		produces="Shell(jump-web),Pivot(jump-web)"
		requires="WebRCE(jump-web)" />
</section>
```

At runtime, ScenarioForge resolves `pivot_node`/`pivot_role` and `target_node`/`target_role` against actual CORE host names and roles. Matching docker-compose targets receive `SegmentationExposure=pivot-only`, `SegmentationSources=<pivot IP>`, and optional port/protocol filters before compose port allow rules are written. Existing compose targets remain public unless a pivot declaration narrows them.

The Web UI also supports a simplified shortcut from Segmentation rows. Turn on `Pivot`, then choose a provider (`Random`, `Vulnerability`, `Flag-Node-Generator`, or `Docker SSH`). The planner chooses the pivot source, target docker-compose nodes, target ports, protocols, source scope, and pivot-only exposure from the scenario's nodes and artifacts. When `Random` is selected, save resolves it to one concrete provider. Saved XML stores only the shortcut flag and resolved provider:

```xml
<section name="Segmentation" density="1.0">
	<item
		selected="Firewall"
		factor="1.0"
		pivot_enabled="true"
		pivot_provider="flag-node-generator" />
</section>
```

Those row attributes compile into runtime pivot metadata. `Random` is a save-time convenience that resolves deterministically to one of the concrete providers. Docker SSH assigns a built-in OpenSSH docker-compose container to the pivot source. This avoids using CORE's host-backed SSH service and keeps the pivot shell inside the container filesystem.

Runtime pivot metadata also records the sequencing contract: the pivot source produces `Shell(host)` and `Pivot(host)` facts, while inferred downstream targets require `Pivot(host)`. This keeps generated Flow/Flag Sequencing chains solvable when pivot-only segmentation is enabled.

## Hint Levels

Every generator should include `hint_levels.low`, `hint_levels.medium`, and `hint_levels.high` arrays.

Flow will substitute these placeholders (if present):
- `{{THIS_NODE_NAME}}`, `{{THIS_NODE_ID}}`
- `{{NEXT_NODE_NAME}}`, `{{NEXT_NODE_ID}}`
- `{{NEXT_NODE_IP}}` (when available)
- `{{SCENARIO}}`

Example:

```yaml
hint_levels:
	low:
		- "Target: {{NEXT_NODE_IP}}"
	medium:
		- "Credential: {{OUTPUT.Credential(user,password)}}"
	high:
		- "Use the access instructions and README.md for the complete workflow."
```

Notes:
- Flow will automatically append an IP to `{{NEXT_NODE_NAME}}` when a next-node IP is known (e.g., `web01 (10.0.0.5)`), even if `{{NEXT_NODE_IP}}` is not explicitly present.
- For payload-specific files, you may still emit a `hint.txt` as challenge content, but Flow generator manifests should declare participant guidance with `hint_levels`.

## Schemas (Generator Authors)

This repo includes JSON schemas to make generator behavior consistent across both:
- **flag-generators** (artifacts inserted into existing docker nodes), and
- **flag-node-generators** (generators that emit a per-node docker-compose environment).

Files:
- `schemas/generators/generator_manifest_v1.schema.json` — schema for `manifest.yaml` (manifest_version: 1), including canonical input types.
- `schemas/generators/flag_generator_outputs.schema.json` — schema for the runtime `/outputs/outputs.json` manifest emitted by a generator.

### Output Placeholder Substitution

In addition to `{{THIS_*}}`/`{{NEXT_*}}` placeholders, Flow supports substituting runtime generator outputs into the hint:

- `{{OUTPUT.<key>}}`

Where `<key>` is a key inside `outputs.json` under the `outputs` object.

Example hint level entry:

`Credential: {{OUTPUT.Credential(user)}} / {{OUTPUT.Credential(user,password)}}`

## Injected artifacts (`injects`)

Some generators need to deliver a file/binary that will be mounted/copied into other containers (or uploaded for remote execution). Use the manifest `injects` allowlist.

Key rules:

- Prefer explicit delivery metadata in `outputs.json.outputs`:
	- `FlagDelivery(mode)` = `file` | `embedded` | `none` | `unknown`
	- `FlagFile(path)` when mode is `file`
- This lets runtime validation distinguish real flag files from embedded-flag artifacts.

Destination directory (optional):

- `injects: ["File(path) -> /opt/bin"]`
- If unspecified or invalid, files default to `/flow_injects`.

### Non-deterministic injection via `inject_candidate_paths`

To randomize where the injected file lands on each run, add `inject_candidate_paths` alongside `injects`:

```yaml
injects:
  - File(path)
inject_candidate_paths:
  - /opt/uploads
  - /var/www/html
  - /tmp/user_data
```

On each execution, one path is chosen at random as the destination directory (only applies when `injects` entries have no explicit `->` destination). Invalid or relative paths are silently ignored. Flow shows these candidates in the Injects override editor; leave the destination blank to keep random selection, or pick/type a destination to make that step explicit.

- `outputs.json.outputs.File(path) = "artifacts/challenge"`
- Do not emit `outputs.json.outputs.File(path) = "/outputs/artifacts/challenge"`.
- `manifest.yaml: injects: ["File(path)"]`

The runner will stage only allowlisted items into `<out_dir>/injected/`.

## Authoring guardrails for AI-generated generators

To reduce Test-vs-Execute drift, enforce these constraints when generating code with AI:

- Use **module-level imports** for shared modules (`json`, `sys`, etc.).
- Avoid function-local imports in scopes that also define nested helper functions.
- Treat package-manager/network setup as optional best-effort (do not make generator success depend on apt/apk availability).
- Ensure `outputs.json` and any `injects`-referenced files are deterministic and present before success exit.
- Validate both:
	- generator Test endpoint run (local)
	- generator Test endpoint run (remote CORE VM, when CORE credentials are provided in the UI)
	- full Execute run (remote CORE path)

## Practical build loop (generator + node-generator)

1. Define manifest inputs/artifacts first.
2. Generate or update `generator.py` with AI using strict templates.
3. Verify `outputs.json.outputs` keys exactly match `artifacts.produces`.
4. Verify `injects` entries resolve to real files (when used).
5. Validate locally with `scripts/run_flag_generator.py`.
6. Validate installed-pack Test and Execute parity.

Remote Test note:
- The Flag Catalog Test flow can run `scripts/run_flag_generator.py` on the CORE VM via SSH.
- This improves parity with Execute for environment/runtime differences, but it still validates generator runtime/output behavior (not full CORE topology/session startup).
