# AI Prompt Templates for Generator Authoring

This page gives copy/paste prompt scaffolds for authoring both:

- `flag-generator`
- `flag-node-generator`

The goal is fast authoring with stable **Test vs Execute parity**.

Use this page together with:
- [docs/GENERATOR_AUTHORING.md](GENERATOR_AUTHORING.md)
- [docs/FLAG_GENERATORS.md](FLAG_GENERATORS.md)
- [docs/prompts/prompt_sample_context_generator.txt](prompts/prompt_sample_context_generator.txt)

For fastest starts, copy/paste the reusable context file above first, then append one of the templates on this page.

---

## AI Scaffolding workflow (recommended)

Use this sequence every time:

1. Start from a template scaffold (`generator_templates/...`).
2. Create or update `manifest.yaml` first (inputs/artifacts/hints/injects).
3. Include `access_instructions` for any participant mount/connect/read/exploit workflow.
4. Include `inject_candidate_paths` when injected artifacts should land in one of several plausible absolute directories.
5. Prompt AI to modify only `generator.py` (and optionally README).
6. Run local runner test (`scripts/run_flag_generator.py`).
7. Install as Generator Pack and validate Execute parity.
8. If you add or change backend routes, update both `API.md` and `docs/openapi.yaml` in the same change.

If you skip steps 2 or 5, most drift bugs come back.

## API doc sync rule (AI scaffolding)

When AI-generated changes touch backend HTTP behavior, keep docs in lockstep:

- Update human-readable API reference: `API.md`
- Update machine-readable contract: `docs/openapi.yaml`
- Include behavior-level notes when clients depend on them (for example polling termination semantics or selection-priority rules)

This prevents UI/client drift and keeps generated integrations accurate.

## Using ChatGPT or Claude Desktop

Use a simple 3-part prompt in one chat thread per generator:

1. **Context block**: paste [docs/prompts/prompt_sample_context_generator.txt](prompts/prompt_sample_context_generator.txt) with filled `TYPE`, `SOURCE_ID`, and target behavior.
2. **Ground truth block**: paste current `manifest.yaml` + scaffolded `generator.py` (and current `docker-compose.yml` for node generators).
3. **Task block**: append the matching template below (`flag-generator` or `flag-node-generator`).

Recommended loop:

1. Ask for **generator.py only**.
2. Run `scripts/run_flag_generator.py` locally and verify `outputs.json.outputs` keys exactly match `artifacts.produces`.
3. If it fails, reply with only the failing error/diff and ask for a minimal fix.
4. After code passes, request optional README/manifest polish.

Reliability tips for desktop chat tools:

- Keep one conversation per generator (avoid mixing unrelated generators).
- Re-paste hard requirements each turn if the thread is long (runtime contract, output schema, compose constraints).
- Keep output format strict: `generator.py` only by default; request multi-file output only when needed.

### Starter message (copy/paste)

```text
You are helping me implement a ScenarioForge generator.

I will give you 3 blocks in this order:
1) Context block (filled from docs/prompts/prompt_sample_context_generator.txt)
2) Ground-truth block (manifest.yaml + current generator.py)
3) Task block (flag-generator or flag-node-generator template)

Global rules:
- Follow the runtime contract exactly (/inputs/config.json -> /outputs/outputs.json).
- Keep outputs deterministic for same inputs.
- Ensure outputs.json.outputs keys exactly match artifacts.produces.
- Use Python standard library only unless I explicitly allow more.
- Keep imports at module scope.
- For solver-facing runtime inputs participants must use on the first challenge but cannot reasonably discover yet, set `flow_supply_when_first: true` in manifest/runtime_inputs.
- Do not mark purely internal entropy/config fields with `flow_supply_when_first`.

Output format for this turn:
- Reply with ONLY full generator.py content.

If anything is ambiguous, choose the minimal deterministic behavior and briefly note assumptions in code comments only when essential.
```

### Starter message: flag-node-generator (copy/paste)

```text
You are helping me implement a ScenarioForge flag-node-generator.

I will give you 3 blocks in this order:
1) Context block (filled from docs/prompts/prompt_sample_context_generator.txt)
2) Ground-truth block (manifest.yaml + current generator.py + current docker-compose.yml if present)
3) Task block (Prompt Template: flag-node-generator)

Hard constraints:
- Read /inputs/config.json.
- Write /outputs/docker-compose.yml.
- Write /outputs/outputs.json including:
  - generator_id
  - File(path): docker-compose.yml
  - Flag(flag_id)
- Ensure outputs.json.outputs keys exactly match artifacts.produces.
- Keep deterministic behavior for same inputs.
- Use Python standard library only unless I explicitly allow more.

CORE compose guardrails (strict):
- Do not emit ${...} in docker-compose.yml.
- Do not depend on ports: for in-CORE peer connectivity.
- Assume network_mode:none and no outbound internet may apply.

Output format for this turn:
- Reply with ONLY full generator.py content.
```

### Quick usage snippet (copy/paste)

```text
1) Open docs/prompts/prompt_sample_context_generator.txt and fill TYPE, SOURCE_ID, and behavior.
2) Paste your manifest.yaml and current generator.py below it.
3) Append either:
  - "Prompt Template: flag-generator", or
  - "Prompt Template: flag-node-generator"
4) Keep the AI output format strict:
  - generator.py only (default)
  - or generator.py + manifest.yaml + README.md when explicitly requested
5) Run scripts/run_flag_generator.py and confirm outputs.json matches artifacts.produces exactly.
```

---

## What you should paste into the AI

For best results, paste:

- Your target **generator type**: `flag-generator` or `flag-node-generator`
- Your intended generator **source id** (the `id` in `manifest.yaml`)
- Your intended artifact **inputs/outputs** (Generator Builder labels these as “Inputs (artifacts)” and “Outputs (artifacts)”; underlying schemas may call them `requires`/`produces`)
- Your `manifest.yaml` (or at least the relevant fields: `id`, `kind`, `runtime`, `inputs`, `artifacts`, `hint_levels`, `injects`)
- Any `access_instructions` and `inject_candidate_paths` expectations
- The current scaffolded `generator.py` (and optionally your `docker-compose.yml` / README)
- A short description of the generator behavior you want
- Whether you want a minimal MVP or a richer implementation

When using Generator Builder intent overrides or natural-language prompt specs, express participant hints as structured levels:

```text
Hint levels:
low: Target: {{NEXT_NODE_IP}}
medium: Artifact or service: {{OUTPUT.File(path)}}
high: Use the access instructions and README.md for the complete workflow.
```

The compact one-line form is also accepted: `Hint levels: low: Target: {{NEXT_NODE_IP}}; medium: Artifact: {{OUTPUT.File(path)}}; high: Use README.md.`

---

## Non‑negotiable runtime contract

Tell the AI these are strict requirements:

- Read config JSON from `/inputs/config.json`.
- Write `/outputs/outputs.json` with:

```json
{
  "generator_id": "<SOME STABLE STRING>",
  "outputs": {
    "Flag(flag_id)": "FLAG{...}",
    "<other_artifact_keys>": "..."
  }
}
```

- `generator_id` is required by schema and used as provenance.
  - Generator Packs: the Web UI assigns a *new numeric installed ID* at install time, so don’t hardcode the installed ID into your generator; using your source manifest `id` is acceptable.
- Outputs should be **deterministic** for the same inputs.
- `outputs.json.outputs` must always include `Flag(flag_id)` (required by schema).
- `hint.txt` is optional. Prefer `hint_levels` in the catalog; only write `/outputs/hint.txt` if you explicitly need a standalone hint file.
- Include `hint_levels.low`, `hint_levels.medium`, and `hint_levels.high`, with at least one non-empty hint in each level: low can reveal an IP/node, medium can reveal a port/service/file/artifact, and high can point to access instructions or README guidance.
- Mark runtime inputs with `flow_supply_when_first: true` only when participants must use that value on the first challenge and cannot reasonably infer or find it before solving.
- Flow labels `flow_supply_when_first` values as `Seq 1 required` Initial Facts, marks them in Participant/Facilitator guide fact tables, and includes them in the first participant hints.
- Treat Flow-synthesized values as **inputs**, not artifacts:
  - Never put `seed`, `secret`, `node_name`, `flag_prefix` into artifact inputs (aka `requires`).
- Input descriptors default to `required: true` when omitted. Set `required: false` for optional runtime inputs.
- Keep shared imports (`json`, `sys`, etc.) at module scope; avoid function-local imports in enclosing scopes that define nested helpers.
- Exit non-zero on true failure; include clear stderr messages for missing required inputs.

If the generator needs to deliver a file/binary to participants:

- Write the file(s) under `/outputs/artifacts/...` (so they appear under `<out_dir>/artifacts/...`).
- Set `outputs.json.outputs["File(path)"]` to a path relative to `/outputs` (for example `artifacts/my_binary`), not an absolute `/outputs/artifacts/my_binary` path.
- Allowlist injected files:
  - Manifest workflow: declare `injects` in `manifest.yaml`.
  - Prefer referencing an **output artifact key** so the allowlist stays stable, e.g. `injects: ["File(path)"]`.
  - `injects` supports resolving output keys via `outputs.json` (e.g. `File(path)` -> `artifacts/my_binary`).

Execution parity requirements (must include in generated code/README):

- The generator must behave the same under UI **Test** and full **Execute** paths.
- Do not rely on package-manager/internet availability for successful generator completion.
- Include both verification commands in README:
  1. local runner test (`scripts/run_flag_generator.py`)
  2. installed-pack execute check (run through Flow/Execute and verify no generator warnings in run log)

Compose + CORE docker-node constraints (important for `flag-node-generator` outputs):

- Compose files attached to CORE docker nodes are treated as templates by CORE (Mako). Avoid docker-compose env interpolation like `${VAR}` / `${VAR:-default}` in the compose you ship unless you know it will be resolved before CORE consumes it.
- Assume containers may run with `network_mode: none` enforced and may have no outbound internet.
- Do not rely on `ports:` for connectivity between CORE nodes. Clients should connect to the server using the server node’s CORE IP.
- Prefer single-port protocols (one TCP port) to reduce segmentation/firewall complexity.
- If startup uses relative script paths (for example `ruby web.rb`, `python app.py`, `./run.sh`), set a compatible `working_dir` explicitly or use absolute script paths.
- Keep command/working_dir/mounts consistent: mounted files must resolve from the chosen `working_dir` (or command must use absolute paths).
- Do not assume image default WORKDIR is always preserved after compose transformation.
- Default runtime policy is `CORETG_COMPOSE_FORCE_ROOT_WORKDIR=auto`; some base/known-safe images may still be forced to `/`.
- If operators set `CORETG_COMPOSE_FORCE_ROOT_WORKDIR=1`, all services may be forced to `/`; prefer absolute script paths when feasible.

---

## Optional manifest field: access_instructions

When your generator outputs artifacts that participants need to interact with (mount, connect, exploit, read files), you can include `access_instructions` in your manifest to guide them.

**Usage:**

- Add optional `access_instructions` section to `manifest.yaml`
- Define multi-step walkthrough with variable substitution
- Variables like `{{PORT}}`, `{{NODE}}`, `{{PATH}}` resolve from artifact outputs

**Example manifest fragment:**

```yaml
access_instructions:
  title: "NFS Mount & Access"
  steps:
    - step: 1
      title: "Mount the NFS export"
      instructions: |
        From another container, mount the NFS service:
        ```bash
        apt-get install -y nfs-common
        mount -t nfs4 -o vers=4,port={{PORT}} {{NODE}}:{{PATH}} /mnt/nfs
        ```
      vars:
        PORT: "PortForward(host, port)"
        NODE: "node_name"
        PATH: "Directory(host, path)"
    - step: 2
      title: "Examine files"
      instructions: |
        ```bash
        ls -la /mnt/nfs/
        cat /mnt/nfs/flag.txt
        ```
```

**Key points:**

- `title`: section heading in participant/facilitator guides
- `steps[]`: ordered list of action steps
- `step`: number (1, 2, 3...)
- `title`: step name
- `instructions`: markdown (supports code blocks with backticks)
- `vars`: optional dict mapping placeholder names to artifact keys
- Variable resolution: `{{PORT}}` → value of `PortForward(host, port)` from outputs, `{{NODE}}` → value of `node_name`, etc.

**Fallback behavior:**

- If you omit `access_instructions`, guides use artifact-pattern heuristics
- Detecting `Directory` + `PortForward` → suggests mounting/file discovery
- Custom instructions always override heuristics

**When to include:**

- NFS/mounted services: guide mounting steps and file location
- Database services: guide connection + query steps
- Web services: guide endpoint discovery and exploitation
- RCE services: guide payload delivery and output capture

---

## Quick AI output checklist

Before accepting AI output, check:

- `generator.py` reads only `/inputs/config.json` and writes only under `/outputs`.
- `outputs.json` always contains `generator_id` and `Flag(flag_id)`.
- Manifest artifact keys match actual `outputs.json.outputs` keys exactly.
- Any `injects` key resolves to a real output file path.
- `access_instructions` exists when a participant needs concrete mount/connect/read/exploit steps.
- `inject_candidate_paths` entries are absolute paths and never contain `..`.
- No fragile internet/package-manager dependency for core success path.
- No `${...}` in emitted compose for node generators.
- Relative startup commands in compose have explicit safe `working_dir` (or absolute paths).

---

## Prompt Template: flag-generator

Paste this, then fill in the placeholders.

```text
You are helping me implement a ScenarioForge generator.

TYPE: flag-generator
SOURCE_ID: <my_source_id>

Hard requirements (do not violate):
- Read /inputs/config.json (JSON).
- Write /outputs/outputs.json with:
  {
    "generator_id": "<SOME STABLE STRING>",
    "outputs": {
      "Flag(flag_id)": "FLAG{...}",
      "...": "..."
    }
  }
- generator_id requirements:
  - Do not assume the installed numeric ID is stable; using SOURCE_ID is acceptable.
- Do NOT write /outputs/hint.txt unless I explicitly ask; prefer hint_levels in the catalog.
- Include low/medium/high hint_levels in manifest.yaml, with at least one non-empty hint in each level: IP or node, service/port/file/artifact, then access instructions or README guidance.
- Deterministic outputs: same (seed, secret, flag_prefix) => same outputs.
- Inputs (NOT artifacts): seed (required), secret (required), flag_prefix (optional).
- Mark any solver-facing runtime input the participant must use but cannot reasonably discover before the first solve with flow_supply_when_first.
- Keep implementation minimal and deterministic unless I explicitly ask for extras.

If this generator outputs a file/binary:
- Write it under /outputs/artifacts/<name>
- Put a path to it in outputs.json.outputs relative to /outputs (example key: File(path) => artifacts/<name>, not /outputs/artifacts/<name>)

Catalog intent:
- inputs artifacts: <list artifacts or '(none)'>
- outputs artifacts: <list artifacts; must include 'Flag(flag_id)'>

Artifact input strictness:
- Default to optional inputs.
- Mark any input as required only if the generator truly cannot run without it.
- For artifact inputs, put optional ones in `artifacts.optional_requires` and required ones in `artifacts.requires`.

Task:
- Modify ONLY generator.py to implement this behavior: <describe behavior>.
- Use only the Python standard library.
- Keep error messages clear when required inputs are missing.
- Keep imports at module scope; do not add function-local `import json`/`import sys` in scopes with nested helpers.

Here is my current scaffolded generator.py:

<PASTE generator.py HERE>

Output:
- Reply with ONLY the full updated generator.py content.

Self-check before output:
- Ensure outputs keys match my intended outputs list exactly.
- Ensure outputs.json includes generator_id and Flag(flag_id).
- Ensure file outputs are relative to /outputs (for example: artifacts/<file>).
```

---

## Prompt Template: flag-node-generator

Paste this, then fill in the placeholders.

```text
You are helping me implement a ScenarioForge generator.

TYPE: flag-node-generator
SOURCE_ID: <my_source_id>

Hard requirements (do not violate):
- Read /inputs/config.json (JSON).
- Write a per-node docker compose file to /outputs/docker-compose.yml.
- Write /outputs/outputs.json with:
  {
    "generator_id": "<SOME STABLE STRING>",
    "outputs": {
      "File(path)": "docker-compose.yml",
      "Flag(flag_id)": "FLAG{...}",
      "...": "..."
    }
  }
- generator_id requirements:
  - Do not assume the installed numeric ID is stable; using SOURCE_ID is acceptable.
- Deterministic outputs: same (seed, node_name, flag_prefix) => same outputs and compose.
- Inputs (NOT artifacts): seed (required), node_name (required), flag_prefix (optional).
- Mark any solver-facing runtime input the participant must use but cannot reasonably discover before the first solve with flow_supply_when_first.
- Keep implementation minimal and deterministic unless I explicitly ask for extras.

CORE docker-node constraints:
- Avoid `${...}` patterns in the emitted docker-compose.yml (CORE treats compose as a template and `${...}` can be interpreted as Mako).
- Do not rely on `ports:` for in-CORE reachability; clients in CORE should connect to the node’s CORE IP.
- Assume `network_mode: none` may be enforced; do not assume default Docker networking or internet access.

Catalog intent:
- inputs artifacts: <list artifacts or '(none)'>
- outputs artifacts: <list artifacts; typically includes 'File(path)' and 'Flag(flag_id)'>

Artifact input strictness:
- Default to optional inputs.
- Mark any input as required only if the generator truly cannot run without it.

Task:
- Modify ONLY generator.py to implement this behavior: <describe behavior>.
- The docker-compose.yml you write should define the node service(s) needed for the challenge.
- Use only the Python standard library.
- Keep imports at module scope; do not add function-local `import json`/`import sys` in scopes with nested helpers.

Here is my current scaffolded generator.py:

<PASTE generator.py HERE>

Output:
- Reply with ONLY the full updated generator.py content.

Self-check before output:
- Ensure outputs keys match my intended outputs list exactly.
- Ensure outputs.json includes generator_id, File(path), and Flag(flag_id).
- Ensure generated docker-compose.yml avoids `${...}`.
```

---

## Optional: prompt add-ons (use when needed)

### Include README updates

If you want the AI to update the README too:

```text
Also update README.md to explain:
- What artifact inputs/outputs it uses
- How it is tested locally using scripts/run_flag_generator.py
- Any environment variables or assumptions
Output BOTH files: generator.py then README.md (clearly separated).
```

### Make “outputs” align to the catalog

If you already created an Outputs (artifacts) list in the Generator Builder UI:

```text
Important: The keys in outputs.json.outputs MUST exactly match my intended outputs list.
If you add new outputs, tell me what catalog changes I should make.
```

---

## Notes / common failure modes

- Don’t let the AI introduce third-party deps unless you explicitly want that.
- Ensure `outputs.json` is always written even on “success with minimal outputs”.
- Always include `Flag(flag_id)` in produced outputs.
- Keep file paths exactly `/inputs/config.json` and `/outputs/...`.
- Prefer fact-ontology keys (e.g., `Credential(user,password)`, `Knowledge(ip)`, `File(path)`) over ad-hoc keys (e.g., `user`, `ip`).
