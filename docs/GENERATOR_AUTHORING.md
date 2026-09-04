# Generator Authoring Guide (Manifests + Generator Packs)

This repo supports **two generator families** used by the Flag Sequencing (Flow) system:

- **flag-generators**: run *on an existing Docker node* to produce artifacts (credentials, URLs, next-step hints, etc.).
- **flag-node-generators**: generate a **per-node `docker-compose.yml`** used to *create* a challenge node (SSH/HTTPS/NFS/local-file flag nodes, etc.).

Both families share the same runtime output contract: a machine-readable `outputs.json`.

AI prompt templates (copy/paste):
- [docs/AI_PROMPT_TEMPLATES.md](AI_PROMPT_TEMPLATES.md)

## 0) AI scaffolding quickstart

If you are using AI to create generators, use this minimal handoff packet:

- `manifest.yaml` (or at least `id`, `kind`, `runtime`, `inputs`, `artifacts`, `injects`, `hint_levels`)
- scaffolded `generator.py`
- expected artifact keys (`requires`, `optional_requires`, `produces`) drawn from the canonical ontology in [schemas/facts/fact_ontology_reference.yaml](../schemas/facts/fact_ontology_reference.yaml); fact keys are matched literally, so write `Credential(user,password)` with no space after the comma
- the flag delivery contract when the flag is not a plain readable file: `FlagDelivery(mode)` (`file` | `embedded` | `none` | `unknown`) plus `FlagFile(path)` when the mode is `file`
- the fact vocabulary the installed catalog actually uses: only require facts something enabled already produces (or that Flow synthesizes per step), and reuse the catalog's exact spelling. A require nothing satisfies drops the generator from every Flow candidate pool silently -- it is simply never selected. The Generator Builder now passes this vocabulary to the model automatically; when prompting elsewhere, paste the produced/required fact lists yourself.
- explicit statement of required vs optional runtime inputs, with `default` and `description` on each input so builder forms and local tests do not guess values
- optional `description_hints` (short author-facing phrases) to make the generator findable in the catalog
- mark solver-facing start-step runtime inputs with `flow_supply_when_first: true` when participants must use the value before solving sequence 1 or the first step of a parallel branch
- supplied start-step values are shown as `Seq N required` Initial Facts in Flow, in Participant/Facilitator guide fact tables, and as Sequence N required supplied-input hints for participants
- `access_instructions` when participants need concrete mount/connect/read/exploit steps
- `inject_candidate_paths` when injected artifacts should be copied into one of several plausible absolute destinations

Recommended prompt flow:

1. Ask AI to update only `generator.py`.
2. Ask AI to self-check output keys against manifest `artifacts.produces`.
3. Ask AI to update `manifest.yaml` only if output keys changed.
4. Ask AI to include or refresh `access_instructions` for any interactive service, credential, mount, file, or exploit workflow.
5. Run local `scripts/run_flag_generator.py` test.
6. Run installed-pack Execute parity check.
7. If route or API payload behavior changed during implementation, update `API.md` and `docs/openapi.yaml` before merge.

Use the copy/paste templates in [docs/AI_PROMPT_TEMPLATES.md](AI_PROMPT_TEMPLATES.md).
If you are using desktop chat tools, follow [Using ChatGPT or Claude Desktop](AI_PROMPT_TEMPLATES.md#using-chatgpt-or-claude-desktop).

---

## 1) How generators are discovered

### Catalog policy

ScenarioForge does not ship a starter generator catalog in the source tree. Generator catalogs are user-managed ZIP packs that are imported from the Flag Catalog page. This keeps curated or environment-specific challenge packs out of the repo while preserving the same manifest/runtime contract.

Use [generator_templates](../generator_templates) when authoring new packs, then package and import the resulting ZIP.

#### Portable catalog status and notes

A repository-level `pack.json` can ship curation and prior test evidence keyed
by the stable source ID. `catalog_item_defaults` applies to every generator;
entries in `catalog_items` override only the fields they declare:

```json
{
  "catalog_item_defaults": {
    "disabled": false,
    "persistent": true,
    "validated_ok": true,
    "validated_incomplete": false,
    "validated_at": "2026-08-12",
    "validation_source": "catalog test dataset"
  },
  "catalog_items": [
    {
      "kind": "flag-node-generator",
      "generator_id": "example_unvalidated",
      "disabled": true,
      "disabled_by_catalog": true,
      "validated_ok": null,
      "disabled_reason": "No successful test evidence is recorded."
    }
  ],
  "catalog_notes": [
    {
      "kind": "flag-node-generator",
      "generator_id": "example_unvalidated",
      "note": "Keep disabled until it passes the catalog test.",
      "note_color": "red"
    }
  ]
}
```

ScenarioForge applies this metadata during import and writes current values back
to `pack.json` when the pack is downloaded. Validation results,
enabled/disabled state, persistence, and user-authored notes and note colors
therefore survive an export/import round trip. Local missing-file or build-time
network checks remain authoritative: imported metadata cannot enable a
generator that the destination detects as unrunnable.

Vulnerability catalogs use the same portable fields in
`.scenarioforge/catalog_items.json`, keyed by `compose_rel`; their notes live in
`.scenarioforge/catalog_notes.json`. Catalog defaults may be declared in the
top-level `defaults` object, with per-recipe exceptions in `items`.

### Installed generators (Web UI + Flow)
The Web UI treats **installed generators** as the source of truth.

- Install location: `outputs/installed_generators/`
- Discovery: `manifest.yaml` / `manifest.yml` inside each generator directory
- Disable semantics:
  - Packs and individual generators can be disabled.
  - Disabled generators are hidden from Flow substitution and rejected at preview/execute time.

Installed generators are managed as **Generator Packs** (ZIP files) uploaded/imported from the Flag Catalog page.

### Local generator workspaces (developer workflow)
For local runner development, use an unpacked scratch workspace with the same Generator Pack layout:

- `flag_generators/<your_generator_dir>/manifest.yaml`
- `flag_node_generators/<your_generator_dir>/manifest.yaml`

Then zip/import the pack through the Flag Catalog page before using it in the Web UI or Flow. The repository does not ship root-level generator catalogs; if you create `flag_generators/` or `flag_node_generators/` locally for experimentation, keep them temporary and untracked.

---

## 2) The manifest format (`manifest_version: 1`)

Each generator directory contains a manifest file:

- `manifest.yaml` (preferred) or `manifest.yml`

Minimum viable manifest (flag-generator):

```yaml
manifest_version: 1
id: my_source_id
kind: flag-generator
name: My Generator
description: Emits deterministic SSH credentials.

runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator

inputs:
  - name: seed
    type: string
    required: true
  - name: secret
    type: string
    required: true
    sensitive: true
  - name: unlock_code
    type: string
    required: true
    sensitive: true
    flow_supply_when_first: true

artifacts:
  requires: []
  optional_requires: []
  produces:
    - Flag(flag_id)
    - Credential(user)
    - Credential(user, password)

hint_levels:
  low:
    - "Inspect the exposed service before moving to {{NEXT_NODE_NAME}}."
  medium:
    - "Credential: {{OUTPUT.Credential(user,password)}}"
  high:
    - "Work through the access instructions for this step in order."

# If you produce files/binaries that should be safe to mount into other containers.
injects:
  - File(path)

# Optional fixed env vars passed to the runtime.
env:
  SOME_FIXED_ENV: "value"
```

Notes:
- `kind` must be `flag-generator` or `flag-node-generator`.
- `inputs` is a list of input descriptors (used by UI forms and Flow). If `required` is omitted, it defaults to `true`.
- For any solver-facing runtime input a participant must use on sequence 1 or on the first step of a parallel branch but cannot reasonably discover yet, set `flow_supply_when_first: true`; Flow supplies a deterministic value and writes it into the matching start hint. Aside from those supplied values, a start hint names only the node and its address — see [What a participant is told](#what-a-participant-is-told-and-what-is-held-back).
- `artifacts.requires` / `artifacts.optional_requires` / `artifacts.produces` drive Flow dependency chaining.

### Input types (mandatory convention)
Generator input `type` values are normalized to a small canonical set. If your manifest omits `type` or uses an unknown value, it **falls back to** `string`.

Canonical values:
- `string`
- `int`, `float`, `number`
- `boolean`
- `json`
- `file` (or `path`/`filepath` aliases)
- `string_list`
- `file_list`

Schema reference:
- `schemas/generators/generator_manifest_v1.schema.json`

### Important: IDs are rewritten on install
When you install a Generator Pack via the Web UI, each generator is assigned a **new numeric** `id` (as a string) and the installed manifest is rewritten to use that numeric ID.

- The installed generator directory also contains `.coretg_pack.json` with:
  - `source_generator_id` (your original manifest `id`)
  - `generator_id` (the assigned installed numeric ID)

This means:
- Treat the manifest `id` in your source pack as a *source identifier*.
- Don’t assume it will remain stable after installation.

---

## 3) Runtime contract (what the generator writes)

Generators run with:

- `/inputs/config.json` mounted read-only
- `/outputs/` mounted read-write

Every run must write an `outputs.json` file in the output directory.

Schema:
- `schemas/generators/flag_generator_outputs.schema.json`

Minimum valid `outputs.json`:

```json
{
  "generator_id": "<some string>",
  "outputs": {
    "Flag(flag_id)": "FLAG{...}"
  }
}
```

Practical guidance on `generator_id`:
- The schema requires it, but it is currently treated as provenance/metadata.
- If your generator can know the invoked generator ID, write that.
- Otherwise, writing your source manifest ID is acceptable.

Notes:
- `outputs.json.outputs.Flag(flag_id)` is **required** by the schema.
- If you expose `File(path)` in `outputs.json.outputs`, store it as a path relative to `/outputs` (for example `artifacts/challenge.bin` or `docker-compose.yml`), not as an absolute `/outputs/...` path.
- Optional explicit delivery contract keys:
  - `FlagDelivery(mode)` = `file` | `embedded` | `none` | `unknown`
  - `FlagFile(path)` = relative/absolute path to the flag file when `FlagDelivery(mode)=file` (prefer a path relative to `/outputs` when the file is produced there)

Using these keys avoids ambiguity when a generator embeds the flag in another
artifact (for example, an ELF binary) instead of writing `flag.txt`.

---

## 4) Injected artifacts (`injects` allowlist)

If a generator produces files that should be safely mountable/copiable into other containers, use `injects` in the manifest.

How it works:

- Generators should write files under `/outputs/artifacts/...`.
- After the generator finishes, `scripts/run_flag_generator.py` **validates** the allowlist: every entry must resolve to a file that exists under `/outputs` (or `/outputs/artifacts`), and the run fails if one does not. It does not pre-stage files or rewrite compose at generate/resolve time -- staging and the copy into target containers happen later, when Flow materializes the step.
- If the generator produces a `docker-compose.yml`, relative bind mounts are rewritten to use a named volume with an **init-copy** service that copies allowlisted files into the volume before the main service runs.

`injects` entries can be:

- A relative path like `artifacts/my_binary` (prefix `artifacts/` is optional), or
- An **output artifact key** like `File(path)` which is resolved via `outputs.json.outputs`.

When using `File(path)` as an output key, the corresponding `outputs.json.outputs["File(path)"]` value **must** be relative to `/outputs` (for example `artifacts/my_binary`), not `/outputs/artifacts/my_binary`. An absolute value is not an injectable path: expansion drops the entry, so the run would otherwise succeed having staged nothing and the artifact would never reach a participant. The runner rejects it, and the Generator Builder catches the literal before it spends a container run.

Optional destination directory syntax:

- `artifacts/my_binary -> /opt/bin`
- `File(path) => /var/tmp`

The `->` / `=>` destination syntax above affects where the injected file is mounted or copied. It does not change the `outputs.json.outputs["File(path)"]` contract, which should remain relative to `/outputs`.

If no destination is provided (or it fails validation), files default to `/flow_injects`.

### Candidate injection paths (`inject_candidate_paths`)

If you want to offer several plausible destination directories for the injected artifact (so an author can place the file somewhere less obvious than the default), add `inject_candidate_paths` to your manifest:

```yaml
inject_candidate_paths:
  - /opt/uploads
  - /var/www/html
  - /srv/data
```

Rules:
- Each path must be an absolute path starting with `/`. Relative or `..`-containing entries are ignored.
- Candidate paths are **suggestions surfaced in the Flow Injects override editor**, not an automatic destination. They are *not* applied at random per run. Unless a candidate is explicitly selected, injects with no explicit `->` destination default to `/flow_injects`.
- An explicit `->` destination in `injects` always takes priority.
- Choosing a candidate in the Injects override editor records it as an explicit `src -> <candidate>` override for that step; both the copy step and the post-run inject validation then use that recorded destination (preserving any subdirectories in the source-relative path).

Example manifest fragment:

```yaml
injects:
  - File(path)
inject_candidate_paths:
  - /opt/uploads
  - /var/www/html
  - /tmp/user_data
```

---

## 4.1) Compose runtime contract (flag-node-generators)

When your generator emits `/outputs/docker-compose.yml`, treat these as hard compatibility rules:

- **If `command`/`entrypoint` uses relative script paths, set an explicit compatible `working_dir`.**
  - Example: `command: ruby web.rb ...` requires `working_dir: /usr/src` (or an equivalent directory where `web.rb` exists).
  - Example: `command: ["python", "app.py"]` should either set `working_dir` to the script directory or use an absolute path (`/app/app.py`).
- **Prefer absolute script paths in `command` where practical.**
  - Absolute paths reduce breakage if runtime policy changes `working_dir` for CORE service compatibility.
- **Do not assume image-default WORKDIR will always be preserved.**
  - Compose transformation may enforce runtime safety policies; author compose so startup remains deterministic.
- **Mount paths and command paths must agree.**
  - If you mount `./web.rb` to `/usr/src/web.rb`, the runtime command must resolve that file from the selected `working_dir` or use `/usr/src/web.rb` directly.

Current default behavior in ScenarioForge is conservative:

- `CORETG_COMPOSE_FORCE_ROOT_WORKDIR` defaults to `auto`.
- Base OS / known-safe images may still be forced to `working_dir: /`.
- Setting `CORETG_COMPOSE_FORCE_ROOT_WORKDIR=1` forces root workdir for all services and can break relative-path startup commands.

Author generators assuming transforms can happen, and make startup robust to them.

### Only the node-named service owns the network

CORE runs a Docker node's whole stack in **one network namespace**. It rewrites
every service except the node-named one to `network_mode: service:<node>`, and
manages the node's own namespace itself — that is where it attaches the veth and
the scenario address.

A container that joins another's namespace cannot own its own networking, and
Docker refuses to create it:

```
service:node:1 Error response from daemon: conflicting options:
              hostname and the container type network mode
service:node:1 Error response from daemon: conflicting options:
              port exposing and the container type network mode
```

The whole stack then sits in `created`, every node reports "not running", and
the cause appears only in the core-daemon journal. ScenarioForge strips
`hostname`, `ports`, `expose`, `dns`, `dns_search`, `dns_opt`, `extra_hosts`,
`mac_address`, `domainname` and `networks` from those services to prevent it,
merging their port intent into the node service where it is actually reachable.

You do not need to do anything for this to work, but do not rely on a secondary
service keeping its own hostname or published ports — it will not.

### Python you generate must run

Generators commonly build their challenge app by templating values into a `.py`
file. A very easy mistake is to paste JSON into Python source:

```python
# Wrong: json.dumps writes true/false/null, which are not Python.
CONFIG = __CONFIG_JSON__
APP_TEMPLATE.replace("__CONFIG_JSON__", json.dumps(app_config, indent=2))
```

Any config carrying a boolean then produces an app that fails at import with
`NameError: name 'true' is not defined`. That is not a syntax error, so the file
looks fine to a parser; the container simply crash-loops, CORE cannot read its
PID or attach an interface, and the session never leaves `configuration`.

Parse the JSON at runtime instead, which also keeps the formatting readable when
the app serves its own source as the challenge artifact:

```python
APP_TEMPLATE.replace("__CONFIG_JSON__",
                     'json.loads(r"""' + json.dumps(app_config, indent=2) + '""")')
```

The runner validates every `.py` a generator emits and fails the run with the
file and line rather than letting it reach a container:

```
[validation error] generator emitted Python that will not import:
app.py line 20: JSON literal 'true' used as Python (did you mean True?)
```

---

## 5) Hint levels and substitution

Manifests declare structured hints via:

- `hint_levels.low`, `hint_levels.medium`, and `hint_levels.high` (lists of strings shown as collapsible guide sections labeled `Hint Low`, `Hint Medium`, and `Hint High` — except for promoted first-step lines, which are labeled `Helpful Fact`; see below)

Use levels consistently and keep at least one non-empty entry in each level: low should be a light pointer such as an IP or node name, medium should reveal a port, service, filename, or artifact to inspect, and high should state the workflow outright — the step that solves the challenge.

**Write hints for someone who only has the deployed scenario.** Participants run
against the built environment; they cannot open your `manifest.yaml`, your
`README.md`, or the `docker-compose.yml` Flow deploys. A hint such as
`"Use the access instructions in this generator manifest."` or
`"README: generators/foo/README.md"` names something they have no way to reach,
so Flow filters those lines out of node cards and both guides. Spell out the
step instead:

```yaml
# Filtered out -- names files the participant cannot open.
high:
  - "See README.md for the complete workflow."

# Kept -- states what to actually do.
high:
  - "Mount the NFS export at /exports, then read flag.txt from the mount."
```

Flow substitutions include:

- `{{THIS_NODE_NAME}}`, `{{THIS_NODE_ID}}`
- `{{NEXT_NODE_NAME}}`, `{{NEXT_NODE_ID}}`
- `{{NEXT_NODE_IP}}` (when available)
- `{{SCENARIO}}`
- `{{OUTPUT.<key>}}` where `<key>` comes from `outputs.json.outputs`

### Next-node variables resolve to a *dependent* successor

A `{{NEXT_NODE_*}}` variable names the next step that actually consumes one of
this generator's outputs — not simply the next node in the emitted chain. Flow
places independent challenges on parallel stages, where no ordering exists
between them, so naming the positional neighbour would assert a gate the solver
never imposed.

When a step has no dependent successor, Flow removes the clause containing the
variable and keeps the rest of the hint:

```
"Inspect the vendor intake dropbox before moving to {{NEXT_NODE_NAME}}."
  -> parallel stage:  "Inspect the vendor intake dropbox."
  -> real dependency: "Inspect the vendor intake dropbox before moving to docker-9 (10.0.98.3)."
```

Write hints so they still read correctly with the pointer removed. Put the
instruction first and the pointer last, in its own clause. A hint whose entire
body is a pointer — such as `"Target: {{NEXT_NODE_IP}}"` — leaves nothing behind
and falls back to a generic line, so prefer a form that carries its own
instruction.

Example:

```yaml
hint_levels:
  low:
    - "Inspect the exposed service before moving to {{NEXT_NODE_NAME}}."
  medium:
    - "Credential: {{OUTPUT.Credential(user)}} / {{OUTPUT.Credential(user,password)}}"
  high:
    - "Log in over SSH with the credential above, then read {{OUTPUT.FlagFile(path)}}."
```

Note:
- Flow will automatically append an IP to `{{NEXT_NODE_NAME}}` when a next-node IP is known, even if `{{NEXT_NODE_IP}}` is not explicitly present. This applies only when a dependent successor exists.

### `File(path)` is reserved on flag-node-generators

A flag-node-generator must publish `File(path)` as the compose file it deploys —
Flow validates that it is `docker-compose.yml` or `docker-compose.yaml` and
rejects anything else. That file is infrastructure: it never reaches the
participant.

So on a flag-node-generator, `{{OUTPUT.File(path)}}` in a hint would render as
`docker-compose.yml`, which is useless to whoever is solving the challenge. Flow
resolves it to `FlagFile(path)` instead — the artifact the challenge is actually
about. Node cards, the participant guide, and the facilitator guide all apply
the same substitution.

Write hints against `{{OUTPUT.FlagFile(path)}}` directly; it is explicit and
behaves identically. This remap does not apply to flag-generators, where
`File(path)` means what it says.

### Promoted disclosures appear as **Helpful Fact**

The opening step has nothing before it. If its access instructions need a value
a participant could not yet have earned — a credential, a token, a private key —
Flow promotes the deeper hint that discloses it into `low`, because otherwise
the chain has no entry point.

Two consequences for authors:

- A promoted line **moves**; it no longer appears at its original depth. Do not
  write a `medium` hint that only makes sense alongside the `high` one.
- Promoted lines are labelled **Helpful Fact** rather than `Hint Low`, since they
  are given rather than earned. Write them as statements of fact.

Only undiscoverable values are promoted. Enumerable ones — ports, paths — stay
gated, and nothing is promoted at any position other than the first.

### What a participant is told, and what is held back

Flow draws a line between *where to go* and *how the challenge was built*. The
second is authoring detail: it names the mechanism, which is usually the answer.

| Surface | Participant sees | Facilitator sees |
|---------|------------------|------------------|
| Start hint (Initial Facts) | node name and address, plus any `flow_supply_when_first` values | same |
| `Technique Source` (guide, Critical Access) | — | generator id and kind |
| Hint levels | as authored, minus filtered lines | same |
| Access instructions | yes | yes |

Concretely, a start hint reads `Start: docker-2 @ 10.103.160.3` and never
appends the generator id, its catalog display name, the assignment type, or the
vulnerability name. Hints naming a README, the generator manifest, or
`docker-compose.yml` are filtered from both guides, since a participant has only
the deployed scenario.

The practical consequence for authors: **your hint levels are the participant's
only guided path.** Do not rely on them being able to see which generator
produced a step, or to look anything up outside the environment.

---

## 5.1) Access Instructions (optional)

**Optional** field in manifest: `access_instructions`

When present, this field provides **step-by-step guidance** for participants on how to interact with the generated artifacts. Access instructions appear in downloaded Participant and Facilitator guides.

Usage:

```yaml
access_instructions:
  title: "NFS Mount & Access"
  steps:
    - step: 1
      title: "Mount the NFS export"
      instructions: |
        From another Docker container in this scenario, install NFS utilities and mount:
        ```bash
        apt-get install -y nfs-common
        mkdir -p /mnt/nfs
        mount -t nfs4 -o vers=4,port={{PORT}} {{NODE}}:{{PATH}} /mnt/nfs
        ```
      vars:
        PORT: "PortForward(host, port)"
        NODE: "node_name"
        PATH: "Directory(host, path)"
    - step: 2
      title: "Examine and extract files"
      instructions: |
        List and examine mounted contents:
        ```bash
        ls -la /mnt/nfs/
        cat /mnt/nfs/flag.txt
        cat /mnt/nfs/creds.txt
        ```
```

**Variable substitution:**
- Template strings like `{{PORT}}`, `{{NODE}}`, `{{PATH}}` are resolved using artifact keys from `outputs.json.outputs`.
- For example, `{{PORT}}` resolves to the value of `PortForward(host, port)`.
- `{{NODE}}` resolves to the value of `node_name` (from inputs or resolved outputs).

**Fallback (if not provided):**
- When `access_instructions` is absent, the guide builder uses heuristics based on artifact patterns.
- If generator outputs include `Directory` + `PortForward` artifacts, guides automatically suggest mounting and file discovery.

**For flag-generators:**
- Provide instructions for accessing/utilizing generated credentials, files, or services.

**For flag-node-generators:**
- Describe how to mount, connect to, or exploit the generated node/service.

**These steps also drive the Solutions Script.**

Beyond the human guides, `access_instructions` is the input to the downloadable
[Solutions Script](FEATURE_DEEP_DIVE.md#solutions-script), which verifies that a deployed
scenario is actually solvable. To keep a generator automatable:

- Put the entry-point command in a fenced ```bash block. The script detects `ssh`,
  `curl`/`wget`, `nc`, and `mount -t nfs`, scanning past setup lines such as `chmod`.
  A step whose only commands use some other tool is reported as `SKIP`.
- Keep protocol dialogs in a fenced ```text block; those lines are piped to the service.
- Prefer the `vars` map over relying on the heuristic placeholder table. `vars` binds a
  placeholder to an exact artifact key and wins over the built-in guesses.
- If a step is gated on a value produced earlier, name the fact and the parameter in
  backticks — for example, ``Provide the previous `Checksum(sha256)` as `sha256` or
  `X-Checksum-SHA256`.`` The script parses that phrasing and presents the resolved value
  as both a query parameter and a header.
- Currently only **flag-node-generators** are automated; flag-generator steps are skipped.

---

## 6) Local testing

The canonical runner is:

- `scripts/run_flag_generator.py`

It runs manifest-based generators (repo-local or installed).

### Test a flag-generator

```bash
python scripts/run_flag_generator.py \
  --kind flag-generator \
  --generator-id <generator_id> \
  --out-dir /tmp/fg_test \
  --config '{"seed":"123","secret":"demo"}'

cat /tmp/fg_test/outputs.json
```

### Test a flag-node-generator

```bash
python scripts/run_flag_generator.py \
  --kind flag-node-generator \
  --generator-id <generator_id> \
  --out-dir /tmp/nodegen_test \
  --config '{"seed":"123","node_name":"node1","flag_prefix":"FLAG"}'

cat /tmp/nodegen_test/docker-compose.yml
cat /tmp/nodegen_test/outputs.json
```

### Test/Execute parity checklist (important)

When a generator passes in the UI **Test** button but fails during **Execute**, it is usually a runtime-parity issue.

Use this checklist before shipping a generator pack:

1. **Run from installed source, not only repo-local**
  - Install the pack via the Web UI and re-test from installed generators.
  - Execute uses installed generators as source-of-truth in normal workflows.

2. **Avoid function-local imports in code that defines nested helpers**
  - In Python, `import json` / `import sys` inside a function can create closure shadowing issues for nested functions.
  - Prefer module-level imports for `json`, `sys`, and other shared modules.

3. **Do not rely on internet/package-manager availability at runtime**
  - Keep runtime resilient if `apt/apk/dnf/yum` is unavailable.
  - Treat package installation as best-effort, not a hard dependency for basic generator output.

4. **Keep runtime paths deterministic**
  - Write outputs under `/outputs` and reference artifacts relative to `outputs.json`.
  - For injectables, emit stable artifact paths and use manifest `injects` keys that resolve to real files.

5. **Validate both execution modes when possible**
  - UI Test run (local web process)
  - UI Test run (remote CORE VM via SSH, when configured)
  - Full Execute run (remote CORE path)
  - Compare logs if behavior diverges.

6. **Require explicit failure signals**
  - Non-zero exit on true failure.
  - Populate `outputs.json` only when outputs are valid.
7. **Preserve CORE compose compatibility for node generators**
  - Avoid `${...}` expressions in generated compose files.
  - Prefer protocol/runtime designs that work without Docker default networking.
  - Keep service script paths robust for relative chmod behavior.

### AI scaffolding prompt addendum

If you use AI to scaffold a generator, include this in your prompt:

> Generate a manifest-based generator that is parity-safe between local Test and remote Execute. Use module-level imports only (no function-local `import json/sys` in enclosing scopes with nested helpers), avoid hard dependency on internet/package-manager availability, write deterministic `/outputs/outputs.json`, and ensure `injects` paths resolve to real files. Mark solver-facing runtime inputs with `flow_supply_when_first: true` when participants must use the value on sequence 1 or on the first step of a parallel branch and cannot reasonably discover it yet; do not mark purely internal entropy/config fields. Include a quick local run command and an installed-pack verification checklist.

---

## 7) Packaging a Generator Pack (ZIP)

A Generator Pack ZIP is a zip archive containing one or more generator directories under either (or both):

- `flag_generators/<generator_dir>/...`
- `flag_node_generators/<generator_dir>/...`

Each generator dir must include a `manifest.yaml`/`manifest.yml`.

The `flag_generators/` and `flag_node_generators/` paths below describe the ZIP's internal layout, not required repository-root directories.

Example:

```text
flag_generators/
  py_my_ssh_creds/
    manifest.yaml
    docker-compose.yml
    generator.py
flag_node_generators/
  py_my_node_challenge/
    manifest.yaml
    docker-compose.yml
    generator.py
```

Create a ZIP (example):

```bash
zip -r my_generator_pack.zip flag_generators/py_my_ssh_creds flag_node_generators/py_my_node_challenge
```

Install it in the Web UI via the Flag Catalog page (upload/import URL).
