# Generator Authoring Guide (Manifests + Generator Packs)

This repo supports **two generator families** used by the Flag Sequencing (Flow) system:

- **flag-generators**: run *on an existing Docker node* to produce artifacts (credentials, URLs, next-step hints, etc.).
- **flag-node-generators**: generate a **per-node `docker-compose.yml`** used to *create* a challenge node (SSH/HTTPS/NFS/local-file flag nodes, etc.).

Both families share the same runtime output contract: a machine-readable `outputs.json`.

AI prompt templates (copy/paste):
- [docs/AI_PROMPT_TEMPLATES.md](AI_PROMPT_TEMPLATES.md)

## 0) AI scaffolding quickstart

If you are using AI to create generators, use this minimal handoff packet:

- `manifest.yaml` (or at least `id`, `kind`, `runtime`, `inputs`, `artifacts`, `injects`, `hint_templates`)
- scaffolded `generator.py`
- expected artifact keys (`requires`, `optional_requires`, `produces`)
- explicit statement of required vs optional runtime inputs
- mark solver-facing first-step runtime inputs with `flow_supply_when_first: true` when participants must use the value and cannot reasonably discover it yet
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

hint_templates:
  - "Next: use {{OUTPUT.Credential(user)}} / {{OUTPUT.Credential(user,password)}}"

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
- For any solver-facing runtime input a participant must use on the first challenge but cannot reasonably discover yet, set `flow_supply_when_first: true`; Flow supplies a deterministic value and writes it into the first challenge hint.
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
- After the generator finishes, `scripts/run_flag_generator.py` stages **only** allowlisted items into `<out_dir>/injected/`.
- If the generator produces a `docker-compose.yml`, the runner rewrites **relative bind mounts** to use a named volume and adds an **init-copy** service that copies allowlisted files into the volume before the main service runs.

`injects` entries can be:

- A relative path like `artifacts/my_binary` (prefix `artifacts/` is optional), or
- An **output artifact key** like `File(path)` which is resolved via `outputs.json.outputs`.

When using `File(path)` as an output key, the corresponding `outputs.json.outputs["File(path)"]` value should still be relative to `/outputs` (for example `artifacts/my_binary`), not `/outputs/artifacts/my_binary`.

Optional destination directory syntax:

- `artifacts/my_binary -> /opt/bin`
- `File(path) => /var/tmp`

The `->` / `=>` destination syntax above affects where the injected file is mounted or copied. It does not change the `outputs.json.outputs["File(path)"]` contract, which should remain relative to `/outputs`.

If no destination is provided (or it fails validation), files default to `/flow_injects`.

### Candidate injection paths (`inject_candidate_paths`)

If you want the injected artifact to land in a **non-deterministically chosen** directory on each run (making the challenge more realistic — the attacker must discover the file rather than check a known path), add `inject_candidate_paths` to your manifest:

```yaml
inject_candidate_paths:
  - /opt/uploads
  - /var/www/html
  - /srv/data
```

Rules:
- Each path must be an absolute path starting with `/`. Relative or `..`-containing entries are ignored.
- When `inject_candidate_paths` is set and non-empty, one path is chosen at random **per execution** as the inject destination (overrides the `/flow_injects` default).
- An explicit `->` destination in `injects` still takes priority over candidate paths (candidates only apply when no explicit destination is given).
- The chosen path is reflected in the `inject_copy` init-container that copies files into the target container's named volume.

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

---

## 5) Hint templates and substitution

Manifests can declare:

- `hint_template` (single string)
- `hint_templates` (list of strings; typically least → most revealing)

Flow substitutions include:

- `{{THIS_NODE_NAME}}`, `{{THIS_NODE_ID}}`
- `{{NEXT_NODE_NAME}}`, `{{NEXT_NODE_ID}}`
- `{{NEXT_NODE_IP}}` (when available)
- `{{SCENARIO}}`
- `{{OUTPUT.<key>}}` where `<key>` comes from `outputs.json.outputs`

Example:

```
Next: SSH to {{NEXT_NODE_NAME}} using {{OUTPUT.Credential(user)}} / {{OUTPUT.Credential(user,password)}}
```

Note:
- Flow will automatically append an IP to `{{NEXT_NODE_NAME}}` when a next-node IP is known, even if `{{NEXT_NODE_IP}}` is not explicitly present.

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

> Generate a manifest-based generator that is parity-safe between local Test and remote Execute. Use module-level imports only (no function-local `import json/sys` in enclosing scopes with nested helpers), avoid hard dependency on internet/package-manager availability, write deterministic `/outputs/outputs.json`, and ensure `injects` paths resolve to real files. Mark solver-facing runtime inputs with `flow_supply_when_first: true` when participants must use the value on the first challenge and cannot reasonably discover it yet; do not mark purely internal entropy/config fields. Include a quick local run command and an installed-pack verification checklist.

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
