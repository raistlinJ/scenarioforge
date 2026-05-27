# Flag Generators: Allowed Inputs and Outputs

This document is a canonical quick reference for both:
- `flag-generator`
- `flag-node-generator`

It summarizes what is allowed by:
- `schemas/generators/generator_manifest_v1.schema.json`
- `schemas/generators/flag_generator_outputs.schema.json`
- `schemas/facts/fact_ontology_reference.yaml`
- `scenarioforge/generator_manifests.py`

## 1) Allowed Runtime Input Types (`inputs[].type`)

Canonical allowed values:

- `string`
- `int`
- `float`
- `number`
- `boolean`
- `json`
- `file`
- `string_list`
- `file_list`

### Normalized aliases accepted by loader

These values are accepted and normalized to canonical types:

- `filepath`, `file_path`, `path`, `pathname` -> `file`
- `integer` -> `int`
- `double` -> `float`
- `numeric` -> `number`
- `bool` -> `boolean`
- `object`, `dict`, `map` -> `json`
- `str`, `text` -> `string`
- `strings` -> `string_list`
- `files` -> `file_list`
- any type ending in `[]` -> `string_list` (except file/path-like list forms, which map to `file_list`)

## 2) Allowed Artifact-Style Keys (Fact References)

Used in:
- `artifacts.requires`
- `artifacts.optional_requires`
- `artifacts.produces`
- `outputs.json` under `outputs` (additional keys)

### Format requirement

Fact-style string:

- `FactName(arg1, arg2, ...)`

Pattern requirement:

- fact name starts with `[A-Za-z_]`
- then `[A-Za-z0-9_]*`
- must include `(...)`

## 3) Canonical Fact Signatures (Ontology)

- `NetworkAccess(src, dst, port)`
- `NetworkAccess(src, subnet)`
- `NetworkRoute(src, dst)`
- `Pivot(host)`
- `Shell(host)`
- `Shell(host, user)`
- `RootShell(host)`
- `CodeExecution(host)`
- `Credential(user)`
- `Credential(user, password)`
- `Credential(user, hash)`
- `Token(service)`
- `APIKey(service)`
- `File(path)`
- `File(host, path)`
- `Directory(host, path)`
- `PCAP(file)`
- `BackupArchive(file)`
- `Knowledge(value)`
- `Knowledge(type, value)`
- `Hostname(host)`
- `VHost(domain)`
- `Endpoint(path)`
- `Version(service)`
- `WebRCE(app)`
- `WebAuthBypass(app)`
- `UploadPrimitive(app)`
- `InternalNetwork(subnet)`
- `LateralMovement(from, to)`
- `PortForward(host, port)`
- `Vulnerability(host, type)`
- `Misconfiguration(service)`
- `ExposedSecret(service)`
- `Binary(binary_id)`
- `SourceCode(repo)`
- `EncryptedBlob(id)`
- `DecryptionKey(id)`
- `Flag(flag_id)`
- `PartialFlag(flag_id, part)`

## 4) Required and Optional `outputs.json` Keys

Schema for `outputs.json` (runtime output):

Top-level required:
- `generator_id` (string)
- `outputs` (object)

Inside `outputs` required:
- `Flag(flag_id)`

Standard optional keys:
- `FlagDelivery(mode)` with enum:
  - `file`
  - `embedded`
  - `none`
  - `unknown`
- `FlagFile(path)`

Additional allowed keys inside `outputs`:
- Any valid fact-style key (`FactName(...)`) consistent with the ontology above.

## 5) Ready-to-Paste Manifest Template: Flag Generator

```yaml
manifest_version: 1
id: your_generator_id
kind: flag-generator
name: Human Readable Name
description: Short description
version: 1.0.0

runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator

inputs:
  - name: Knowledge(ip)
    type: string
    required: true
    description: Target IP
  - name: unlock_code
    type: string
    required: true
    sensitive: true
    flow_supply_when_first: true
  - name: File(path)
    type: file
    required: false
  - name: extra_hosts
    type: string_list
    required: false
    default: []

artifacts:
  requires:
    - Knowledge(ip)
    - Credential(user,password)
  optional_requires:
    - Token(service)
    - APIKey(service)
    - File(path)
  produces:
    - Flag(flag_id)
    - Credential(user,password)
    - File(path)
    - Knowledge(value)

hint_template: Next: move to {{NEXT_NODE_NAME}} using {{OUTPUT.Credential(user,password)}}
injects:
  - File(path)
```

## 6) Ready-to-Paste Manifest Template: Flag Node Generator

```yaml
manifest_version: 1
id: your_node_generator_id
kind: flag-node-generator
name: Node Generator Name
description: Creates per-node compose/runtime artifacts
version: 1.0.0

runtime:
  type: docker-compose
  compose_file: docker-compose.yml
  service: generator

inputs:
  - name: Knowledge(ip)
    type: string
    required: true
  - name: node_config
    type: json
    required: false
    default: {}

artifacts:
  requires:
    - Knowledge(ip)
  optional_requires:
    - Directory(host,path)
  produces:
    - Flag(flag_id)
    - File(path)
    - Endpoint(path)

hint_template: Next: access {{NEXT_NODE_NAME}} at {{NEXT_NODE_IP}}
injects:
  - File(path) -> /flow_injects
```

## 7) Ready-to-Paste `outputs.json` Template

```json
{
  "schema_version": 1,
  "generator_id": "your_generator_id",
  "outputs": {
    "Flag(flag_id)": "FLAG{example}",
    "FlagDelivery(mode)": "file",
    "FlagFile(path)": "artifacts/flag.txt",
    "Credential(user,password)": "user:pass",
    "Knowledge(value)": "10.0.0.5",
    "File(path)": "artifacts/payload.bin"
  }
}
```

## 8) Notes

- Keep output file paths relative to `/outputs` conventions used by the runner.
- Prefer ontology-defined fact keys for best compatibility with sequencing and validation.
- `hint_template` placeholders (for example `{{NEXT_NODE_NAME}}`, `{{OUTPUT.Key}}`) are supported by Flow rendering.
