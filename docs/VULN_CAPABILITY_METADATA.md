# Vulnerability Capability Metadata

## Why this exists

A vulnerability catalog entry (a vulhub-style compose directory) only describes
how to *deploy* a target. It says nothing about what a solver gains by
exploiting it.

Flag sequencing used to reduce a vulnerability to a single `is_vuln` boolean, so
an unauthenticated RCE and a read-only path traversal were interchangeable. Two
things went wrong as a result:

- A generator declaring `requires: CodeExecution(host)` could be placed behind a
  vulnerability that never yields code execution, and validation passed.
- A real RCE earned no credit, so it could not unlock a downstream step that
  legitimately depended on it.

This metadata file closes that gap. It declares, in the same fact vocabulary
generators already use, what a vulnerability needs before it can be exploited
and what it yields once it is.

## File locations

The loader merges three levels. **Earlier levels win.**

| Level | Path | Use when |
|---|---|---|
| Per-vuln | `<vuln_dir>/scenarioforge.vuln.yaml` | The declaration should travel with a single pack entry |
| Per-catalog | `outputs/installed_vuln_catalogs/<catalog_id>/vuln_metadata.yaml` | Normal case: one file per installed catalog |
| Site-wide | `<repo_root>/vuln_metadata.yaml` | Shared defaults and glob rules across catalogs |

`.yml` and `.json` are accepted at every level.

## Format

Validated against [`schemas/vulns/vuln_metadata_v1.schema.json`](../schemas/vulns/vuln_metadata_v1.schema.json).

```yaml
schema_version: 1
catalog: "vulhub.zip"
vulns:
  - match: "vulhub/activemq/CVE-2015-5254"
    cve: CVE-2015-5254
    impact: deserialization
    notes: "Unauthenticated deserialization to shell."

  # Explicit facts are unioned on top of the impact default.
  - match: "vulhub/joomla/CVE-2023-23752"
    impact: information_disclosure
    provides:
      - Credential(user, password)

  # Globs are matched after exact and CVE lookups fail.
  - match: "vulhub/nginx/*"
    impact: arbitrary_file_read
```

### Matching

`match` is resolved case-insensitively against the entry's `rel_dir` or display
name, tolerating `\` vs `/`. Resolution order:

1. Exact match
2. Path-suffix match — `vulhub/activemq/CVE-2015-5254` also matches an entry
   keyed `activemq/CVE-2015-5254`
3. `cve` match against any CVE id found in the name
4. Glob patterns (`*`, `?`, `[...]`)

### Impact shorthand

`impact` expands to a default fact set so common cases need one line:

| Impact | Provides | Requires |
|---|---|---|
| `remote_code_execution` | `CodeExecution(host)`, `Shell(host)` | |
| `command_injection` | `CodeExecution(host)`, `Shell(host)` | |
| `deserialization` | `CodeExecution(host)`, `Shell(host)` | |
| `web_rce` | `WebRCE(app)`, `CodeExecution(host)`, `Shell(host)` | |
| `privilege_escalation` | `RootShell(host)` | `Shell(host)` |
| `auth_bypass` | `WebAuthBypass(app)` | |
| `arbitrary_file_read` | `File(host, path)` | |
| `path_traversal` | `File(host, path)` | |
| `arbitrary_file_write` | `File(host, path)` | |
| `arbitrary_file_upload` | `UploadPrimitive(app)`, `File(host, path)` | |
| `sql_injection` | `Knowledge(type, value)`, `Credential(user, hash)` | |
| `credential_disclosure` | `Credential(user, password)` | |
| `secret_disclosure` | `ExposedSecret(service)` | |
| `information_disclosure` | `Knowledge(value)` | |
| `ssrf` | `NetworkAccess(src, dst, port)` | |
| `xxe` | `File(host, path)` | |
| `misconfiguration` | `Misconfiguration(service)` | |
| `denial_of_service` | *(nothing)* | |
| `unknown` | *(nothing)* | |

`denial_of_service` and `unknown` deliberately grant nothing: they cannot
advance a chain.

Every fact must exist in
[`schemas/facts/fact_ontology_reference.yaml`](../schemas/facts/fact_ontology_reference.yaml).
An unknown fact name or wrong arity is a load error, not a silent skip.

### Subsumption

A few implications are applied automatically, so you declare the strongest fact
and get the weaker ones:

- `RootShell(host)` → `Shell(host)`, `CodeExecution(host)`
- `Shell(host)` → `CodeExecution(host)`
- `WebRCE(app)` → `CodeExecution(host)`

### Fact spelling

Generators in the wild write both `Credential(user,password)` and
`Credential(user, password)`. Vuln facts are matched on a spelling-insensitive
key and re-spelled to whatever the consuming generator declared, so either form
works. Arity is still significant: `Shell(host)` and `Shell(host, user)` are
different signatures.

## How sequencing uses it

The vulnerability at a chain position is exploited before that position's flag
is reachable, so its grants are in scope **for that step and every later one**.

- The solver adds the vuln's `provides` to its fact state at that position. A
  generator is only placed where the underlying vuln actually supplies what it
  requires.
- Chain validation adds the same facts before checking each step, and reports a
  vulnerability whose own `requires` are unmet — for example a privilege
  escalation with no prior shell.
- Each assignment carries `vuln_provides`, `vuln_requires`, and
  `vuln_metadata_missing` so an unreachable step is inspectable.

A vulnerability with no metadata grants nothing. That is conservative rather
than permissive: the solver will refuse to place a generator that needs a fact
nobody supplies.

## Node authoring docs as a second source

A node can declare capability without hosting a catalog vulnerability. If a
chain node carries a node-authoring doc (under `node_authoring`, `node_schema`,
`node_spec`, `node_definition`, or `authoring`), its `logic.provides` and
`logic.requires` are credited exactly like vulnerability metadata:

```yaml
node_authoring:
  node_id: jump-web
  template: web
  logic:
    requires: []
    provides:
      - name: CodeExecution
        args: [host]
```

The authoring schema spells facts as `{name, args}` objects; they are converted
to the `CodeExecution(host)` signature form before entering fact state. This was
previously shape-validated only — the declared facts were parsed and discarded.

Vulnerability metadata and authoring facts are unioned when a node has both.

## Pivot rules no longer assume a shell

A pivot rule that does not declare `produces` used to default to
`Shell(<source>)` and `Pivot(<source>)` unconditionally — asserting a shell on
the jump host regardless of what was actually deployed there.

The default is now checked against the source node's declared capability:

| Source node capability | Fallback `produces` |
|---|---|
| Grants shell-class access (`Shell`, `RootShell`, `CodeExecution`, `WebRCE`) | `Shell(src)`, `Pivot(src)` |
| Declared, but grants no shell (e.g. `information_disclosure`) | `Pivot(src)` only, and the rule is marked `unbacked_shell: true` |
| Not declared at all | `Shell(src)`, `Pivot(src)` — unchanged |

An undeclared node keeps the old default: absence of metadata is not evidence
that a shell is unavailable. A rule with an explicit `produces` is never
second-guessed.

The `Pivot(src)` fact is retained even when the shell claim is dropped, because
that is what the pivot subsystem uses for chain ordering; only the unbacked
shell assertion is removed.

## Getting started

Scaffold a file covering the active catalog:

```bash
python scripts/scaffold_vuln_metadata.py
```

Every entry is emitted as `impact: unknown` so nothing is assumed. Entries that
already have metadata are preserved and reported as covered, so the script is
safe to re-run after a catalog update.

Useful flags:

```bash
python scripts/scaffold_vuln_metadata.py --catalog-id <ID>
python scripts/scaffold_vuln_metadata.py --all --output vuln_metadata.yaml
python scripts/scaffold_vuln_metadata.py --include-unvalidated --force
```

Fill in the real impact per entry, then require coverage:

```bash
export SCENARIOFORGE_REQUIRE_VULN_METADATA=1
```

With that set, a chain node whose vulnerability has no metadata entry is a
validation error naming the entry to add. It is **off by default** so an
existing catalog keeps working while you populate the file.

## Related

- [`docs/FLAG_GENERATORS_ALLOWED_INPUTS_OUTPUTS.md`](FLAG_GENERATORS_ALLOWED_INPUTS_OUTPUTS.md) — the fact vocabulary generators use
- [`schemas/facts/fact_ontology_reference.yaml`](../schemas/facts/fact_ontology_reference.yaml) — canonical fact signatures

## Optional participant hints and walkthrough steps

Vulnerability entries can also provide `hint_levels` and `access_instructions`.
These fields are optional, including individual hint levels. Existing Vulhub-style
packs need no changes. Add a `scenarioforge.vuln.yaml` alongside the vulnerability's
compose file, or add the fields to its catalog/site-wide metadata entry. The same
metadata precedence described above applies to the entire entry; guidance does
not merge across precedence levels.

````yaml
schema_version: 1
match: example/service
hint_levels:
  low:
    - "Inspect the service on {{NODE_NAME}}."
  medium:
    - "Scan TCP port 8080 on {{NODE_IP}}."
  high:
    - |
      Request the exposed diagnostic endpoint:
      ```bash
      curl http://{{NODE_IP}}:8080/diagnostics
      ```
access_instructions:
  title: Inspect the exposed diagnostics
  steps:
    - title: Confirm the service
      instructions: |
        ```bash
        curl -I http://{{NODE_IP}}:8080/
        ```
    - title: Retrieve the diagnostic data
      instructions: |
        ```bash
        curl http://{{NODE_IP}}:8080/diagnostics
        ```
        Inspect the response for the challenge's disclosed information.
````

This example demonstrates the format; replace it with commands appropriate to
that vulnerability. Retain any existing `impact`, `requires`, and `provides`
fields when adding guidance to capability metadata.

Both the Flow and Reports guide exports include available vulnerability hints
at their respective low/medium/high levels. Ordered walkthrough steps appear in
a separate collapsed **Vulnerability Walkthrough (Spoilers)** section in both
participant and facilitator guides. Commands retain Markdown code fences and
line breaks. No hint or walkthrough section is added when its metadata is absent.

Supported substitutions are `{{NODE_IP}}` (the current target IP, without a CIDR
suffix) and `{{NODE_NAME}}` (the current target name). Ports, paths, credentials,
and payloads must be supplied explicitly by the metadata author; ports are not
automatically inferred or remapped. A hint or step with unresolved placeholders
is omitted to avoid publishing an incomplete command. These vulnerability fields
do not use the flag generator's output substitution context.

Guidance is read from the active installed catalog when a guide is exported.
The catalog and matching vulnerability entry must remain available. The existing
README reference section remains facilitator-only and is labeled **Publicly
available documentation**. README text is not converted into participant hints
or walkthrough steps automatically.
