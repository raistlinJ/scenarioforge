# ScenarioForge Eval Compatibility Contract

This guide is the integration contract for batch harnesses such as
`scenarioforge-eval`. It describes how to invoke the current ScenarioForge CLI
with behavior as close as possible to WebUI Execute.

The WebUI behavior is authoritative. The CLI intentionally shares its saved XML,
planning, Flow resolution, remote CORE execution, artifact copy, and post-run
validation paths.

## Required Pipeline

Use one XML file as the ground truth for the entire iteration:

```text
generate scenario.xml
  -> preview-plan
  -> flag-sequencing (when Flow is enabled)
  -> execute --post-execution-validation
```

Use the same scenario name and RNG seed in every phase:

```bash
python -m scenarioforge.cli preview-plan \
  --xml "$XML" \
  --scenario "$SCENARIO" \
  --seed "$SEED" \
  --plan-output preview-plan.json

python -m scenarioforge.cli flag-sequencing \
  --xml "$XML" \
  --scenario "$SCENARIO" \
  --seed "$SEED" \
  --flow-mode resolve \
  --flow-length 3 \
  --flow-best-effort \
  --plan-output flag-sequencing.json

NO_COLOR=1 PYTHONUNBUFFERED=1 \
python -m scenarioforge.cli execute \
  --xml "$XML" \
  --scenario "$SCENARIO" \
  --seed "$SEED" \
  --post-execution-validation
```

`preview-plan` and `flag-sequencing` modify the XML in place. Do not regenerate,
replace, or restore the XML between phases.

## Minimum Evaluator Changes

An evaluator updating from the older CLI contract should make these changes:

1. Generate and persist one random seed per iteration.
2. Pass that seed to `preview-plan`, `flag-sequencing`, `topo`, and `execute`.
3. Add `--post-execution-validation` to every full `execute` run.
4. Parse `VALIDATION_SUMMARY_JSON` from combined stdout/stderr, including on a
   nonzero exit.
5. Save the parsed payload as an evaluator artifact such as
   `execute-validation.json`.
6. Preserve the mutated `scenario.xml` produced by the phase pipeline.
7. Write credential-bearing XML atomically with mode `0600`.
8. Redact `CoreConnection/@ssh_password` before including XML in AI prompts,
   reports, archives, or uploaded artifacts.
9. Serialize evaluations that share one CORE VM.
10. Do not require the local `core` Python package when the XML selects remote VM
    execution.

## XML Is Authoritative

The exact path supplied through `--xml` is the scenario definition used by the
CLI. The CLI does not silently substitute a newer catalog XML or WebUI draft.

Current saved XML can contain:

- top-level `Scenarios/CoreConnection`
- scenario-level `ScenarioEditor/HardwareInLoop/CoreConnection`
- `ScenarioEditor/PlanPreview`
- `ScenarioEditor/FlagSequencing/FlowState`
- planning sections and their item rows

The CORE connection, including `ssh_password` when configured, is embedded so a
later CLI invocation targets the same VM as the WebUI. Saved environment values
may fill compatible defaults or credentials, but they must not redirect an XML
that already identifies its CORE target.

Use durable saved XML such as `outputs/scenarios-*/Scenario1.xml`. Do not use
`outputs/tmp-preview-*` as a long-lived execution input. Temporary preview XML
may reference Flow artifacts that no longer exist.

### Safe XML Persistence

`scenarioforge-eval` currently builds XML through `webapp.app_backend`. After
building the tree, use the backend's atomic writer:

```python
tree = backend._build_scenarios_xml(
    {"scenarios": scenarios_inline, "core": core_defaults}
)
xml_path = os.path.join(self.out_dir, "scenario.xml")
backend._write_xml_tree_atomic(tree, xml_path)
```

This writer uses a sibling temporary file, atomically replaces the destination,
and forces mode `0600` when an SSH password is embedded.

If the evaluator stops using the backend helper, preserve those same semantics.
The containing iteration directory should normally use mode `0700`.

## Preview And Flow State

`preview-plan` persists `ScenarioEditor/PlanPreview` into the XML. Execute and
topo automatically reuse that embedded preview when `--preview-plan` is omitted.

`flag-sequencing` persists `ScenarioEditor/FlagSequencing/FlowState`. In resolve
mode, generator output paths, inject source paths, and flag assignments become
part of the runtime contract.

Execute now fails early when:

- embedded preview metadata is stale relative to the scenario
- active Flow state lacks resolved runtime values
- a referenced local Flow artifact no longer exists

For evaluator runs, prefer the embedded XML state over a separately retained
preview JSON. The `--plan-output` files are useful evidence, but the XML remains
the execution input.

## Remote CORE Execution

When XML contains complete remote CORE SSH settings, the parent CLI:

1. stages the exact XML, code, and required Flow artifacts on the CORE VM
2. invokes the remote CLI with the resolved scenario and preview source
3. verifies that the reported CORE session reached `RUNTIME`
4. performs export and validation through remote-aware fallback paths

The evaluator must not set `CORETG_CLI_REMOTE_DELEGATED`; it is an internal
recursion guard used by ScenarioForge.

The local evaluator environment does not need the `core` Python package for this
remote VM path. System-site packages are only required when the evaluator is
actually running CORE natively on the same machine.

The remote CLI normally uses the XML's `venv_bin`, commonly
`/opt/core/venv/bin`.

## Execute Success Contract

Do not treat the text "completed" alone as proof that a scenario is running.
For a full evaluator run, require:

1. the CLI process completes
2. a `CORE_SESSION_ID: <id>` marker is present
3. post-execution validation emits a parseable summary
4. the chosen evaluator validation policy passes

The CLI also checks current-session `core-daemon` journal entries for node boot,
service dependency, service validation, template, and command failures. This
prevents a session creation response from hiding failures such as missing
`CoreTGPrereqs`, `DockerDefaultRoute` validation errors, or failed file setup.

## Post-Execution Validation

Enable validation with the conventional double-dash option:

```text
--post-execution-validation
```

The legacy-compatible spelling `-post-execution-validation` is also accepted.

Before validation, the CLI copies resolved Flow artifacts into stable running
containers and verifies the exact destination paths. It retries bounded
container replacement races, then performs one repair-and-revalidate pass if
inject validation still reports missing files.

The default copy controls are:

| Environment variable | Default | Meaning |
|---|---:|---|
| `CORETG_FLOW_COPY_SETTLE_S` | `1.0` | Initial container settle delay |
| `CORETG_FLOW_COPY_RETRY_S` | `1.0` | Delay between copy attempts |
| `CORETG_FLOW_COPY_MAX_ATTEMPTS` | `4` | Copy attempts, bounded from 1 to 10 |

Keep these defaults unless a test explicitly exercises timing behavior.

### Machine-Readable Marker

The complete validation payload is emitted on one line:

```text
VALIDATION_SUMMARY_JSON: {"ok":true,...}
```

Parse the last occurrence because remote delegation and repair validation may
produce more than one relevant line:

```python
import json
import re

ANSI_RE = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")


def extract_last_json_marker(text: str, marker: str) -> dict | None:
    clean = ANSI_RE.sub("", text or "")
    for line in reversed(clean.splitlines()):
        if marker not in line:
            continue
        return json.loads(line.split(marker, 1)[1].strip())
    return None


summary = extract_last_json_marker(combined_output, "VALIDATION_SUMMARY_JSON:")
```

Set `NO_COLOR=1` for stable logs. Captured subprocess output is normally
non-interactive and therefore uncolored, but explicit disabling makes the
artifact contract clear.

Parse the marker before raising for a nonzero return code. A validation failure
often contains the most precise explanation for the failed run.

### Errors And Warnings

The CLI treats these populated fields as errors and exits nonzero:

- `missing_nodes`
- `missing_docker_nodes`
- `missing_vuln_nodes`
- `docker_missing`
- `docker_not_running`
- `generator_outputs_missing`
- `flow_live_paths_missing`
- `validation_unavailable` or `error`
- `flow_artifact_copy_error`

The CLI prints these populated fields as warnings and preserves the successful
execute status:

- `extra_nodes`
- `extra_docker_nodes`
- `docker_start_pending`
- `injects_missing`
- `generator_injects_missing`

Warning-only summaries can still contain `"ok": false`. Track process success
and validation status separately.

For regression evaluation, the recommended strict policy is:

```python
passed = (
    process.returncode == 0
    and validation_summary is not None
    and validation_summary.get("ok") is True
)
```

If a suite intentionally allows WebUI-style warnings, make that a named,
configurable policy rather than silently treating every return code 0 as clean.

`flow_copy_retried_after_validation` is informational and records that the
automatic repair pass ran.

## Suggested Phase Result

Have the evaluator's subprocess helper return structured phase data instead of
only the `--plan-output` payload:

```python
{
    "phase": phase,
    "returncode": proc.returncode,
    "combined_output": combined,
    "log_path": log_path,
    "plan_payload": plan_payload,
    "session_id": session_id,
    "validation_summary": validation_summary,
}
```

For execute, parse these markers:

- `CORE_SESSION_ID: <id>`
- `VALIDATION_SUMMARY_JSON: {...}`
- `Scenario report written to ...`
- `Scenario summary written to ...`

Useful streamed progress patterns also include `Post-execution validation:` and
`[validate]`.

## Artifact Contract

Retain these artifacts per iteration:

| Artifact | Purpose |
|---|---|
| `scenario.xml` | Authoritative, phase-mutated scenario input; sensitive |
| `preview-plan.json` | Preview phase evidence |
| `preview-plan.log` | Preview diagnostics |
| `flag-sequencing.json` | Flow resolution evidence when enabled |
| `flag-sequencing.log` | Flow diagnostics |
| `execute.log` | Complete execution and remote delegation output |
| `execute-validation.json` | Parsed final validation marker |
| `core-post/session-<id>.xml` | Exported live CORE session, when retained |
| `core-post/validation-session-<id>.json` | ScenarioForge validation sidecar |
| report and summary files | ScenarioForge generated results |

The validation sidecar is written beside the scenario XML under `core-post/`.
An evaluator may copy or reference it, but it should also save the parsed marker
as a stable top-level artifact.

## Secrets And Failure Reports

The authoritative XML can contain a plaintext SSH password by design. This is
required so standalone CLI execution can reproduce the WebUI target.

Never include the raw credential-bearing XML in `_ai_prompt.md`, CI output,
uploaded test bundles, or issue bodies. Either omit it or create a redacted copy:

```python
import xml.etree.ElementTree as ET


def redacted_xml_text(xml_path: str) -> str:
    tree = ET.parse(xml_path)
    for element in tree.getroot().iter("CoreConnection"):
        if "ssh_password" in element.attrib:
            element.set("ssh_password", "[REDACTED]")
    return ET.tostring(tree.getroot(), encoding="unicode")
```

Apply the same rule to environment dumps and command diagnostics. ScenarioForge
redacts normal execution logs, but the evaluator owns its copied XML and prompt
assembly.

## Shared VM Concurrency

Execute defaults include CORE session cleanup, Docker cleanup, conflict removal,
and wrapper/generator image refresh. Two evaluator iterations using the same VM
can therefore remove or replace each other's sessions and containers.

Use one per-VM lock across `flag-sequencing` when it runs generators remotely,
`topo`, and `execute`. Keeping the lock across Flow resolution and execute also
protects the resolved `/tmp/vulns` artifacts from another run's cleanup.
Parallelize scenario generation, static checks, or tests targeting different
CORE VMs, but serialize runtime phases sharing one VM identity.

The lock key should be based on the resolved XML target, for example:

```text
ssh_host:ssh_port:ssh_username:vmid
```

## Timeout Guidance

Remote staging, image setup, container stabilization, Flow copies, session
export, and post-run validation can take several minutes. Use a configurable
subprocess timeout of at least 15 to 20 minutes for broad integration cases.

On timeout:

- preserve stdout/stderr collected so far
- mark the current phase explicitly
- retain the authoritative XML and phase artifacts
- do not immediately launch a replacement run against the same VM without
  cleanup or session inspection

## Evaluator Test Checklist

Add or update tests that prove:

1. generated XML contains both global and scenario CORE connection data
2. `ssh_password` is embedded and the XML mode is `0600`
3. one seed is passed to every invoked phase
4. phase order is `preview-plan`, optional `flag-sequencing`, then `execute`
5. execute receives `--post-execution-validation`
6. the last validation marker is parsed on both exit 0 and exit 1
7. strict and warning-tolerant policies behave differently
8. `execute-validation.json` is registered as an artifact
9. AI prompts redact the XML password
10. shared-VM execution uses a lock
11. remote VM execution does not require a locally importable `core` package
12. a missing validation marker fails a full execute evaluation

## Current Compatibility Baseline

The intended parity behavior includes:

- exact XML forwarding during remote delegation
- embedded preview and Flow state reuse
- complete CORE connection persistence
- remote session existence and `RUNTIME` verification
- current-session `core-daemon` error inspection
- CORE service dependency closure
- stable-container Flow copy with destination verification and retry
- automatic copy repair followed by revalidation
- WebUI-equivalent node, Docker, generator, Flow path, and inject validation

For deeper implementation details, see:

- [CLI Execution Deep Dive](CLI_EXECUTION_DEEP_DIVE.md)
- [Quick Start](QUICK_START.md)
- [Scenario XML Schema](reference/SCENARIO_XML_SCHEMA.md)
- [REST and CLI API Reference](reference/API.md)
