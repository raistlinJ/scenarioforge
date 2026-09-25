# Export evaluation suites for CyberAgentFlow

`evaluation-export` produces a versioned package for the question: **does a frozen
generated artifact improve agent task performance?** The package supplies common
tasks and evaluator-only answers. CyberAgentFlow supplies model configuration,
artifact/tool conditions, budgets, repetitions, execution, and dataset export.
There are no dynamic hints, model calls, or artifact-generation steps in this export.

## Generate with scenario execution

In the **WebUI**, execute the saved scenario as usual. On a successful execution,
the post-run workflow starts evaluation-package generation in the background,
including live artifact checks. Open **Reports → the execution row → Download →
Evaluation package (ZIP)**. The download waits for generation to finish. It is
available to administrators and builders authorized for that scenario, and contains
evaluator-only answers: do not distribute the complete ZIP to participants.

The WebUI default creates a whole-scenario flag task. CAF owns execution scope:
configure allow/disallow only in the CAF evaluation YAML. ScenarioForge exports
objectives and topology, not execution permissions. Scenarios need resolved flags
and addresses for the default task. Older executions require a new execution or
the standalone export below.

If checks fail or cannot run, a package may still be generated for inspection, but
the download warns that readiness has not passed. CyberAgentFlow will reject it.
Generation errors do not change the success/failure of the WebUI's scenario execution.
The package and ZIP are stored under `outputs/evaluation-packages/<execution-key>/`.
They are separate from the existing full-scenario bundle. Generation uses the saved
XML version captured at execution completion; intervening XML edits cause refusal.

In the **CLI**, request the artifact as part of execution:

```bash
python -m scenarioforge.cli execute \
  --xml /path/to/scenario.xml --scenario Training \
  --evaluation-export
```

This runs checks and emits `EVALUATION_PACKAGE_JSON:` with the ZIP path,
package hash and readiness result. It works for local execution and execution
delegated to a CORE VM; package generation runs on the coordinating machine. A
failed readiness result or generation error gives the requested CLI workflow a
nonzero exit code, even when the scenario itself was deployed successfully.

Optional settings:

```bash
--suite-id training-dev-v1 \
--evaluation-output-dir /path/to/new-package-directory
```

`--evaluation-tasks reviewed-tasks.json` selects custom objectives and
`--eval-split validation` changes the default split. `--readiness-report` is for
standalone export only; execute-time generation always collects fresh evidence.
Do not also run `--check-artifacts` expecting a second check: evaluation generation
already performs the strict checks once.

### Execution scope belongs to CAF

The export is version 2 and contains no network-policy file. The former
`--eval-allow` and `--eval-disallow` options have been removed. Neither export nor
CAF scope settings change what ScenarioForge deploys.

CAF import preserves the runtime template's `execution.network_policy`, including
all exclusions and multiple allowed subnets. It checks known objective addresses
against that policy and refuses conflicts; it never broadens permissions or drops
objectives. Custom tasks without source-node references cannot be checked this way.
CAF can still read version 1 packages, but their embedded policy is not authoritative;
their old prompt text remains unchanged. Re-export to remove those old scope statements.

For an air-gapped participant VM, manually transfer the ZIP using the lab's approved
mechanism, then unpack and import locally. No live CAF-to-ScenarioForge link is required.

## End-to-end workflow

Use the ScenarioForge checkout and environment. Start with the **saved XML actually
used for the deployed scenario**, including resolved FlagSequencing FlowState.
The export never regenerates flags or modifies that XML.

```bash
# Run live readiness checks. Use your actual CORE endpoint, session and XML.
python -m scenarioforge.cli check-artifacts \
  --xml /path/to/deployed.xml --scenario Training \
  --host core-vm.example --session-id 9 --strict > /path/to/readiness.log

# Proceed only after check-artifacts succeeds.
python -m scenarioforge.cli evaluation-export \
  --xml /path/to/deployed.xml --scenario Training \
  --suite-id training-dev-v1 --session-id 9 \
  --readiness-report /path/to/readiness.log \
  --output-dir /path/to/training-dev-v1
```

Addresses, session IDs and endpoints above are placeholders. Configure execution
authorization in CAF, independently of the exported topology.

The default is **one whole-scenario flag-collection task** using all graph nodes
with resolved nonempty string flags. Each selected node must have a
resolved IPv4 address. This avoids incorrectly treating dependent attack-chain
nodes as independent tasks with missing prerequisite access. Node IDs and target
addresses are public objectives; graph edges, credentials, resolved generator
inputs/outputs and flag answers remain private. The expected response is:

```json
{"flags": {"objective-node-id": "recovered flag value"}}
```

The evaluator checks exact objective-to-flag matches and reports per-objective
results plus the fraction found. Missing flags fail their objectives. Unknown
objective IDs or malformed response structure prevent overall success. Any permitted
approach may succeed; graph path order is never a verifier requirement. A valid flag
is evidence of knowledge of that flag, not proof of a specific exploit path.

Default flag tasks require `containers`, `services`, `ports`, and `injects` readiness
checks to pass. If a legitimate scenario has different prerequisites, supply
reviewed task definitions with the appropriate `required_checks`.

For an observational service task instead of flag collection, copy and **edit**
[the task-definition example](examples/evaluation-inventory-tasks.json), then add:

```bash
--evaluation-tasks /path/to/reviewed-tasks.json
```

This example's addresses and answer are illustrative, not discovered facts about
your deployment. Readiness validates environment prerequisites; expected service
answers must still be reviewed against deployed truth.

On Kali, copy the complete package to a coordinator-owned location. From
CyberAgentFlow, use its separate Python environment:

```bash
venv/bin/python -m experiments import-suite /path/to/training-dev-v1 \
  --config configs/experiments/scenarioforge-observational.yaml \
  --output configs/experiments/training-dev-v1.yaml

venv/bin/python -m experiments plan configs/experiments/training-dev-v1.yaml
venv/bin/python -m experiments run configs/experiments/training-dev-v1.yaml \
  --output eval-runs/training-dev-v1
```

Import preserves the template's model, budgets, conditions and repetitions, rebases
file paths, replaces inline tasks with a suite reference, and preserves the template’s
network scope. **Choose tools appropriate to the tasks:** the example template
exposes only nmap and is suitable for the observational inventory example. It is
not generally sufficient for flag-collection challenges. Review the generated YAML
before running. Export/import and `plan` do not contact the model or target.

## Reviewed task definitions

The input is a nonempty JSON array. Every task has a unique `id`, `family`, optional
`split` (default `--eval-split`, which defaults to `development`), and nonempty
`required_checks`. There are two forms:

1. `flag_nodes`: an explicit list of graph node IDs; flags resolve from the saved
   graph. Optional `prompt` replaces the generated task wording. Do not include
   flags, credentials, or solution steps in it.
2. `prompt` plus `verifier: {type, expected}`: an authored task with `json_equals`
   or `contains_all`. `contains_all` is a literal smoke check, not semantic scoring.

Do not supply both `flag_nodes` and `verifier`. The exporter does not append execution policy
to prompts. Each selected flag node must have a flag and a resolved address. Known resolved flag strings appearing in participant task text
cause export failure; this is an accidental-leak check, not comprehensive secret
redaction. Audit any authored prompts and participant materials.

For dependent subsets, state prerequisite access in the prompt and arrange that
starting state operationally. Graph relationships are preserved privately for
provenance, not automatically provisioned. Splits and families are author labels;
the system cannot prove tasks were held out from artifact generation.

## Package contract: `scenarioforge-evaluation`, version 2

```text
manifest.json
participant/
  tasks.json                  # Prompts, IDs, families, splits; no answers
evaluator/
  verifiers.json              # Expected outcomes, keyed by task ID
  task-metadata.json          # Graph source-node references, required checks
  readiness.json              # Original check report or explicit unverified status
  attack-graph.json           # Full private attack graph and dependency data
  scenario.xml                # Exact saved XML bytes
```

The manifest contains suite ID, creation timestamp, scenario name/identity, XML and
graph hashes, CORE session/host, individual file SHA-256 hashes, and a package hash.
The package hash is SHA-256 of the manifest excluding `package_hash`, serialized
with UTF-8, sorted keys, indentation 2, unescaped Unicode, no non-finite numbers,
and one trailing newline. Per-file hashes cover exact file bytes. Output is staged
then renamed into a new directory; existing outputs are never overwritten.

Evaluator directories use mode 0700 and files 0600. These permissions restrict
other users but **do not isolate tools running under the same account**. Keep the
whole package and CyberAgentFlow output private; distribute only reviewed
participant files to agents, and use separate evaluator permissions/sandboxing
for held-out trials with filesystem-capable tools. Hashes detect changed content;
they are not signatures or proof that source reports are truthful.

## Readiness evidence and limits

`check-artifacts` now adds `status`, `xml_sha256`, `checked_at` (UTC), `core_host`,
and `session_confirmed` to its existing `CHECK_ARTIFACTS_SUMMARY_JSON:` marker. The
XML hash is recorded only if its bytes were unchanged across the check. A check
must confirm the requested session in the live CORE session list for imported
evaluation to proceed.

`--readiness-report` accepts a raw marker JSON object or captured CLI stdout. Old
reports without the added identity fields cannot authorize a run. Reports with an
explicit mismatched XML hash, scenario name, or requested session are rejected on
export. Omit the report to export a **draft** for inspection; CyberAgentFlow refuses
to execute drafts.

Before a run and before each new attempt, CyberAgentFlow requires:

- Valid manifest and file hashes; participant/evaluator task IDs align.
- Known objective addresses permitted by the CAF execution policy (deny takes precedence).
- A completed passing report tied to the same XML, scenario, CORE host/session.
- Confirmed live-session identity at the time of the report.
- No failed/warning/pending checks; each task-required check must pass, not skip.
- A timezone-bearing timestamp within the configured age limit (default one hour).

This is validation of **historical evidence**, not a live per-trial readiness probe.
It does not guarantee Kali has the intended vantage point, the environment has not
changed since checking, or that every expected flag string is deployed correctly.
Source XML/graph intent still needs verification against actual deployment.

For longer studies, predeclare an appropriate `--max-readiness-age-seconds` at
import. If evidence expires, collect new checks and export a new package and output
run; changing evidence deliberately changes experiment identity. Do not edit the
frozen package in place to make an old report appear fresh.

There is no environment deployment/reset adapter in this change. Begin with
observational tasks on a reserved lab. Flag tasks that mutate state need a validated
restoration procedure before repeated baseline/artifact comparisons are interpretable.
Restoration, executable/container snapshots, and held-out evaluator isolation remain
explicit prerequisites for stronger claims.
