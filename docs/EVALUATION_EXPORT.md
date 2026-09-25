# Export evaluation suites for CyberAgentFlow

`evaluation-export` produces a versioned package for the question: **does a frozen
generated artifact improve agent task performance?** The package supplies common
tasks and evaluator-only answers. CyberAgentFlow supplies model configuration,
artifact/tool conditions, budgets, repetitions, execution, and dataset export through
the **cyber-agent-flow-eval project** (`cyber-agent-flow-eval`), configured with
`engine.path` pointing to the CAF checkout and optional `engine.python`. CAF's main application
handles interactive sessions, analysis, artifact generation, repair and tests. The
evaluator consumes selected artifacts and shares the agent engine/tool modules;
it does not launch the main WebUI or generate artifacts during a trial.
There are no dynamic hints, model calls, or artifact-generation steps in this export.

## Generate with scenario execution

In the **WebUI**, execute the saved scenario as usual. On a successful execution,
the post-run workflow starts evaluation-package generation in the background,
including live artifact checks. Open **Reports → the execution row → Download →
Evaluation package (ZIP)**. The download waits for generation to finish. It is
available to administrators and builders authorized for that scenario, and contains
evaluator-only answers: do not distribute the complete ZIP to participants.

Without saved task definitions, the WebUI default creates a whole-scenario flag task.
Saved `FlowState.evaluation_tasks` supplies authored tasks to automatic export.
CAF's evaluation YAML owns execution scope:
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

The export is version 3 and contains no network-policy file. The former
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

On Kali, copy the complete package to a coordinator-owned location. From the
cyber-agent-flow-eval checkout, use its environment and configure `engine.path`
(and optionally `engine.python`) to point at the CAF installation:

```bash
.venv/bin/cyber-agent-flow-eval import-suite /path/to/training-dev-v1 \
  --config configs/experiments/scenarioforge-observational.yaml \
  --output configs/experiments/training-dev-v1.yaml

.venv/bin/cyber-agent-flow-eval plan configs/experiments/training-dev-v1.yaml
.venv/bin/cyber-agent-flow-eval run configs/experiments/training-dev-v1.yaml \
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

## Hidden network discovery (version 3)

Use `--evaluation-tasks docs/examples/evaluation-discovery-tasks.json` with either
`execute --evaluation-export` or standalone `evaluation-export`. Replace the example
node IDs and networks with your deployed scenario. The ordinary default task remains
a disclosed-target task; hidden discovery is explicit, not inferred from topology.

Set `discovery: true` and declare:

- `starting_facts`: public `{id, artifact, value}` records, such as the entry subnet
  and any initial credentials. Only these facts are appended to the briefing.
- `discoverable_facts`: private `{id, artifact, value, source_node, evidence, requires}`
  records. `requires` is an optional list of fact IDs. `evidence` identifies the file,
  service response, or observation that actually reveals the value in the scenario.
- `objective_requires`: private mapping from graph node IDs to required fact IDs.

For example, supply `InternalNetwork(subnet) = 10.77.0.0/24` initially, place a clue
for `10.78.0.0/24` on the entry host, and make the internal objective depend on that
fact. Knowledge does not create connectivity: CORE must provide the intended routes
and pivot requirements. Missing initial facts are never automatically disclosed.
The exporter rejects missing references, duplicate IDs, circular prerequisites,
and hidden fact values or hidden-subnet IPv4 addresses in participant content.

Discovery flag tasks omit node names, objective IPs, and private node-to-objective
mappings. They request `{"flags":["FLAG{recovered}"]}`; CAF matches recovered strings
to private objectives and gives partial credit. This measures flag recovery, not
proof of which evidence the agent read. There are no automatic hints.

The [network clue generator](../generator_templates/network-discovery-clue/README.md)
provides an importable template that emits `InternalNetwork(subnet)` and injects a
configuration file. It requires an explicit deployed subnet value. First-step
chain-supplied subnet inputs likewise require a configured CIDR instead of a
synthesized placeholder. Existing initial-fact *type* declarations are not concrete
participant values; author the starting values explicitly in the evaluation tasks.

The task contract records evidence provenance; it does not install the clue or prove
the entire discovery path is solvable. Install/configure the generator and verify
the injected file, access prerequisites, and routing in CORE. WebUI automatic export
uses saved `FlowState.evaluation_tasks` when present, otherwise the ordinary default
task. An external task JSON file can be supplied to the CLI for a scenario deployed
from either interface.

CAF retains its private execution policy and refuses policy disclosure for discovery
suites. Its artifact checks also reject literal hidden facts and hidden-subnet IPv4
addresses in condition catalogs/guidance. These are accidental-disclosure checks,
not semantic secrecy guarantees. Keep evaluator files outside tool-accessible storage
for strict experiments: the current same-user runner does not provide OS isolation.

### Starting facts in guides and graphs

Concrete starting knowledge is shared across Flow and Reports guides, CLI guides,
attack-graph JSON (`starting_facts`), the DOT/PDF “Starting facts (given)” note,
preview/export API responses, the frozen evaluation graph, and solutions-script
comments. Ordinary evaluation prompts also include explicit scenario starting facts
and supplied first-step values.

Sources are `FlowState.starting_facts`, first-step `chain_supplied_input_values`,
and task-specific `starting_facts`. Resolved generator inputs/outputs and
discoverable facts are never inferred to be starting knowledge. `initial_facts`
remains the sequencer's fact-type declaration, not concrete participant values.

For consistent WebUI and automatic evaluation exports, persist `starting_facts`
and/or `evaluation_tasks` in the saved XML's FlowState using the existing
`save_flow_state_to_xml` API. Older clients preserve these fields when omitted;
explicit empty lists clear them. Example FlowState fragment:

```json
{
  "starting_facts": [
    {"id": "entry-network", "artifact": "InternalNetwork(subnet)", "value": "10.77.0.0/24"}
  ]
}
```

Include the existing chain and other flow fields in the full API request. There
is no new WebUI facts editor. When task definitions live in an external file,
pass the same file to each CLI export:

```bash
python -m scenarioforge.cli guides --xml scenario.xml --scenario Training \
  --evaluation-tasks discovery-tasks.json --output-dir guides

python -m scenarioforge.cli attack-graph --xml scenario.xml --scenario Training \
  --evaluation-tasks discovery-tasks.json
```

Task-specific facts carry task IDs. Discovery participant guides contain only
those explicit task starting facts and a short discovery instruction; they omit
detailed steps, hints, setup routes, and topology that could reveal hidden networks.
Facilitator guides and attack graphs remain privileged, full-scenario materials;
do not supply them to the evaluation agent.

## Package contract: `scenarioforge-evaluation`, version 3

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
