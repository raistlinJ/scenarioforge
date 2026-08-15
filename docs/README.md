# Documentation Index

Use this page to navigate the main project documentation.

## Getting started
- [Quick Start](QUICK_START.md)
- [CORE Install](CORE_INSTALL.md) – install our CORE fork (<https://github.com/raistlinJ/core>), or the updates to apply to a vanilla CORE install.
- [Operating Modes](OPERATING_MODES.md)
- [VM Mode Setup](VM_MODE_SETUP.md) – CORE VM interface layout, Proxmox bridges, and the VM-mode `.scenarioforge.env` reference.
- [Native Mode Setup](NATIVE_MODE_SETUP.md) – local/remote CORE targets, the native-mode `.scenarioforge.env` reference, and the Proxmox VM / Access workflow.
- [Runtime Validation (strict by default)](QUICK_START.md#runtime-validation)
- [Catalog Batch Testing](CATALOG_BATCH_TESTING.md)
- [Artifact Checks (validate a running session)](CLI_EXECUTION_DEEP_DIVE.md#check-artifacts-phase)
- [Screenshots](screenshots.md)

## Core workflows
- [CLI Execution Deep Dive](CLI_EXECUTION_DEEP_DIVE.md)
- [Catalog Batch Testing](CATALOG_BATCH_TESTING.md)
- [AI Generator Workflow](AI_GENERATOR_WORKFLOW.md)
- [Full Preview Workflow](FULL_PREVIEW_WORKFLOW.md)
- Flag Sequencing API, XML synchronization, retry IDs, and long-request behavior are documented in the [REST API Reference](reference/API.md#flag-sequencing-flow).
- [Feature Deep Dive](FEATURE_DEEP_DIVE.md)
- [Artifact Checks](FEATURE_DEEP_DIVE.md#artifact-checks-live-session-validation) – validate a running session's containers, services, ports, injects, segmentation, traffic, and reachability.
- [Solutions Script](FEATURE_DEEP_DIVE.md#solutions-script) – downloadable script that verifies the deployed challenges are solvable.
- AI Generator state flow and persistence are documented in [Feature Deep Dive](FEATURE_DEEP_DIVE.md#ai-generator-workflow).
- Recent AI generator compiler, validation, retry, and preview-sync improvements are summarized in [AI Generator Workflow](AI_GENERATOR_WORKFLOW.md).

## Reference
- [Architecture Overview](ARCHITECTURE_OVERVIEW.md)
- [Restrictions & Limitations](RESTRICTIONS_LIMITATIONS.md)
- [Troubleshooting](TROUBLESHOOTING.md)
- [OpenAPI Spec](openapi.yaml)

## Authoring and APIs
- [Generator Authoring](GENERATOR_AUTHORING.md)
- [Flag Generator Notes](FLAG_GENERATORS.md)
- [Flag Generator Inputs & Outputs](FLAG_GENERATORS_ALLOWED_INPUTS_OUTPUTS.md)
- [Vulnerability Capability Metadata](VULN_CAPABILITY_METADATA.md) – Declare what a vuln requires and yields so generated chains are solvable.
- [AI Prompt Templates](AI_PROMPT_TEMPLATES.md)
- [Generator Prompt Context](prompts/prompt_sample_context_generator.txt)
- [REST API Reference](reference/API.md)
- Participant UI endpoints and schemas are documented in both [REST API Reference](reference/API.md) and [OpenAPI Spec](openapi.yaml).

## Schema & XML
- [ScenarioForge XML Schema](reference/SCENARIO_XML_SCHEMA.md) – Detailed schema walkthrough, field descriptions, and examples.
- [XML Validation](reference/SCENARIO_XML_SCHEMA.md)

## Integration & Advanced
- [ScenarioForge Eval Compatibility Contract](SCENARIOFORGE_EVAL_COMPATIBILITY.md) – Required CLI pipeline, XML ground truth, validation parsing, artifacts, concurrency, and secret handling for batch evaluators.
- [Catalog Batch Testing](CATALOG_BATCH_TESTING.md) – Pre-execute CLI checks for vulnerability catalogs, flag-generators, and flag-node-generators.
- [DeployForge](DEPLOYFORGE.md) – Ready-to-deploy VM-mode lab file coming soon.
- [MCP (Model Context Protocol) Server](reference/MCP_README.md) – Remote scenario authoring and LLM tool integration.
- [Web UI Backend](webapp/README.md) – Web backend architecture, routes, and Docker deployment.

## Stability & Baselines
- [Stability Baseline (2026-03-07)](STABILITY_BASELINE_2026-03-07.md)
