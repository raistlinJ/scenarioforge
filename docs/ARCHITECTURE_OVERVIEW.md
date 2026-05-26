# Architecture Overview

| Folder | Purpose |
| --- | --- |
| `scenarioforge/cli.py` | CLI entry point; orchestrates parsing, planning, building, and report generation |
| `scenarioforge/parsers/` | Modular XML parsers per scenario section (node info, routing, traffic, services, vulnerabilities, segmentation) |
| `scenarioforge/planning/ai_topology_intent.py` | Deterministic AI intent compiler that turns prompt-derived counts and section requests into backend-compatible scenario rows and MCP seed operations |
| `scenarioforge/builders/topology.py` | Builds star, multi-switch, and segmented topologies using CORE gRPC APIs |
| `scenarioforge/utils/` | Supporting allocators, report writers, traffic/segmentation/service helpers |
| `webapp/` | Flask Web UI, templates, SSE log streaming, history persistence |
| `webapp/routes/_registration.py` | Shared helper for idempotent extracted-route registration so backend imports and repeated test setup do not duplicate route binding |
| `webapp/templates/partials/dock.html` | Persistent logs/XML dock with follow toggle and filters |
| `examples/` | Checked-in example ScenarioForge XML fixtures, including `examples/sample.xml` |
| `generator_templates/` | Starter skeletons for authoring Generator Packs before importing them through the Web UI |
| `schemas/` | XML, generator, sequencer, and fact ontology contracts used by the app and tests |
| `tests/` | Pytest suite covering planning semantics, policy enforcement, preview parity, and CLI behaviours |
| `docs/` | Documentation assets, screenshots, API references, and generator prompt templates under `docs/prompts/` |
