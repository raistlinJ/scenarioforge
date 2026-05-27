# Generator Templates

These templates are starter skeletons for building new generators that integrate with the Flow/Flag Sequencing system.

Folders:
- `flag-generator-python-compose/`: runs a generator inside a container and writes `outputs.json`.
- `flag-node-generator-python-compose/`: generates a per-node `docker-compose.yml` and writes `outputs.json`.

How to use:
1. Copy a template folder into a scratch working directory and rename it using the Generator Pack layout:
	- `flag_generators/<your_generator_dir>/...` or
	- `flag_node_generators/<your_generator_dir>/...`
2. Edit `generator.py` and `docker-compose.yml`.
3. Add a `manifest.yaml` in the generator directory (required by the Web UI / installed workflow).
4. Pack install via Web UI:
	- Create a ZIP containing `flag_generators/<your_generator_dir>/...` and/or `flag_node_generators/<your_generator_dir>/...`.
	- Upload/import it from the Flag Catalog page (Generator Packs).
5. Optional local runner development:
	- Keep an unpacked pack workspace in a scratch directory, then run the generator directly with the runner.
	- The repository does not ship root-level generator catalogs; imported packs install under `outputs/installed_generators/`.
6. Test with `python scripts/run_flag_generator.py ...`.

See [docs/GENERATOR_AUTHORING.md](../docs/GENERATOR_AUTHORING.md) for a full tutorial.
Use [docs/AI_PROMPT_TEMPLATES.md](../docs/AI_PROMPT_TEMPLATES.md) for copy/paste AI scaffolding prompts.

## AI scaffold handoff checklist

When asking AI to author from these templates, include:

- generator kind (`flag-generator` or `flag-node-generator`)
- target source `id`
- current `manifest.yaml`
- scaffolded `generator.py`
- exact required vs optional inputs
- any solver-facing first-step runtime inputs that need `flow_supply_when_first: true`
- exact `artifacts.produces` keys

Ask AI to output only the target file(s), then run local + installed-pack parity tests.

## Parity checklist (Test vs Execute)

When adapting templates, apply these defaults so UI Test and full Execute behave the same:

- Keep imports (`json`, `sys`, etc.) at module scope.
- Do not depend on live internet/package-manager success for core generator output.
- Always write `outputs.json` with valid keys before exiting successfully.
- Ensure `injects` entries map to real generated files.
- Verify once with the local runner and once through the installed-pack execute path.
