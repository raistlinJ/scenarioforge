# Catalog Batch Testing

Use these checks before a full Execute run when you want to catch catalog start, compose, generator, and inject problems early.

There are two complementary commands:

- `preflight-vuln-catalog`: local static preflight for the active vulnerability catalog. It does not require the Web UI, CORE, SSH, or Docker.
- `catalog-batch-test`: live batch runner through the Web UI API. It uses the same batch routes as the UI and can test vulnerabilities, flag-generators, and flag-node-generators against the configured CORE target.

## Static Vulnerability Preflight

Run this when you want a fast pass over every item in the active installed vulnerability catalog:

```bash
uv run preflight-vuln-catalog --repo-root .
```

The preflight checks the active catalog pack under `outputs/installed_vuln_catalogs/`, prepares the compose metadata the same way execute planning does, and validates inject-plan wiring without starting containers. It catches issues such as missing compose files, invalid template rendering, unsafe shell fragments, missing required support files, and broken `coretg.inject.*` metadata.

Default report:

```text
outputs/vuln-catalog-preflight/latest.json
```

Write a specific report path:

```bash
uv run preflight-vuln-catalog --repo-root . --out outputs/vuln-catalog-preflight/check.json
```

This command is intentionally vulnerability-catalog only. Use `catalog-batch-test` for flag generator catalogs.

## Live Batch Tests

Run this when the Web UI is up and you want the same start/test path used by the catalog pages:

```bash
uv run catalog-batch-test --target all --scope untested
```

Targets:

```bash
uv run catalog-batch-test --target vulns
uv run catalog-batch-test --target flag-generators
uv run catalog-batch-test --target flag-node-generators
uv run catalog-batch-test --target all
```

Scopes match the Web UI vocabulary:

```bash
uv run catalog-batch-test --target all --scope untested
uv run catalog-batch-test --target all --scope failed
uv run catalog-batch-test --target all --scope all
```

The CLI also accepts the internal aliases `unvalidated`, `incomplete`, `previously failed`, `all enabled`, and `all_enabled`.

Useful filters:

```bash
uv run catalog-batch-test --target vulns --scope all --query jboss
uv run catalog-batch-test --target flag-generators --scope failed --limit 25
uv run catalog-batch-test --target all --scope all --include-disabled
```

By default, skipped items make the command fail. This is useful in CI because manual-input generators are not silently treated as a pass. If skipped items are acceptable for a run:

```bash
uv run catalog-batch-test --target flag-generators --scope all --allow-skipped
```

## CORE And Web Credentials

`catalog-batch-test` logs into the Web UI and reuses the backend's saved/default CORE config when possible.

Default Web UI values:

```text
CORETG_WEB_BASE=http://127.0.0.1:9090
CORETG_WEB_USER=coreadmin
CORETG_WEB_PASS=coreadmin
```

Override from the command line:

```bash
uv run catalog-batch-test \
  --base-url http://127.0.0.1:9090 \
  --username coreadmin \
  --password coreadmin \
  --target all \
  --scope all
```

Pass CORE config directly:

```bash
uv run catalog-batch-test --target all --scope all --core-json @core.json
```

`core.json` should be a JSON object with the same fields the Web UI stores for CORE testing, for example:

```json
{
  "ssh_host": "10.0.0.50",
  "ssh_port": 22,
  "ssh_username": "corevm",
  "ssh_password": "change-me",
  "host": "10.0.0.50",
  "port": 50051,
  "venv_bin": "/opt/core/venv/bin"
}
```

You can also pass inline JSON:

```bash
uv run catalog-batch-test \
  --target vulns \
  --scope all \
  --core-json '{"ssh_host":"10.0.0.50","ssh_username":"corevm","ssh_password":"change-me"}'
```

Or select a saved Web UI CORE secret:

```bash
uv run catalog-batch-test --target all --scope failed --core-secret-id my-core-secret
```

If no explicit CORE config or secret is provided, the CLI tries local Web UI hints under `outputs/flag_generators_test_core_hint.json` and `outputs/secrets/core/`, then sends an empty `core` object so the Web UI route can use its configured defaults.

## Reports And Exit Codes

JSON exports are written by default to:

```text
outputs/catalog-batch-tests/<target>-<run-id>.json
```

Change or disable report output:

```bash
uv run catalog-batch-test --target all --out-dir outputs/my-batch-reports
uv run catalog-batch-test --target all --out-dir ""
```

Exit codes:

- `0`: all selected batches completed without failed, incomplete, pending, or disallowed skipped items.
- `10`: Web UI login failed.
- `11`: explicit CORE JSON or CORE secret loading failed.
- `12`: start, status, or export request failed.
- `20`: the batch completed but at least one item failed, was incomplete, stayed pending, or was skipped without `--allow-skipped`.
- `130`: interrupted.

The progress counters printed by the CLI are the same counters returned by the batch status endpoints: `total`, `completed`, `passed`, `failed`, `incomplete`, `skipped`, and `pending`.

## What The Live Batch Covers

Vulnerability batches use the execute-like vulnerability test path. They validate that the item can be selected, staged, started, classified, and cleaned up through the Web UI's CORE-aware test flow. Runtime validation categories include missing nodes, Docker availability, missing inject files, missing generator outputs, and missing generator inject sources.

Flag generator batches run `flag-generator` and `flag-node-generator` catalog tests through the Web UI batch route. The runner generates safe placeholder inputs where it can, skips items that require manual file/artifact input, and classifies failures using the same output/inject checks used by the catalog UI.

These batch tests are pre-execute checks. A full scenario Execute with `--post-execution-validation` is still the final end-to-end validation for a saved scenario XML.

## CI Example

With the Web UI already running:

```bash
uv run preflight-vuln-catalog --repo-root .
uv run catalog-batch-test --target all --scope all --max-wait-seconds 3600
```

For a narrower incremental check:

```bash
uv run catalog-batch-test --target all --scope failed --limit 50
```

## Related Endpoints

The CLI wraps these authenticated Web UI routes:

- `POST /vuln_catalog_items/batch/start`
- `GET /vuln_catalog_items/batch/status`
- `GET /vuln_catalog_items/batch/export.json`
- `POST /flag_catalog_items/batch/start`
- `GET /flag_catalog_items/batch/status`
- `GET /flag_catalog_items/batch/export.json`

See [REST API Reference](reference/API.md) for the endpoint details.
