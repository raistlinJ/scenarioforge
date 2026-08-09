# Todo Fix List

## High Priority

- [ ] **Missing Docker images causing run failures** — *environment, not code*
  - Image `vulhub/drupal:8.5.0` not found
  - Image `vulhub/drupal:7.57` not found
  - Affects: Multiple runs (dataset-catalog-coverage-071, dataset-segmented-firewall-pivot_run01)
  - Error: `Error response from daemon: No such image: vulhub/drupal:8.5.0`
  - Investigated: the pull preflight already handles this correctly. On a failed
    pull it retries once, then checks whether the images are present locally and
    only raises when they are genuinely missing, with `_format_pull_failure`
    naming each one (`topology.py`). So the failure is reported accurately — the
    images simply are not available on that host.
  - Resolution is operational: pull the two drupal images on the CORE VM, or mark
    those catalog items unselectable so the planner stops drawing them
    (`disabled` / `validated_ok` via `POST /vuln_catalog_items/set_disabled`, or
    let `catalog-rest-batch-test` set `validated_ok` from real results).
  - Scope (checked Aug 8): five drupal composes in the installed catalog reference
    four tags — `vulhub/drupal:8.5.0` (×3), `8.3.0`, `7.57`, `7.31` — so six
    scenarios can draw a drupal node and two of those tags are known missing.
    Verify all four on the CORE VM before re-running; fixing only the two named
    above still leaves the others able to fail the same way:
    `for t in 8.5.0 8.3.0 7.57 7.31; do sudo docker image inspect vulhub/drupal:$t >/dev/null 2>&1 || echo "MISSING $t"; done`

- [ ] **CLI execution failure with exit code 1** — *downstream of the above*
  - Run: `dataset-segmented-firewall-pivot_run01`
  - Run: `dataset-catalog-coverage-071`
  - Error: `RuntimeError: scenarioforge.cli execute failed with exit code 1`
  - Location: `scenarioforge-eval/scenarioforge_eval/executor.py`, line 2215
  - This is the missing-image failure surfacing through the eval harness. The
    raise site is in the **scenarioforge-eval** repo, not this one. Expected to
    clear once the image issue above is resolved.

## Medium Priority

- [x] **SSH fallback pivoting warnings** — *fixed*
  - Multiple warnings for 'docker-10': ssh fallback not applicable to docker-10
  - Affects: dataset-segmented-firewall-pivot_run01
  - Occurrences: pivot[1], pivot[2], pivot[3], pivot[4]
  - Old message: "pivot source already has a compose assignment" — the pivot kept
    `ssh-fallback` as its provider even though the container was never installed,
    so `produces` / `target_requires` / `PivotAccessProvider` advertised access
    the node did not have.
  - Then: "ssh fallback not applicable to docker-10; using existing
    flag-node-generator access instead" — correct resolution, still reported as a
    warning, which made a healthy run look degraded (one line per pivot for the
    same node).
  - Now: the substitution is logged at **info** level, matching the existing
    `Pivoting: assigned Docker SSH fallback container on %s` line. It is a working
    outcome, not a problem, so it no longer enters the run's warnings. A pivot
    source that offers no usable access at all still warns.

## Notes

- Both runs show similar error patterns
- Validation result shows `ok: true` despite the runtime errors — *partly fixed*
  - A container stuck in a **restart loop** answers "running" at every poll, so it
    landed in `docker_running` and none of the `ok = False` conditions fired. The
    validator reported success while the node repeatedly lost the address,
    default route and traffic agent CORE applied at execute.
  - Fix (`app_backend.py`): `docker_restarting` now participates in the `ok`
    computation, and `_inspect_state` reads `RestartCount` (top-level, not under
    `.State`, which is why nothing saw it before).
  - Still true in general: validation describes the **session that got built**, so
    a CLI failure earlier in the run can coexist with a valid session summary.
    Treat the CLI exit code as authoritative for whether a run succeeded.
- Missing Docker images appear to be the root cause of CLI execution failures
