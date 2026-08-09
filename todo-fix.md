# TODO/Fix List

## ScenarioForge Evaluation Failures

### Summary
From `/Users/jcacosta/Documents/GitHub/scenarioforge-eval/Original result folders`:
- **Total runs**: 6
- **Failed runs**: 3 (50% failure rate)
- **Failed stage**: All in `execute` phase

### Failed Runs and Root Causes

#### 1. dataset-mixed-collaboration-messaging_run05
**Failure Type**: Docker Image Pull Failures → Post-execution Validation Failed

**Error Details**:
- `vulhub/confluence:7.13.6` - not found
- `postgres:12.8-alpine` - not found
- `vulhub/confluence:8.5.1` - not found
- `postgres:15.4-alpine` - not found

**Validation Result**: `ok: false`
- Docker nodes `docker-7` and `docker-10` had restart_count > 0
- CORE network config lost on restart
- Post-execution validation failed

**Root Cause**: Docker image pull failures caused nodes to restart, losing network configuration.

---

#### 2. dataset-segmented-mixed-perimeter_run05
**Failure Type**: Container Name Conflict → Validation Unavailable

**Error Details**:
- Container name conflict: `/docker-8` is already in use by container `2b23f2ea7b8ad6474533e177093fa062fc1eb78264445065023fcc88cdb78447`

**Validation Result**: `ok: false`, `validation_unavailable: true`

**Root Cause**: Container name conflict when trying to restart docker-8. The container was not properly cleaned up between runs.

---

#### 3. dataset-vuln-collaboration_run04
**Failure Type**: Docker Image Pull Failures → Post-execution Validation Failed

**Error Details**:
- `vulhub/confluence:8.5.3` - not found
- `vulhub/confluence:7.4.10` - not found
- `vulhub/confluence:8.5.1` - not found

**Validation Result**: `ok: false`
- Docker nodes had restart_count: docker-9 (1), docker-10 (2), docker-11 (1)
- Post-execution validation failed

**Root Cause**: Docker image pull failures caused nodes to restart multiple times.

---

### Common Patterns

1. **Docker Image Availability Issues**: Multiple scenarios failed because vulhub images are no longer available at the specified tags
2. **Container Cleanup**: Improper cleanup between runs caused container name conflicts
3. **Network Configuration Loss**: When Docker nodes restart, CORE network configuration is lost (documented in logs: "CORE network config is reapplied only at execute")
4. **Validation Impact**: All 3 failures occurred during post-execution validation phase

### Images Affected
- `vulhub/weblogic:10.3.6.0-2017`
- `vulhub/vite:6.2.2`
- `vulhub/drupal:8.5.0`
- `vulhub/drupal:7.57`
- `vulhub/confluence:7.13.6`, `7.4.10`, `8.5.1`, `8.5.3`
- `postgres:12.8-alpine`, `postgres:15.4-alpine`
- `vulhub/nginx:1.4.2`, `vulhub/nginx:1.13.2`
- `vulhub/php:5.6-fpm`

### Fix Actions
- [ ] Audit all scenario specs for outdated Docker image tags
- [ ] Update vulhub image references to use available tags or modern alternatives
- [ ] Implement container cleanup before each run (remove old containers)
- [ ] Add image availability pre-flight checks
- [ ] Improve error handling to distinguish between image pull warnings and hard failures
- [ ] Consider adding retry logic with exponential backoff for image pulls
- [ ] Document Docker image maintenance procedures

### Related Code
- File: `/Users/jcacosta/Documents/GitHub/scenarioforge/webapp/templates/index.html`
- Fix: Added `_importInProgress` flag to prevent navigation prompts during materialization
