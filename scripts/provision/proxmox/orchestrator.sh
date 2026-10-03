# Optional host application. Sourced by install-scenarioforge-lab.sh.
ORCHESTRATOR="${SF_ORCHESTRATOR:-0}"
ORCHESTRATOR_URL="${SF_ORCHESTRATOR_URL:-https://github.com/raistlinJ/cyber-agent-flow-orchestrator.git}"
ORCHESTRATOR_REF="${SF_ORCHESTRATOR_REF:-main}"
ORCHESTRATOR_DIR=/opt/scenarioforge-orchestrator
ORCHESTRATOR_CERT_DIR="$ORCHESTRATOR_DIR/cyber-agent-flow-orchestrator/certs"

preflight_orchestrator_certificate() {
    local cert="$ORCHESTRATOR_CERT_DIR/cert.pem" key="$ORCHESTRATOR_CERT_DIR/key.pem"
    [[ -d "$ORCHESTRATOR_CERT_DIR" || ( ! -e "$ORCHESTRATOR_CERT_DIR" && ! -L "$ORCHESTRATOR_CERT_DIR" ) ]] \
        || die "TLS directory is not a directory: $ORCHESTRATOR_CERT_DIR"
    if [[ -e "$cert" || -L "$cert" || -e "$key" || -L "$key" ]]; then
        [[ -f "$cert" && -f "$key" ]] \
            || die "incomplete TLS certificate pair in $ORCHESTRATOR_CERT_DIR; restore both cert.pem and key.pem before retrying (existing files are never replaced)"
    fi
}

install_orchestrator_certificate() {
    local cli="$1" cert="$ORCHESTRATOR_CERT_DIR/cert.pem" key="$ORCHESTRATOR_CERT_DIR/key.pem"
    preflight_orchestrator_certificate
    if [[ -f "$cert" && -f "$key" ]]; then
        log "Preserving existing WebUI certificate and key in $ORCHESTRATOR_CERT_DIR"
        return 0
    fi
    local host_name host_fqdn
    host_name="$(hostname -s)"
    host_fqdn="$(hostname -f 2>/dev/null || hostname)"
    # Keep existing directory permissions; create-cert writes private files with
    # exclusive creation and mode 0600, and refuses to replace an existing pair.
    if [[ ! -d "$ORCHESTRATOR_CERT_DIR" ]]; then
        run install -d -m 0755 "$ORCHESTRATOR_CERT_DIR"
    fi
    run "$cli" create-cert --hostname localhost --hostname 127.0.0.1 \
        --hostname ::1 --hostname "$host_name" --hostname "$host_fqdn" \
        --days 365 --cert "$cert" --key "$key"
    log "WebUI TLS: $cert and $key; replace both with your signed certificate/key and restart the WebUI to reload."
}

validate_orchestrator() {
    [[ "$ORCHESTRATOR" == 0 || "$ORCHESTRATOR" == 1 ]] || die 'orchestrator must be true or false'
    [[ "$ORCHESTRATOR" == 1 ]] || return 0
    python3 - "$(dirname "$CAF_HELPER")" "$ORCHESTRATOR_URL" "$ORCHESTRATOR_REF" "$CYBER_AGENT_FLOW_EVAL_URL" "$CYBER_AGENT_FLOW_EVAL_REF" <<'PY'
import sys
sys.path.insert(0, sys.argv[1])
from cyber_agent_flow import validate_git_source
validate_git_source(sys.argv[2], sys.argv[3], 'orchestrator')
validate_git_source(sys.argv[4], sys.argv[5], 'cyber_agent_flow_eval')
if sys.version_info < (3, 10):
    raise SystemExit('The orchestrator requires host Python 3.10 or newer')
PY
}

preflight_orchestrator() {
    [[ "$ORCHESTRATOR" == 1 ]] || return 0
    preflight_orchestrator_certificate
    [[ ! -L "$ORCHESTRATOR_DIR" ]] || die "refusing symlink installation directory: $ORCHESTRATOR_DIR"
    if [[ -e "$ORCHESTRATOR_DIR" && ! -f "$ORCHESTRATOR_DIR/.scenarioforge-managed" ]]; then
        die "unmanaged directory exists: $ORCHESTRATOR_DIR; choose a clean installation before retrying"
    fi
    local name target
    for name in cyber-agent-flow-orchestrator cyber-agent-flow-eval; do
        target="$ORCHESTRATOR_DIR/cyber-agent-flow-orchestrator/.venv/bin/$name"
        if [[ -e "/usr/local/bin/$name" || -L "/usr/local/bin/$name" ]]; then
            [[ -L "/usr/local/bin/$name" && "$(readlink "/usr/local/bin/$name")" == "$target" ]] \
                || die "refusing to replace existing command /usr/local/bin/$name"
        fi
    done
}

clone_orchestrator_source() {
    local name="$1" url="$2" ref="$3" target
    target="$ORCHESTRATOR_DIR/$name"
    if [[ ! -e "$target" ]]; then
        run git clone -- "$url" "$target"
    elif [[ "$DRY_RUN" == 0 ]]; then
        [[ ! -L "$target" && -d "$target/.git" ]] || die "incomplete checkout: $target; inspect before retrying"
        [[ "$(git -C "$target" remote get-url origin)" == "$url" ]] || die "repository URL changed for $target; inspect before retrying"
        [[ -z "$(git -C "$target" status --porcelain --untracked-files=no)" ]] || die "tracked changes exist in $target; preserve them before retrying"
    fi
    run git -C "$target" fetch origin "$ref"
    run git -C "$target" checkout --detach FETCH_HEAD
}

install_orchestrator() {
    [[ "$ORCHESTRATOR" == 1 ]] || return 0
    validate_orchestrator
    preflight_orchestrator
    log "Installing host orchestrator in $ORCHESTRATOR_DIR (ref $ORCHESTRATOR_REF)"
    # Repeating an explicit install refreshes the selected refs and dependencies.
    # Guest-only reinstall and lab cleanup do not change this host application.
    run apt-get update
    run apt-get install -y --no-install-recommends git ca-certificates python3-venv
    run install -d -m 0755 "$ORCHESTRATOR_DIR"
    run touch "$ORCHESTRATOR_DIR/.scenarioforge-managed"
    clone_orchestrator_source cyber-agent-flow-eval "$CYBER_AGENT_FLOW_EVAL_URL" "$CYBER_AGENT_FLOW_EVAL_REF"
    clone_orchestrator_source cyber-agent-flow-orchestrator "$ORCHESTRATOR_URL" "$ORCHESTRATOR_REF"
    local project="$ORCHESTRATOR_DIR/cyber-agent-flow-orchestrator" env
    env="$project/.venv"
    run python3 -m venv "$env"
    run "$env/bin/python" -m pip install --disable-pip-version-check uv
    # Supply both local packages so pip never looks for our evaluator on PyPI.
    run "$env/bin/uv" pip install --python "$env/bin/python" \
        --editable "$ORCHESTRATOR_DIR/cyber-agent-flow-eval" --editable "$project"
    run "$env/bin/uv" pip check --python "$env/bin/python"
    # --help exits before importing the evaluator. Check the actual host/helper
    # APIs too, including preflight and VM locks, before publishing commands.
    run "$env/bin/python" -m cyber_agent_flow_orchestrator.compatibility
    run "$env/bin/cyber-agent-flow-orchestrator" --help
    run "$env/bin/cyber-agent-flow-eval" --help
    install_orchestrator_certificate "$env/bin/cyber-agent-flow-orchestrator"
    run ln -sfn "$env/bin/cyber-agent-flow-orchestrator" /usr/local/bin/cyber-agent-flow-orchestrator
    run ln -sfn "$env/bin/cyber-agent-flow-eval" /usr/local/bin/cyber-agent-flow-eval
    log "Host CLI: cyber-agent-flow-orchestrator --help"
    log "Use $project/examples/web.pve.yaml (TLS files in $ORCHESTRATOR_CERT_DIR); configure the workflow and PVE login before starting the WebUI."
}

save_orchestrator_state() {
    local variable
    for variable in ORCHESTRATOR ORCHESTRATOR_URL ORCHESTRATOR_REF; do
        shell_assignment "$variable" "${!variable}"
    done
}
