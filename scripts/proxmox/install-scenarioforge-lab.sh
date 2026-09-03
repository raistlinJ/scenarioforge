#!/usr/bin/env bash
# Provision the three-VM ScenarioForge lab on one Proxmox VE node.

set -Eeuo pipefail

SCRIPT_VERSION="0.1.0"
STATE_DIR="${SCENARIOFORGE_LAB_STATE_DIR:-/etc/scenarioforge-lab}"
STATE_FILE="$STATE_DIR/state.env"
CREDENTIALS_FILE="$STATE_DIR/credentials.env"

VM_STORAGE="${SF_VM_STORAGE:-local-lvm}"
SNIPPET_STORAGE="${SF_SNIPPET_STORAGE:-local}"
UPLINK_BRIDGE="${SF_UPLINK_BRIDGE:-vmbr0}"
MANAGEMENT_BRIDGE="${SF_MANAGEMENT_BRIDGE:-sfmgmt0}"
HITL_BRIDGE="${SF_HITL_BRIDGE:-sfhitl0}"

CORE_VMID="${SF_CORE_VMID:-9401}"
APP_VMID="${SF_APP_VMID:-9402}"
PARTICIPANT_VMID="${SF_PARTICIPANT_VMID:-9403}"
CORE_NAME="${SF_CORE_NAME:-scenarioforge-core}"
APP_NAME="${SF_APP_NAME:-scenarioforge-app}"
PARTICIPANT_NAME="${SF_PARTICIPANT_NAME:-scenarioforge-participant}"

CORE_MEMORY_MB="${SF_CORE_MEMORY_MB:-8192}"
APP_MEMORY_MB="${SF_APP_MEMORY_MB:-4096}"
PARTICIPANT_MEMORY_MB="${SF_PARTICIPANT_MEMORY_MB:-2048}"
CORE_CORES="${SF_CORE_CORES:-4}"
APP_CORES="${SF_APP_CORES:-2}"
PARTICIPANT_CORES="${SF_PARTICIPANT_CORES:-2}"
CORE_DISK_GB="${SF_CORE_DISK_GB:-80}"
APP_DISK_GB="${SF_APP_DISK_GB:-40}"
PARTICIPANT_DISK_GB="${SF_PARTICIPANT_DISK_GB:-20}"

APP_MANAGEMENT_CIDR="${SF_APP_MANAGEMENT_CIDR:-172.31.250.2/24}"
CORE_MANAGEMENT_CIDR="${SF_CORE_MANAGEMENT_CIDR:-172.31.250.3/24}"
CORE_HITL_CIDR="${SF_CORE_HITL_CIDR:-10.254.200.3/24}"
PARTICIPANT_CIDR="${SF_PARTICIPANT_CIDR:-10.254.200.10/24}"

CORE_MINIMAL_URL="${SF_CORE_MINIMAL_URL:-https://github.com/raistlinJ/coreemu-minimal.git}"
CORE_MINIMAL_REF="${SF_CORE_MINIMAL_REF:-main}"
CORE_REPO_URL="${SF_CORE_REPO_URL:-https://github.com/raistlinJ/core.git}"
CORE_REPO_REF="${SF_CORE_REPO_REF:-master}"
SCENARIOFORGE_URL="${SF_SCENARIOFORGE_URL:-https://github.com/raistlinJ/scenarioforge.git}"
SCENARIOFORGE_REF="${SF_SCENARIOFORGE_REF:-main}"

DEBIAN_IMAGE_URL="${SF_DEBIAN_IMAGE_URL:-https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2}"
DEBIAN_SUMS_URL="${SF_DEBIAN_SUMS_URL:-https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS}"
UBUNTU_IMAGE_URL="${SF_UBUNTU_IMAGE_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}"
UBUNTU_SUMS_URL="${SF_UBUNTU_SUMS_URL:-https://cloud-images.ubuntu.com/noble/current/SHA256SUMS}"
IMAGE_CACHE="${SF_IMAGE_CACHE:-/var/lib/vz/template/cache/scenarioforge}"

SSH_PUBLIC_KEY_FILE="${SF_SSH_PUBLIC_KEY_FILE:-}"
WAIT_MINUTES="${SF_WAIT_MINUTES:-90}"
DRY_RUN=0
ASSUME_YES=0
WAIT_FOR_BOOTSTRAP=1
VERBOSE="${SF_VERBOSE:-0}"
STATUS_WATCH=0
STATUS_INTERVAL="${SF_STATUS_INTERVAL:-10}"
COMMAND="install"
PVE_NODE=""
WORK_DIR=""
NETWORK_CHANGES=0
CURRENT_STEP=0
TOTAL_STEPS=8
LAST_CORE_ACTIVITY=""
LAST_APP_ACTIVITY=""

timestamp() {
    date '+%Y-%m-%d %H:%M:%S'
}

emit() {
    local level="$1"
    shift
    printf '%s [scenarioforge-lab] %-8s %s\n' "$(timestamp)" "$level" "$*"
}

log() {
    emit INFO "$@"
}

progress() {
    CURRENT_STEP=$((CURRENT_STEP + 1))
    emit PROGRESS "[$CURRENT_STEP/$TOTAL_STEPS] $*"
}

verbose() {
    [[ "$VERBOSE" -eq 1 ]] || return 0
    emit DEBUG "$@"
}

warn() {
    emit WARN "$@" >&2
}

die() {
    emit ERROR "$@" >&2
    exit 1
}

on_unexpected_error() {
    local line="$1" exit_code="$2"
    emit ERROR "unexpected installer failure at line $line (exit $exit_code)" >&2
    if [[ -f "$STATE_FILE" ]]; then
        emit WARN "VMs and saved credentials were left intact; inspect with: $0 status" >&2
    elif [[ "$NETWORK_CHANGES" -eq 1 ]]; then
        emit WARN "network bridge changes may be staged or applied; review the Proxmox node network configuration" >&2
    fi
}

usage() {
    cat <<'EOF'
Usage:
  install-scenarioforge-lab.sh install [options]
  install-scenarioforge-lab.sh status [--watch] [--interval SECONDS]
  install-scenarioforge-lab.sh --help

Provision three cloud-image VMs on the current Proxmox VE node:
  - Debian 12 + CORE from raistlinJ/core via coreemu-minimal --from-source
  - Ubuntu 24.04 + ScenarioForge via Docker Compose
  - A minimal Debian 12 participant VM

Important options:
  --storage ID                 VM disk storage (default: local-lvm)
  --snippet-storage ID         Directory storage for Cloud-Init snippets (default: local)
  --uplink-bridge NAME         Existing LAN/Internet bridge (default: vmbr0)
  --management-bridge NAME     Isolated CORE management bridge (default: sfmgmt0)
  --hitl-bridge NAME           Isolated participant/HITL bridge (default: sfhitl0)
  --core-vmid ID               CORE VMID (default: 9401)
  --app-vmid ID                ScenarioForge VMID (default: 9402)
  --participant-vmid ID        Participant VMID (default: 9403)
  --ssh-public-key FILE        Add one OpenSSH public key to all guest users
  --wait-minutes N             Bootstrap timeout (default: 90)
  --no-wait                    Start VMs and return without waiting for provisioning
  --verbose                    Show detailed progress and guest bootstrap activity
  --watch                      Keep printing status until CORE and the app are ready
  --interval SECONDS           Status watch interval (default: 10, minimum: 2)
  --yes                        Do not ask for installation confirmation
  --dry-run                    Validate and print mutations without applying them

Network/address overrides:
  --app-management-cidr CIDR   Default: 172.31.250.2/24
  --core-management-cidr CIDR  Default: 172.31.250.3/24
  --core-hitl-cidr CIDR        Default: 10.254.200.3/24
  --participant-cidr CIDR      Default: 10.254.200.10/24

Repository overrides:
  --core-minimal-ref REF       Default: main
  --core-ref REF               Default: master
  --scenarioforge-ref REF      Default: main

Environment variables with the SF_ prefix can set every default; see
scripts/proxmox/README.md for the complete list.
EOF
}

parse_args() {
    if [[ $# -gt 0 && "$1" != -* ]]; then
        COMMAND="$1"
        shift
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) usage; exit 0 ;;
            --version) printf '%s\n' "$SCRIPT_VERSION"; exit 0 ;;
            --storage) VM_STORAGE="${2:?missing value for --storage}"; shift 2 ;;
            --snippet-storage) SNIPPET_STORAGE="${2:?missing value for --snippet-storage}"; shift 2 ;;
            --uplink-bridge) UPLINK_BRIDGE="${2:?missing value for --uplink-bridge}"; shift 2 ;;
            --management-bridge) MANAGEMENT_BRIDGE="${2:?missing value for --management-bridge}"; shift 2 ;;
            --hitl-bridge) HITL_BRIDGE="${2:?missing value for --hitl-bridge}"; shift 2 ;;
            --core-vmid) CORE_VMID="${2:?missing value for --core-vmid}"; shift 2 ;;
            --app-vmid) APP_VMID="${2:?missing value for --app-vmid}"; shift 2 ;;
            --participant-vmid) PARTICIPANT_VMID="${2:?missing value for --participant-vmid}"; shift 2 ;;
            --ssh-public-key) SSH_PUBLIC_KEY_FILE="${2:?missing value for --ssh-public-key}"; shift 2 ;;
            --wait-minutes) WAIT_MINUTES="${2:?missing value for --wait-minutes}"; shift 2 ;;
            --app-management-cidr) APP_MANAGEMENT_CIDR="${2:?missing value for --app-management-cidr}"; shift 2 ;;
            --core-management-cidr) CORE_MANAGEMENT_CIDR="${2:?missing value for --core-management-cidr}"; shift 2 ;;
            --core-hitl-cidr) CORE_HITL_CIDR="${2:?missing value for --core-hitl-cidr}"; shift 2 ;;
            --participant-cidr) PARTICIPANT_CIDR="${2:?missing value for --participant-cidr}"; shift 2 ;;
            --core-minimal-ref) CORE_MINIMAL_REF="${2:?missing value for --core-minimal-ref}"; shift 2 ;;
            --core-ref) CORE_REPO_REF="${2:?missing value for --core-ref}"; shift 2 ;;
            --scenarioforge-ref) SCENARIOFORGE_REF="${2:?missing value for --scenarioforge-ref}"; shift 2 ;;
            --no-wait) WAIT_FOR_BOOTSTRAP=0; shift ;;
            --verbose) VERBOSE=1; shift ;;
            --watch) STATUS_WATCH=1; shift ;;
            --interval) STATUS_INTERVAL="${2:?missing value for --interval}"; shift 2 ;;
            --yes) ASSUME_YES=1; shift ;;
            --dry-run) DRY_RUN=1; shift ;;
            *) die "unknown argument: $1" ;;
        esac
    done

    [[ "$COMMAND" == "install" || "$COMMAND" == "status" ]] || die "unknown command: $COMMAND"
    [[ "$VERBOSE" == "0" || "$VERBOSE" == "1" ]] || die "SF_VERBOSE must be 0 or 1"
    [[ "$STATUS_WATCH" -eq 0 || "$COMMAND" == "status" ]] || die "--watch is only valid with the status command"
    validate_integer "status interval" "$STATUS_INTERVAL" 2
}

require_root_and_pve() {
    [[ "${EUID:-$(id -u)}" -eq 0 ]] || die "run this command as root on a Proxmox VE node"
    local command_name
    for command_name in pveversion pvesh pvesm qm curl openssl python3 sha256sum sha512sum; do
        command -v "$command_name" >/dev/null 2>&1 || die "required command not found: $command_name"
    done
    case "$(dpkg --print-architecture 2>/dev/null || true)" in
        amd64) ;;
        *) die "this release supports amd64 Proxmox hosts only" ;;
    esac
    PVE_NODE="$(hostname -s)"
    pvesh get "/nodes/$PVE_NODE/status" >/dev/null 2>&1 || die "cannot query Proxmox node '$PVE_NODE'"
}

run() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        local rendered="" argument
        for argument in "$@"; do
            printf -v rendered '%s %q' "$rendered" "$argument"
        done
        emit DRY-RUN "${rendered# }"
        return 0
    fi
    if [[ "$VERBOSE" -eq 1 ]]; then
        local rendered="" argument
        for argument in "$@"; do
            printf -v rendered '%s %q' "$rendered" "$argument"
        done
        emit DEBUG "exec: ${rendered# }"
    fi
    "$@"
}

validate_integer() {
    local label="$1" value="$2" minimum="$3"
    [[ "$value" =~ ^[0-9]+$ ]] || die "$label must be an integer"
    (( value >= minimum )) || die "$label must be at least $minimum"
}

validate_name() {
    local label="$1" value="$2"
    [[ "$value" =~ ^[A-Za-z0-9][A-Za-z0-9._-]*$ ]] || die "$label contains unsupported characters: $value"
}

validate_bridge_name() {
    validate_name "bridge name" "$1"
    (( ${#1} <= 15 )) || die "Linux bridge names may not exceed 15 characters: $1"
}

validate_ref() {
    local label="$1" value="$2"
    [[ "$value" =~ ^[A-Za-z0-9._/-]+$ ]] || die "$label contains unsupported characters"
}

plain_ip() {
    printf '%s\n' "${1%/*}"
}

validate_networks() {
    python3 - "$APP_MANAGEMENT_CIDR" "$CORE_MANAGEMENT_CIDR" "$CORE_HITL_CIDR" "$PARTICIPANT_CIDR" <<'PY'
import ipaddress
import sys

try:
    app_mgmt, core_mgmt, core_hitl, participant = [ipaddress.ip_interface(value) for value in sys.argv[1:]]
except ValueError as exc:
    raise SystemExit(f"invalid IPv4/CIDR setting: {exc}")

values = (app_mgmt, core_mgmt, core_hitl, participant)
if any(value.version != 4 for value in values):
    raise SystemExit("the first installer release supports IPv4 networks only")
if app_mgmt.network != core_mgmt.network:
    raise SystemExit("ScenarioForge and CORE management addresses must share a subnet")
if core_hitl.network != participant.network:
    raise SystemExit("CORE HITL and participant addresses must share a subnet")
if len({value.ip for value in values}) != len(values):
    raise SystemExit("guest addresses must be unique")
PY
}

validate_install_inputs() {
    local value
    for value in "$CORE_VMID" "$APP_VMID" "$PARTICIPANT_VMID"; do
        validate_integer "VMID" "$value" 100
    done
    [[ "$CORE_VMID" != "$APP_VMID" && "$CORE_VMID" != "$PARTICIPANT_VMID" && "$APP_VMID" != "$PARTICIPANT_VMID" ]] \
        || die "VMIDs must be unique"
    for value in "$CORE_MEMORY_MB" "$APP_MEMORY_MB" "$PARTICIPANT_MEMORY_MB"; do validate_integer "memory" "$value" 512; done
    for value in "$CORE_CORES" "$APP_CORES" "$PARTICIPANT_CORES"; do validate_integer "CPU cores" "$value" 1; done
    for value in "$CORE_DISK_GB" "$APP_DISK_GB" "$PARTICIPANT_DISK_GB"; do validate_integer "disk size" "$value" 8; done
    validate_integer "wait minutes" "$WAIT_MINUTES" 1
    validate_name "CORE VM name" "$CORE_NAME"
    validate_name "ScenarioForge VM name" "$APP_NAME"
    validate_name "participant VM name" "$PARTICIPANT_NAME"
    validate_bridge_name "$UPLINK_BRIDGE"
    validate_bridge_name "$MANAGEMENT_BRIDGE"
    validate_bridge_name "$HITL_BRIDGE"
    [[ "$UPLINK_BRIDGE" != "$MANAGEMENT_BRIDGE" && "$UPLINK_BRIDGE" != "$HITL_BRIDGE" && "$MANAGEMENT_BRIDGE" != "$HITL_BRIDGE" ]] \
        || die "uplink, management, and HITL bridge names must be distinct"
    validate_ref "coreemu-minimal ref" "$CORE_MINIMAL_REF"
    validate_ref "CORE ref" "$CORE_REPO_REF"
    validate_ref "ScenarioForge ref" "$SCENARIOFORGE_REF"
    [[ "$CORE_MINIMAL_URL" == https://* && "$CORE_REPO_URL" == https://* && "$SCENARIOFORGE_URL" == https://* ]] \
        || die "repository URLs must use HTTPS"
    validate_networks

    if [[ -n "$SSH_PUBLIC_KEY_FILE" ]]; then
        [[ -f "$SSH_PUBLIC_KEY_FILE" ]] || die "SSH public key file not found: $SSH_PUBLIC_KEY_FILE"
        [[ "$(wc -l < "$SSH_PUBLIC_KEY_FILE" | tr -d ' ')" -eq 1 ]] || die "SSH public key file must contain exactly one key"
        grep -Eq '^(ssh-|ecdsa-|sk-)' "$SSH_PUBLIC_KEY_FILE" || die "SSH public key does not look like an OpenSSH public key"
        grep -q "'" "$SSH_PUBLIC_KEY_FILE" && die "SSH public key comments may not contain a single quote"
    fi
}

storage_config() {
    local payload
    payload="$(pvesh get "/storage/$1" --output-format json 2>/dev/null)" \
        || die "Proxmox storage not found: $1"
    [[ -n "$payload" ]] || die "Proxmox returned an empty configuration for storage: $1"
    printf '%s\n' "$payload"
}

storage_field() {
    local config="$1" field="$2"
    python3 -c '
import json
import sys
payload = json.load(sys.stdin)
if isinstance(payload, dict) and isinstance(payload.get("data"), dict):
    payload = payload["data"]
value = payload.get(sys.argv[1], "") if isinstance(payload, dict) else ""
if isinstance(value, bool):
    print(1 if value else 0)
else:
    print(value)
' "$field" <<<"$config"
}

storage_has_content() {
    local config="$1" wanted="$2" content
    content="$(storage_field "$config" content)"
    [[ ",$content," == *",$wanted,"* ]]
}

preflight_proxmox() {
    local vmid config
    [[ ! -f "$STATE_FILE" ]] || die "installer state already exists at $STATE_FILE; use the status command or remove the old lab explicitly"
    for vmid in "$CORE_VMID" "$APP_VMID" "$PARTICIPANT_VMID"; do
        if qm status "$vmid" >/dev/null 2>&1; then
            die "VMID $vmid already exists; this installer never overwrites VMs"
        fi
    done
    ip link show "$UPLINK_BRIDGE" >/dev/null 2>&1 || die "uplink bridge does not exist: $UPLINK_BRIDGE"
    if [[ -f /etc/network/interfaces.new ]] && ! cmp -s /etc/network/interfaces /etc/network/interfaces.new; then
        die "Proxmox has unapplied network changes; review or revert them before this installer adds bridges"
    fi

    config="$(storage_config "$VM_STORAGE")"
    [[ "$(storage_field "$config" disable)" != "1" ]] || die "storage '$VM_STORAGE' is disabled"
    storage_has_content "$config" images || die "storage '$VM_STORAGE' does not allow VM images"

    config="$(storage_config "$SNIPPET_STORAGE")"
    [[ "$(storage_field "$config" disable)" != "1" ]] || die "storage '$SNIPPET_STORAGE' is disabled"
    [[ "$(storage_field "$config" type)" == "dir" ]] \
        || die "snippet storage '$SNIPPET_STORAGE' must be directory-backed"
    verbose "Preflight passed: VMIDs are free, uplink exists, and storage capabilities are compatible"
}

confirm_install() {
    log "Proxmox node:        $PVE_NODE"
    log "VM storage:         $VM_STORAGE"
    log "Cloud-Init snippets:$SNIPPET_STORAGE"
    log "VMIDs:              CORE=$CORE_VMID APP=$APP_VMID PARTICIPANT=$PARTICIPANT_VMID"
    log "Bridges:            uplink=$UPLINK_BRIDGE management=$MANAGEMENT_BRIDGE HITL=$HITL_BRIDGE"
    log "Addresses:          app=$APP_MANAGEMENT_CIDR core=$CORE_MANAGEMENT_CIDR participant=$PARTICIPANT_CIDR"
    verbose "Repositories: coreemu-minimal=$CORE_MINIMAL_REF CORE=$CORE_REPO_REF ScenarioForge=$SCENARIOFORGE_REF"
    if [[ "$DRY_RUN" -eq 1 || "$ASSUME_YES" -eq 1 ]]; then
        return
    fi
    printf 'Type INSTALL to create these resources: '
    local response
    read -r response
    [[ "$response" == "INSTALL" ]] || die "installation cancelled"
}

ensure_isolated_bridge() {
    local bridge="$1" description="$2"
    if ip link show "$bridge" >/dev/null 2>&1; then
        [[ -d "/sys/class/net/$bridge/bridge" ]] || die "$bridge exists but is not a Linux bridge"
        log "Using existing bridge $bridge"
        return
    fi
    log "Creating isolated bridge $bridge"
    run pvesh create "/nodes/$PVE_NODE/network" \
        --iface "$bridge" --type bridge --autostart 1 --comments "$description"
    NETWORK_CHANGES=1
}

wait_for_pve_task() {
    local upid="$1" deadline status_payload status exit_status
    deadline=$(( $(date +%s) + 120 ))
    while :; do
        status_payload="$(pvesh get "/nodes/$PVE_NODE/tasks/$upid/status" --output-format json)"
        status="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("status", ""))' <<<"$status_payload")"
        if [[ "$status" != "running" ]]; then
            exit_status="$(python3 -c 'import json,sys; print(json.load(sys.stdin).get("exitstatus", ""))' <<<"$status_payload")"
            [[ "$exit_status" == "OK" ]] || die "Proxmox task failed ($exit_status): $upid"
            return
        fi
        verbose "Proxmox task is still running: $upid"
        (( $(date +%s) < deadline )) || die "timed out waiting for Proxmox task: $upid"
        sleep 2
    done
}

apply_network_changes() {
    if [[ "$NETWORK_CHANGES" -eq 0 ]]; then
        return
    fi
    if [[ "$DRY_RUN" -eq 1 ]]; then
        run pvesh set "/nodes/$PVE_NODE/network"
        return
    fi
    log "Applying the two isolated bridge additions"
    local task_payload upid
    task_payload="$(pvesh set "/nodes/$PVE_NODE/network" --output-format json)"
    upid="$(python3 -c '
import json
import sys
value = json.load(sys.stdin)
print(value.get("data", "") if isinstance(value, dict) else value)
' <<<"$task_payload")"
    [[ -n "$upid" ]] || die "Proxmox did not return a task ID while applying network configuration"
    wait_for_pve_task "$upid"
    ip link show "$MANAGEMENT_BRIDGE" >/dev/null 2>&1 || die "management bridge did not appear after applying network configuration"
    ip link show "$HITL_BRIDGE" >/dev/null 2>&1 || die "HITL bridge did not appear after applying network configuration"
}

ensure_snippet_storage() {
    local config content path new_content
    config="$(storage_config "$SNIPPET_STORAGE")"
    content="$(storage_field "$config" content)"
    path="$(storage_field "$config" path)"
    [[ -n "$path" ]] || die "could not resolve directory path for snippet storage '$SNIPPET_STORAGE'"
    if ! storage_has_content "$config" snippets; then
        new_content="${content:+$content,}snippets"
        log "Enabling snippets content on $SNIPPET_STORAGE"
        run pvesm set "$SNIPPET_STORAGE" --content "$new_content"
    fi
    SNIPPET_DIR="$path/snippets"
    run install -d -m 0700 "$SNIPPET_DIR"
}

download_verified_image() {
    local url="$1" sums_url="$2" algorithm="$3" destination="$4"
    local filename sums expected actual temporary checksum_command
    filename="${url##*/}"
    checksum_command="${algorithm}sum"
    sums="$(curl -fsSL --retry 3 "$sums_url")" || die "could not download checksum list: $sums_url"
    expected="$(awk -v name="$filename" '$2 == name || $2 == "*" name {print $1; exit}' <<<"$sums")"
    [[ -n "$expected" ]] || die "checksum list does not contain $filename"
    verbose "Resolved $algorithm checksum for $filename: $expected"

    if [[ -f "$destination" ]]; then
        actual="$("$checksum_command" "$destination" | awk '{print $1}')"
        if [[ "$actual" == "$expected" ]]; then
            log "Using verified cached image $destination"
            return
        fi
        warn "Cached image checksum changed; downloading a fresh copy"
    fi

    if [[ "$DRY_RUN" -eq 1 ]]; then
        emit DRY-RUN "download and verify $url -> $destination"
        return
    fi
    install -d -m 0755 "$(dirname "$destination")"
    temporary="$destination.part"
    rm -f "$temporary"
    log "Downloading $filename"
    curl -fL --retry 3 --progress-bar "$url" -o "$temporary"
    actual="$("$checksum_command" "$temporary" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]] || { rm -f "$temporary"; die "checksum verification failed for $filename"; }
    mv "$temporary" "$destination"
}

random_password() {
    openssl rand -hex 16
}

random_mac() {
    local hex
    hex="$(openssl rand -hex 5)"
    printf '02:%s:%s:%s:%s:%s\n' "${hex:0:2}" "${hex:2:2}" "${hex:4:2}" "${hex:6:2}" "${hex:8:2}"
}

shell_assignment() {
    printf '%s=%q\n' "$1" "$2"
}

encode_file() {
    base64 < "$1" | tr -d '\n'
}

public_key_yaml() {
    if [[ -n "$SSH_PUBLIC_KEY_FILE" ]]; then
        printf '    ssh_authorized_keys:\n      - '\''%s'\''\n' "$(<"$SSH_PUBLIC_KEY_FILE")"
    fi
}

write_guest_bootstraps() {
    cat > "$WORK_DIR/core-bootstrap.sh" <<'CORE_SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
exec > >(tee -a /var/log/scenarioforge-core-bootstrap.log) 2>&1
source /etc/scenarioforge-installer.env

install -d -m 0755 /var/lib/scenarioforge
set_bootstrap_status() {
    printf '%s\n' "$*" > /var/lib/scenarioforge/bootstrap-status
    printf 'BOOTSTRAP: %s\n' "$*"
}

export DEBIAN_FRONTEND=noninteractive
set_bootstrap_status 'preparing coreemu-minimal source installer'
install -d -m 0755 /opt/bootstrap
if [[ ! -d /opt/bootstrap/coreemu-minimal/.git ]]; then
    git clone --branch "$CORE_MINIMAL_REF" "$CORE_MINIMAL_URL" /opt/bootstrap/coreemu-minimal
fi

cd /opt/bootstrap/coreemu-minimal/9.2.1
set_bootstrap_status 'installing system packages and building CORE from source'
printf 'n\n' | ./setup-coreemu9.2.1.sh --from-source "$CORE_REPO_URL" "$CORE_REPO_REF"

set_bootstrap_status 'configuring Docker for CORE networking'
install -d -m 0755 /etc/docker
if [[ -s /etc/docker/daemon.json ]]; then
    jq '. + {"bridge":"none","iptables":false}' /etc/docker/daemon.json > /etc/docker/daemon.json.new
else
    printf '%s\n' '{"bridge":"none","iptables":false}' > /etc/docker/daemon.json.new
fi
install -m 0644 /etc/docker/daemon.json.new /etc/docker/daemon.json
rm -f /etc/docker/daemon.json.new

set_bootstrap_status 'installing ScenarioForge custom CORE services'
if [[ ! -d /opt/scenarioforge-services/.git ]]; then
    git clone --branch "$SCENARIOFORGE_REF" "$SCENARIOFORGE_URL" /opt/scenarioforge-services
else
    git -C /opt/scenarioforge-services fetch origin "$SCENARIOFORGE_REF"
    git -C /opt/scenarioforge-services checkout "$SCENARIOFORGE_REF"
    git -C /opt/scenarioforge-services pull --ff-only origin "$SCENARIOFORGE_REF"
fi
install -d -m 0755 /opt/core/custom_services
install -m 0644 /opt/scenarioforge-services/on_core_machine/custom_services/*.py /opt/core/custom_services/

CORE_CONF=/etc/core/core.conf
install -d -m 0755 /etc/core
touch "$CORE_CONF"
if grep -Eq '^[[:space:]]*grpcaddress[[:space:]]*=' "$CORE_CONF"; then
    sed -i 's/^[[:space:]]*grpcaddress[[:space:]]*=.*/grpcaddress = 0.0.0.0/' "$CORE_CONF"
else
    printf '\ngrpcaddress = 0.0.0.0\n' >> "$CORE_CONF"
fi
if grep -Eq '^[[:space:]]*custom_services_dir[[:space:]]*=' "$CORE_CONF"; then
    sed -i 's|^[[:space:]]*custom_services_dir[[:space:]]*=.*|custom_services_dir = /opt/core/custom_services|' "$CORE_CONF"
else
    printf 'custom_services_dir = /opt/core/custom_services\n' >> "$CORE_CONF"
fi

set_bootstrap_status 'restarting and verifying Docker and core-daemon'
systemctl restart docker
systemctl restart core-daemon
systemctl is-active --quiet docker
systemctl is-active --quiet core-daemon
ss -lnt | grep -q ':50051 '
if ip -4 addr show dev ens19 | grep -q 'inet '; then
    echo 'ens19 unexpectedly has an IPv4 address' >&2
    exit 1
fi

touch /var/lib/scenarioforge/core-ready
set_bootstrap_status 'ready'
echo 'CORE provisioning complete.'
CORE_SCRIPT

    cat > "$WORK_DIR/app-bootstrap.sh" <<'APP_SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
exec > >(tee -a /var/log/scenarioforge-app-bootstrap.log) 2>&1
source /etc/scenarioforge-installer.env

install -d -m 0755 /var/lib/scenarioforge
set_bootstrap_status() {
    printf '%s\n' "$*" > /var/lib/scenarioforge/bootstrap-status
    printf 'BOOTSTRAP: %s\n' "$*"
}

export DEBIAN_FRONTEND=noninteractive
set_bootstrap_status 'installing Docker Engine'
if ! command -v docker >/dev/null 2>&1; then
    curl -fsSL https://get.docker.com -o /tmp/get-docker.sh
    sh /tmp/get-docker.sh
    rm -f /tmp/get-docker.sh
fi
systemctl enable --now docker
usermod -aG docker scenarioforge

set_bootstrap_status 'cloning the ScenarioForge repository'
if [[ ! -d /opt/scenarioforge/.git ]]; then
    git clone --branch "$SCENARIOFORGE_REF" "$SCENARIOFORGE_URL" /opt/scenarioforge
else
    git -C /opt/scenarioforge fetch origin "$SCENARIOFORGE_REF"
    git -C /opt/scenarioforge checkout "$SCENARIOFORGE_REF"
    git -C /opt/scenarioforge pull --ff-only origin "$SCENARIOFORGE_REF"
fi
chown -R scenarioforge:scenarioforge /opt/scenarioforge

cat > /opt/scenarioforge/.scenarioforge.env <<ENV_FILE
CORE_HOST=$CORE_MANAGEMENT_IP
CORE_PORT=50051
CORE_SSH_HOST=$CORE_MANAGEMENT_IP
CORE_SSH_PORT=22
CORE_SSH_USERNAME=corevm
CORE_SSH_PASSWORD=$CORE_PASSWORD
CORETG_WEBUI_MODE=vm
CORETG_VM_MODE_HITL_ENABLED=true
CORETG_VM_MODE_HITL_CORE_IFX_NAME=ens19
CORETG_VM_MODE_HITL_CORE_IFX_ATTACHMENT=existing_router
CORETG_VM_MODE_HITL_CORE_IFX_DESCRIPTION=ScenarioForge participant network
CORETG_HITL_CORE_IFX_IPV4=$CORE_HITL_CIDR
CORETG_PUBLISH_HOST=0.0.0.0
CORETG_USE_RELOADER=0
ENV_FILE
chmod 0600 /opt/scenarioforge/.scenarioforge.env

cd /opt/scenarioforge
set_bootstrap_status 'building ScenarioForge and nginx container images'
docker compose --env-file .scenarioforge.env build
set_bootstrap_status 'creating the ScenarioForge administrator account'
install -d -m 0700 outputs/users
docker compose --env-file .scenarioforge.env run --rm --no-deps \
    -e SF_BOOTSTRAP_ADMIN_PASSWORD="$SCENARIOFORGE_ADMIN_PASSWORD" \
    web python -c 'import json, os; from pathlib import Path; from werkzeug.security import generate_password_hash; p=Path("/app/outputs/users/users.json"); p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps({"users":[{"username":"coreadmin","password_hash":generate_password_hash(os.environ["SF_BOOTSTRAP_ADMIN_PASSWORD"]),"role":"admin"}]}, indent=2))'
set_bootstrap_status 'starting ScenarioForge services'
docker compose --env-file .scenarioforge.env up -d

set_bootstrap_status 'waiting for the ScenarioForge HTTPS health check'
for attempt in $(seq 1 60); do
    if curl -kfsS https://127.0.0.1/healthz >/dev/null; then
        break
    fi
    if [[ "$attempt" -eq 60 ]]; then
        docker compose --env-file .scenarioforge.env ps
        docker compose --env-file .scenarioforge.env logs --tail=100
        exit 1
    fi
    sleep 5
done

touch /var/lib/scenarioforge/app-ready
set_bootstrap_status 'ready'
echo 'ScenarioForge provisioning complete.'
APP_SCRIPT
    chmod 0755 "$WORK_DIR/core-bootstrap.sh" "$WORK_DIR/app-bootstrap.sh"
}

write_cloud_init_files() {
    local core_password_hash app_password_hash participant_password_hash public_key
    local core_script_b64 app_script_b64 core_config_b64 app_config_b64
    core_password_hash="$(openssl passwd -6 "$CORE_PASSWORD")"
    app_password_hash="$(openssl passwd -6 "$APP_PASSWORD")"
    participant_password_hash="$(openssl passwd -6 "$PARTICIPANT_PASSWORD")"
    public_key="$(public_key_yaml)"

    {
        shell_assignment CORE_MINIMAL_URL "$CORE_MINIMAL_URL"
        shell_assignment CORE_MINIMAL_REF "$CORE_MINIMAL_REF"
        shell_assignment CORE_REPO_URL "$CORE_REPO_URL"
        shell_assignment CORE_REPO_REF "$CORE_REPO_REF"
        shell_assignment SCENARIOFORGE_URL "$SCENARIOFORGE_URL"
        shell_assignment SCENARIOFORGE_REF "$SCENARIOFORGE_REF"
    } > "$WORK_DIR/core-installer.env"
    {
        shell_assignment SCENARIOFORGE_URL "$SCENARIOFORGE_URL"
        shell_assignment SCENARIOFORGE_REF "$SCENARIOFORGE_REF"
        shell_assignment CORE_MANAGEMENT_IP "$(plain_ip "$CORE_MANAGEMENT_CIDR")"
        shell_assignment CORE_HITL_CIDR "$CORE_HITL_CIDR"
        shell_assignment CORE_PASSWORD "$CORE_PASSWORD"
        shell_assignment SCENARIOFORGE_ADMIN_PASSWORD "$SCENARIOFORGE_ADMIN_PASSWORD"
    } > "$WORK_DIR/app-installer.env"
    chmod 0600 "$WORK_DIR/core-installer.env" "$WORK_DIR/app-installer.env"

    core_script_b64="$(encode_file "$WORK_DIR/core-bootstrap.sh")"
    app_script_b64="$(encode_file "$WORK_DIR/app-bootstrap.sh")"
    core_config_b64="$(encode_file "$WORK_DIR/core-installer.env")"
    app_config_b64="$(encode_file "$WORK_DIR/app-installer.env")"

    cat > "$WORK_DIR/core-user.yaml" <<EOF
#cloud-config
hostname: $CORE_NAME
manage_etc_hosts: true
ssh_pwauth: true
disable_root: true
users:
  - name: corevm
    gecos: CORE operator
    groups: [sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) ALL
    lock_passwd: false
    passwd: '$core_password_hash'
$public_key
chpasswd:
  expire: false
package_update: true
packages: [git, curl, ca-certificates, qemu-guest-agent]
write_files:
  - path: /etc/scenarioforge-installer.env
    owner: root:root
    permissions: '0600'
    encoding: b64
    content: $core_config_b64
  - path: /usr/local/sbin/scenarioforge-core-bootstrap
    owner: root:root
    permissions: '0700'
    encoding: b64
    content: $core_script_b64
runcmd:
  - [systemctl, enable, --now, qemu-guest-agent]
  - [bash, /usr/local/sbin/scenarioforge-core-bootstrap]
EOF

    cat > "$WORK_DIR/app-user.yaml" <<EOF
#cloud-config
hostname: $APP_NAME
manage_etc_hosts: true
ssh_pwauth: true
disable_root: true
users:
  - name: scenarioforge
    gecos: ScenarioForge operator
    groups: [sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) ALL
    lock_passwd: false
    passwd: '$app_password_hash'
$public_key
chpasswd:
  expire: false
package_update: true
packages: [git, curl, ca-certificates, qemu-guest-agent]
write_files:
  - path: /etc/scenarioforge-installer.env
    owner: root:root
    permissions: '0600'
    encoding: b64
    content: $app_config_b64
  - path: /usr/local/sbin/scenarioforge-app-bootstrap
    owner: root:root
    permissions: '0700'
    encoding: b64
    content: $app_script_b64
runcmd:
  - [systemctl, enable, --now, qemu-guest-agent]
  - [bash, /usr/local/sbin/scenarioforge-app-bootstrap]
EOF

    cat > "$WORK_DIR/participant-user.yaml" <<EOF
#cloud-config
hostname: $PARTICIPANT_NAME
manage_etc_hosts: true
ssh_pwauth: true
disable_root: true
users:
  - name: participant
    gecos: Scenario participant
    groups: [sudo]
    shell: /bin/bash
    sudo: ALL=(ALL) ALL
    lock_passwd: false
    passwd: '$participant_password_hash'
$public_key
chpasswd:
  expire: false
package_update: false
final_message: Participant VM is ready
EOF

    cat > "$WORK_DIR/core-network.yaml" <<EOF
version: 2
ethernets:
  management:
    match: {macaddress: '$CORE_NET0_MAC'}
    set-name: ens18
    addresses: [$CORE_MANAGEMENT_CIDR]
  hitl:
    match: {macaddress: '$CORE_NET1_MAC'}
    set-name: ens19
    dhcp4: false
    dhcp6: false
    accept-ra: false
    optional: true
  uplink:
    match: {macaddress: '$CORE_NET2_MAC'}
    set-name: ens20
    dhcp4: true
    dhcp6: false
EOF

    cat > "$WORK_DIR/app-network.yaml" <<EOF
version: 2
ethernets:
  uplink:
    match: {macaddress: '$APP_NET0_MAC'}
    set-name: ens18
    dhcp4: true
    dhcp6: false
  management:
    match: {macaddress: '$APP_NET1_MAC'}
    set-name: ens19
    addresses: [$APP_MANAGEMENT_CIDR]
EOF

    cat > "$WORK_DIR/participant-network.yaml" <<EOF
version: 2
ethernets:
  participant:
    match: {macaddress: '$PARTICIPANT_NET0_MAC'}
    set-name: ens18
    addresses: [$PARTICIPANT_CIDR]
    dhcp4: false
    dhcp6: false
    accept-ra: false
EOF
}

install_snippets() {
    local file destination
    for file in core-user.yaml core-network.yaml app-user.yaml app-network.yaml participant-user.yaml participant-network.yaml; do
        destination="$SNIPPET_DIR/scenarioforge-$file"
        run install -m 0600 "$WORK_DIR/$file" "$destination"
    done
}

create_vm() {
    local vmid="$1" name="$2" memory="$3" cores="$4" disk="$5" image="$6"
    shift 6
    log "Creating VM $vmid ($name)"
    run qm create "$vmid" --name "$name" --memory "$memory" --cores "$cores" \
        --cpu host --ostype l26 --scsihw virtio-scsi-single --agent enabled=1,fstrim_cloned_disks=1 \
        --serial0 socket --vga serial0 --onboot 1 "$@"
    run qm set "$vmid" --scsi0 "$VM_STORAGE:0,import-from=$image,discard=on,iothread=1,ssd=1"
    run qm resize "$vmid" scsi0 "${disk}G"
    run qm set "$vmid" --ide2 "$VM_STORAGE:cloudinit" --boot order=scsi0
}

create_vms() {
    create_vm "$CORE_VMID" "$CORE_NAME" "$CORE_MEMORY_MB" "$CORE_CORES" "$CORE_DISK_GB" "$DEBIAN_IMAGE" \
        --startup order=10,up=30 \
        --net0 "virtio=$CORE_NET0_MAC,bridge=$MANAGEMENT_BRIDGE" \
        --net1 "virtio=$CORE_NET1_MAC,bridge=$HITL_BRIDGE" \
        --net2 "virtio=$CORE_NET2_MAC,bridge=$UPLINK_BRIDGE"
    run qm set "$CORE_VMID" --cicustom \
        "user=$SNIPPET_STORAGE:snippets/scenarioforge-core-user.yaml,network=$SNIPPET_STORAGE:snippets/scenarioforge-core-network.yaml"

    create_vm "$APP_VMID" "$APP_NAME" "$APP_MEMORY_MB" "$APP_CORES" "$APP_DISK_GB" "$UBUNTU_IMAGE" \
        --startup order=20,up=30 \
        --net0 "virtio=$APP_NET0_MAC,bridge=$UPLINK_BRIDGE" \
        --net1 "virtio=$APP_NET1_MAC,bridge=$MANAGEMENT_BRIDGE"
    run qm set "$APP_VMID" --cicustom \
        "user=$SNIPPET_STORAGE:snippets/scenarioforge-app-user.yaml,network=$SNIPPET_STORAGE:snippets/scenarioforge-app-network.yaml"

    create_vm "$PARTICIPANT_VMID" "$PARTICIPANT_NAME" "$PARTICIPANT_MEMORY_MB" "$PARTICIPANT_CORES" "$PARTICIPANT_DISK_GB" "$DEBIAN_IMAGE" \
        --startup order=30,up=15 \
        --net0 "virtio=$PARTICIPANT_NET0_MAC,bridge=$HITL_BRIDGE"
    run qm set "$PARTICIPANT_VMID" --cicustom \
        "user=$SNIPPET_STORAGE:snippets/scenarioforge-participant-user.yaml,network=$SNIPPET_STORAGE:snippets/scenarioforge-participant-network.yaml"
}

write_state() {
    [[ "$DRY_RUN" -eq 0 ]] || return
    install -d -m 0700 "$STATE_DIR"
    chmod 0700 "$STATE_DIR"
    {
        shell_assignment INSTALLER_VERSION "$SCRIPT_VERSION"
        shell_assignment PVE_NODE "$PVE_NODE"
        shell_assignment VM_STORAGE "$VM_STORAGE"
        shell_assignment SNIPPET_STORAGE "$SNIPPET_STORAGE"
        shell_assignment UPLINK_BRIDGE "$UPLINK_BRIDGE"
        shell_assignment MANAGEMENT_BRIDGE "$MANAGEMENT_BRIDGE"
        shell_assignment HITL_BRIDGE "$HITL_BRIDGE"
        shell_assignment CORE_VMID "$CORE_VMID"
        shell_assignment APP_VMID "$APP_VMID"
        shell_assignment PARTICIPANT_VMID "$PARTICIPANT_VMID"
        shell_assignment CORE_MANAGEMENT_CIDR "$CORE_MANAGEMENT_CIDR"
        shell_assignment APP_MANAGEMENT_CIDR "$APP_MANAGEMENT_CIDR"
        shell_assignment CORE_HITL_CIDR "$CORE_HITL_CIDR"
        shell_assignment PARTICIPANT_CIDR "$PARTICIPANT_CIDR"
        shell_assignment APP_NET0_MAC "$APP_NET0_MAC"
    } > "$STATE_FILE"
    {
        shell_assignment CORE_VM_USERNAME corevm
        shell_assignment CORE_VM_PASSWORD "$CORE_PASSWORD"
        shell_assignment APP_VM_USERNAME scenarioforge
        shell_assignment APP_VM_PASSWORD "$APP_PASSWORD"
        shell_assignment PARTICIPANT_VM_USERNAME participant
        shell_assignment PARTICIPANT_VM_PASSWORD "$PARTICIPANT_PASSWORD"
        shell_assignment SCENARIOFORGE_ADMIN_USERNAME coreadmin
        shell_assignment SCENARIOFORGE_ADMIN_PASSWORD "$SCENARIOFORGE_ADMIN_PASSWORD"
    } > "$CREDENTIALS_FILE"
    chmod 0600 "$STATE_FILE" "$CREDENTIALS_FILE"
}

guest_marker_exists() {
    local vmid="$1" marker="$2" output
    output="$(qm guest exec "$vmid" -- test -f "$marker" 2>/dev/null || true)"
    grep -Eq '"exitcode"[[:space:]]*:[[:space:]]*0' <<<"$output"
}

guest_command_output() {
    local vmid="$1" output
    shift
    output="$(qm guest exec "$vmid" -- "$@" 2>/dev/null || true)"
    [[ -n "$output" ]] || return 0
    python3 -c '
import json
import sys
try:
    payload = json.load(sys.stdin)
except Exception:
    raise SystemExit
if payload.get("exitcode") == 0:
    print(str(payload.get("out-data", "")).strip())
' <<<"$output" 2>/dev/null || true
}

guest_last_log_line() {
    guest_command_output "$1" tail -n 1 "$2"
}

guest_progress_text() {
    local vmid="$1" bootstrap_log="$2" current
    current="$(guest_command_output "$vmid" cat /var/lib/scenarioforge/bootstrap-status)"
    if [[ -z "$current" ]]; then
        current="$(guest_last_log_line "$vmid" "$bootstrap_log")"
    fi
    if [[ -z "$current" ]]; then
        current="$(guest_last_log_line "$vmid" /var/log/cloud-init-output.log)"
    fi
    printf '%s\n' "${current:-waiting for guest agent / Cloud-Init}"
}

report_guest_activity() {
    [[ "$VERBOSE" -eq 1 ]] || return 0
    local label="$1" vmid="$2" path="$3" current previous
    current="$(guest_last_log_line "$vmid" "$path")"
    [[ -n "$current" ]] || return 0
    if [[ "$label" == "CORE" ]]; then
        previous="$LAST_CORE_ACTIVITY"
        LAST_CORE_ACTIVITY="$current"
    else
        previous="$LAST_APP_ACTIVITY"
        LAST_APP_ACTIVITY="$current"
    fi
    if [[ "$current" != "$previous" ]]; then
        emit DEBUG "$label guest: $current"
    fi
}

wait_for_provisioning() {
    local deadline now core_ready=0 app_ready=0
    deadline=$(( $(date +%s) + WAIT_MINUTES * 60 ))
    log "Waiting up to $WAIT_MINUTES minutes for CORE and ScenarioForge provisioning"
    while :; do
        guest_marker_exists "$CORE_VMID" /var/lib/scenarioforge/core-ready && core_ready=1
        guest_marker_exists "$APP_VMID" /var/lib/scenarioforge/app-ready && app_ready=1
        report_guest_activity CORE "$CORE_VMID" /var/log/scenarioforge-core-bootstrap.log
        report_guest_activity APP "$APP_VMID" /var/log/scenarioforge-app-bootstrap.log
        log "Bootstrap status: CORE=$([[ $core_ready -eq 1 ]] && echo ready || echo working) APP=$([[ $app_ready -eq 1 ]] && echo ready || echo working)"
        if [[ "$core_ready" -eq 1 && "$app_ready" -eq 1 ]]; then
            return 0
        fi
        now="$(date +%s)"
        (( now < deadline )) || return 1
        sleep 20
    done
}

app_uplink_ip() {
    local payload
    payload="$(qm guest cmd "$APP_VMID" network-get-interfaces 2>/dev/null || true)"
    [[ -n "$payload" ]] || return 0
    python3 -c '
import json
import sys
mac = sys.argv[1].lower()
payload = json.load(sys.stdin)
interfaces = payload.get("result", payload.get("data", [])) if isinstance(payload, dict) else payload
for interface in interfaces:
    if str(interface.get("hardware-address", "")).lower() != mac:
        continue
    for address in interface.get("ip-addresses", []):
        value = address.get("ip-address", "")
        if address.get("ip-address-type") == "ipv4" and value and not value.startswith("127."):
            print(value)
            raise SystemExit
' "$APP_NET0_MAC" <<<"$payload" 2>/dev/null || true
}

vm_status_line() {
    local label="$1" vmid="$2" marker="$3" status="missing" bootstrap="unknown" agent="n/a"
    if qm status "$vmid" >/dev/null 2>&1; then
        status="$(qm status "$vmid" | awk '{print $2}')"
        if [[ "$status" == "running" ]]; then
            if qm agent "$vmid" ping >/dev/null 2>&1; then agent="ready"; else agent="waiting"; fi
            if [[ "$marker" == "-" ]]; then
                bootstrap="n/a"
            elif guest_marker_exists "$vmid" "$marker"; then
                bootstrap="ready"
            else
                bootstrap="working/failed"
            fi
        fi
    fi
    printf '  %-13s VMID %-6s %-8s agent=%-7s bootstrap=%s\n' "$label" "$vmid" "$status" "$agent" "$bootstrap"
}

show_status() {
    [[ -f "$STATE_FILE" ]] || die "no installer state found at $STATE_FILE"
    # shellcheck disable=SC1090
    source "$STATE_FILE"
    printf 'ScenarioForge Proxmox lab on %s\n' "$PVE_NODE"
    vm_status_line CORE "$CORE_VMID" /var/lib/scenarioforge/core-ready
    vm_status_line APP "$APP_VMID" /var/lib/scenarioforge/app-ready
    vm_status_line PARTICIPANT "$PARTICIPANT_VMID" -
    printf '  CORE progress:    %s\n' "$(guest_progress_text "$CORE_VMID" /var/log/scenarioforge-core-bootstrap.log)"
    printf '  APP progress:     %s\n' "$(guest_progress_text "$APP_VMID" /var/log/scenarioforge-app-bootstrap.log)"
    printf '  CORE management: %s (SSH 22, gRPC 50051)\n' "$CORE_MANAGEMENT_CIDR"
    printf '  Participant:     %s on %s\n' "$PARTICIPANT_CIDR" "$HITL_BRIDGE"
    local app_ip
    app_ip="$(app_uplink_ip)"
    if [[ -n "$app_ip" ]]; then
        printf '  ScenarioForge:   https://%s/\n' "$app_ip"
    else
        printf '  ScenarioForge:   query with: qm guest cmd %s network-get-interfaces\n' "$APP_VMID"
    fi
    printf '  Credentials:     %s (root-readable)\n' "$CREDENTIALS_FILE"
}

watch_status() {
    [[ -f "$STATE_FILE" ]] || die "no installer state found at $STATE_FILE"
    # shellcheck disable=SC1090
    source "$STATE_FILE"
    emit INFO "Watching provisioning every $STATUS_INTERVAL seconds; press Ctrl-C to stop"
    while :; do
        printf '\n'
        show_status
        if guest_marker_exists "$CORE_VMID" /var/lib/scenarioforge/core-ready \
            && guest_marker_exists "$APP_VMID" /var/lib/scenarioforge/app-ready; then
            emit INFO "CORE and ScenarioForge provisioning are ready"
            return
        fi
        sleep "$STATUS_INTERVAL"
    done
}

perform_install() {
    progress "Validating Proxmox, storage, VMIDs, and requested networks"
    validate_install_inputs
    preflight_proxmox
    confirm_install

    WORK_DIR="$(mktemp -d /tmp/scenarioforge-pve.XXXXXX)"
    trap '[[ -n "${WORK_DIR:-}" && -d "$WORK_DIR" ]] && rm -rf "$WORK_DIR"' EXIT

    CORE_PASSWORD="$(random_password)"
    APP_PASSWORD="$(random_password)"
    PARTICIPANT_PASSWORD="$(random_password)"
    SCENARIOFORGE_ADMIN_PASSWORD="$(random_password)"
    CORE_NET0_MAC="$(random_mac)"
    CORE_NET1_MAC="$(random_mac)"
    CORE_NET2_MAC="$(random_mac)"
    APP_NET0_MAC="$(random_mac)"
    APP_NET1_MAC="$(random_mac)"
    PARTICIPANT_NET0_MAC="$(random_mac)"

    progress "Creating or validating the isolated management and HITL bridges"
    ensure_isolated_bridge "$MANAGEMENT_BRIDGE" "ScenarioForge isolated CORE management"
    ensure_isolated_bridge "$HITL_BRIDGE" "ScenarioForge isolated participant HITL"
    apply_network_changes

    progress "Preparing Cloud-Init snippet storage"
    ensure_snippet_storage

    progress "Downloading and verifying Debian and Ubuntu cloud images"
    DEBIAN_IMAGE="$IMAGE_CACHE/debian-12-genericcloud-amd64.qcow2"
    UBUNTU_IMAGE="$IMAGE_CACHE/noble-server-cloudimg-amd64.img"
    download_verified_image "$DEBIAN_IMAGE_URL" "$DEBIAN_SUMS_URL" sha512 "$DEBIAN_IMAGE"
    download_verified_image "$UBUNTU_IMAGE_URL" "$UBUNTU_SUMS_URL" sha256 "$UBUNTU_IMAGE"

    progress "Generating credentials, guest bootstrap scripts, and Cloud-Init data"
    write_guest_bootstraps
    write_cloud_init_files
    install_snippets
    write_state

    progress "Creating the CORE, ScenarioForge, and participant VMs"
    create_vms

    progress "Starting all three VMs"
    run qm start "$CORE_VMID"
    run qm start "$APP_VMID"
    run qm start "$PARTICIPANT_VMID"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        progress "Dry-run validation finished"
        log "Dry run complete; no resources were changed"
        return
    fi
    if [[ "$WAIT_FOR_BOOTSTRAP" -eq 1 ]]; then
        progress "Waiting for CORE and ScenarioForge guest provisioning"
        if ! wait_for_provisioning; then
            warn "Provisioning did not finish before the timeout. VMs were left intact for diagnosis."
            warn "Run: $0 status"
            warn "Guest logs: /var/log/scenarioforge-{core,app}-bootstrap.log"
            exit 2
        fi
    else
        progress "Guest provisioning started in the background (--no-wait)"
    fi
    show_status
    log "Installation complete. Retrieve generated passwords from $CREDENTIALS_FILE"
}

main() {
    parse_args "$@"
    trap 'exit_code=$?; on_unexpected_error "$LINENO" "$exit_code"' ERR
    require_root_and_pve
    if [[ "$COMMAND" == "status" ]]; then
        if [[ "$STATUS_WATCH" -eq 1 ]]; then
            watch_status
        else
            show_status
        fi
    else
        perform_install
    fi
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
