#!/usr/bin/env bash
# Provision the three-VM ScenarioForge lab on one Proxmox VE node.

set -Eeuo pipefail

SCRIPT_VERSION="0.9.0"
STATE_DIR="${SCENARIOFORGE_LAB_STATE_DIR:-/etc/scenarioforge-lab}"
STATE_FILE="$STATE_DIR/state.env"
CREDENTIALS_FILE="$STATE_DIR/credentials.env"
STATE_TEMP_FILE="$STATE_FILE.new"
CREDENTIALS_TEMP_FILE="$CREDENTIALS_FILE.new"
RUNTIME_STATUS_FILE="${SCENARIOFORGE_LAB_RUNTIME_STATUS_FILE:-/run/scenarioforge-lab-install.status}"
RUNTIME_STATUS_TEMP_FILE="$RUNTIME_STATUS_FILE.new"

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
CORE_USE_SYSTEMD_RESOLVED_STUB="${SF_CORE_USE_SYSTEMD_RESOLVED_STUB:-0}"
FLAG_GENERATORS_URL="${SF_FLAG_GENERATORS_URL:-https://github.com/raistlinJ/flag-generators.git}"
TESTED_FLAG_GENERATORS_COMMIT="5f612eecb8ff5df74a0e517d0de1e54385a62044"
FLAG_GENERATORS_REF="${SF_FLAG_GENERATORS_REF:-$TESTED_FLAG_GENERATORS_COMMIT}"
FLAG_GENERATORS_RESOLVED_COMMIT=""
INSTALL_FLAG_GENERATORS="${SF_INSTALL_FLAG_GENERATORS:-0}"
INSTALL_VULNHUB="${SF_INSTALL_VULNHUB:-0}"
REQUESTED_CORE_PASSWORD="${SF_CORE_PASSWORD:-}"
REQUESTED_APP_PASSWORD="${SF_APP_PASSWORD:-}"
REQUESTED_PARTICIPANT_PASSWORD="${SF_PARTICIPANT_PASSWORD:-}"
REQUESTED_WEB_ADMIN_PASSWORD="${SF_WEB_ADMIN_PASSWORD:-}"

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
FORCE_CLEANUP=0
CONFIG_FILE=""
CONFIG_LINE=0
PARTICIPANT_BOOTSTRAP_REQUIRED=1
PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED=0
COMMAND="install"
PVE_NODE=""
WORK_DIR=""
NETWORK_CHANGES=0
CREATED_MANAGEMENT_BRIDGE=""
CREATED_HITL_BRIDGE=""
CURRENT_STEP=0
TOTAL_STEPS=8
LAST_CORE_ACTIVITY=""
LAST_APP_ACTIVITY=""
LAST_PARTICIPANT_ACTIVITY=""
INSTALL_COMPLETE=""
INSTALL_PHASE=""
INSTALL_PERCENT=0
INSTALL_STARTED_EPOCH=""
INSTALL_STATE_INITIALIZED=0
PROVISIONING_FAILURE_DETAIL=""
OPTIONAL_CONTENT_ARCHIVE=""
OPTIONAL_CONTENT_SHA256=""
CATALOG_TRANSFER_KEY=""
CATALOG_TRANSFER_PUBLIC_KEY_FILE=""
RUNTIME_TRACKING=0
CLEANUP_STATE_FOUND=0
declare -a CLEANUP_VMIDS=()
declare -a CLEANUP_LABELS=()
declare -a CLEANUP_SNIPPETS=()
declare -a CLEANUP_BRIDGES=()

sanitize_host_environment() {
    # Proxmox host tools and Debian Python modules must not inherit Conda/venv
    # command paths or module overrides from an interactive root shell.
    PATH="/usr/sbin:/usr/bin:/sbin:/bin"
    unset PYTHONHOME PYTHONPATH
    export PATH
}

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
    local percent="$1"
    shift
    CURRENT_STEP=$((CURRENT_STEP + 1))
    INSTALL_PERCENT="$percent"
    emit PROGRESS "[$(printf '%3d' "$INSTALL_PERCENT")%] [$CURRENT_STEP/$TOTAL_STEPS] $*"
    if [[ "$RUNTIME_TRACKING" -eq 1 ]]; then
        write_runtime_status running "$*" ""
    fi
    record_install_phase "$*"
}

configure_install_progress() {
    local base_steps="$1"
    CURRENT_STEP=0
    TOTAL_STEPS="$base_steps"
    if [[ "$INSTALL_FLAG_GENERATORS" == "1" || "$INSTALL_VULNHUB" == "1" ]]; then
        TOTAL_STEPS=$((TOTAL_STEPS + 1))
    fi
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
    if [[ "$RUNTIME_TRACKING" -eq 1 ]]; then
        write_runtime_status failed "Installer stopped" "$*"
    fi
    exit 1
}

trim_config_value() {
    local value="$1"
    while [[ "$value" == [[:space:]]* ]]; do value="${value:1}"; done
    while [[ "$value" == *[[:space:]] ]]; do value="${value:0:${#value}-1}"; done
    printf '%s' "$value"
}

parse_config_boolean() {
    local key="$1" value
    value="$(printf '%s' "$2" | tr '[:upper:]' '[:lower:]')"
    case "$value" in
        1|true|yes|on) CONFIG_BOOLEAN_VALUE=1 ;;
        0|false|no|off) CONFIG_BOOLEAN_VALUE=0 ;;
        *) die "$CONFIG_FILE:$CONFIG_LINE: $key must be true or false" ;;
    esac
}

assign_config_setting() {
    local target="$1" environment_name="$2" value="$3"
    if [[ -z "$environment_name" ]] || ! declare -p "$environment_name" >/dev/null 2>&1; then
        printf -v "$target" '%s' "$value"
    fi
}

load_installer_config_file() {
    local callback="$1" path="$2" raw_line key value first last
    [[ -n "$path" ]] || die "--config requires a file"
    [[ -f "$path" ]] || die "config file not found: $path"
    [[ -r "$path" ]] || die "config file is not readable: $path"
    CONFIG_FILE="$path"
    CONFIG_LINE=0
    while IFS= read -r raw_line || [[ -n "$raw_line" ]]; do
        CONFIG_LINE=$((CONFIG_LINE + 1))
        raw_line="${raw_line%$'\r'}"
        raw_line="$(trim_config_value "$raw_line")"
        [[ -z "$raw_line" || "$raw_line" == \#* ]] && continue
        [[ "$raw_line" == *=* ]] || die "$CONFIG_FILE:$CONFIG_LINE: expected key=value"
        key="$(trim_config_value "${raw_line%%=*}")"
        value="$(trim_config_value "${raw_line#*=}")"
        [[ "$key" =~ ^[a-z][a-z0-9_]*$ ]] \
            || die "$CONFIG_FILE:$CONFIG_LINE: invalid config key: $key"
        if (( ${#value} >= 2 )); then
            first="${value:0:1}"
            last="${value: -1}"
            if [[ "$first" == \" || "$first" == "'" ]]; then
                [[ "$last" == "$first" ]] \
                    || die "$CONFIG_FILE:$CONFIG_LINE: unmatched quote for $key"
                value="${value:1:${#value}-2}"
            fi
        fi
        "$callback" "$key" "$value"
    done < "$path"
    log "Using installer config from $path"
}

load_config_from_args() {
    local callback="$1" found="" option
    shift
    while [[ $# -gt 0 ]]; do
        option="$1"
        case "$option" in
            --config)
                [[ $# -ge 2 ]] || die "--config requires a file"
                [[ -z "$found" ]] || die "--config may only be specified once"
                found="$2"
                shift 2
                ;;
            --config=*)
                [[ -z "$found" ]] || die "--config may only be specified once"
                found="${option#--config=}"
                shift
                ;;
            --storage|--snippet-storage|--uplink-bridge|--management-bridge|--hitl-bridge|\
            --core-vmid|--app-vmid|--participant-vmid|--lab-dir|--management-vmnet|--hitl-vmnet|\
            --ssh-public-key|--core-password|--app-password|--participant-password|--web-admin-password|\
            --wait-minutes|--interval|--app-management-cidr|--core-management-cidr|--core-hitl-cidr|\
            --participant-cidr|--core-minimal-ref|--core-ref|--scenarioforge-ref|--flag-generators-ref)
                shift 2
                ;;
            *) shift ;;
        esac
    done
    [[ -z "$found" ]] || load_installer_config_file "$callback" "$found"
}

apply_proxmox_config_value() {
    local key="$1" value="$2"
    case "$key" in
        storage) assign_config_setting VM_STORAGE SF_VM_STORAGE "$value" ;;
        snippet_storage) assign_config_setting SNIPPET_STORAGE SF_SNIPPET_STORAGE "$value" ;;
        uplink_bridge) assign_config_setting UPLINK_BRIDGE SF_UPLINK_BRIDGE "$value" ;;
        management_bridge) assign_config_setting MANAGEMENT_BRIDGE SF_MANAGEMENT_BRIDGE "$value" ;;
        hitl_bridge) assign_config_setting HITL_BRIDGE SF_HITL_BRIDGE "$value" ;;
        core_vmid) assign_config_setting CORE_VMID SF_CORE_VMID "$value" ;;
        app_vmid) assign_config_setting APP_VMID SF_APP_VMID "$value" ;;
        participant_vmid) assign_config_setting PARTICIPANT_VMID SF_PARTICIPANT_VMID "$value" ;;
        ssh_public_key) assign_config_setting SSH_PUBLIC_KEY_FILE SF_SSH_PUBLIC_KEY_FILE "$value" ;;
        core_password) assign_config_setting REQUESTED_CORE_PASSWORD SF_CORE_PASSWORD "$value" ;;
        app_password) assign_config_setting REQUESTED_APP_PASSWORD SF_APP_PASSWORD "$value" ;;
        participant_password) assign_config_setting REQUESTED_PARTICIPANT_PASSWORD SF_PARTICIPANT_PASSWORD "$value" ;;
        web_admin_password) assign_config_setting REQUESTED_WEB_ADMIN_PASSWORD SF_WEB_ADMIN_PASSWORD "$value" ;;
        flag_generators)
            parse_config_boolean "$key" "$value"
            assign_config_setting INSTALL_FLAG_GENERATORS SF_INSTALL_FLAG_GENERATORS "$CONFIG_BOOLEAN_VALUE"
            ;;
        vulnhub)
            parse_config_boolean "$key" "$value"
            assign_config_setting INSTALL_VULNHUB SF_INSTALL_VULNHUB "$CONFIG_BOOLEAN_VALUE"
            ;;
        wait_minutes) assign_config_setting WAIT_MINUTES SF_WAIT_MINUTES "$value" ;;
        no_wait)
            parse_config_boolean "$key" "$value"
            WAIT_FOR_BOOTSTRAP=$((1 - CONFIG_BOOLEAN_VALUE))
            ;;
        verbose)
            parse_config_boolean "$key" "$value"
            assign_config_setting VERBOSE SF_VERBOSE "$CONFIG_BOOLEAN_VALUE"
            ;;
        watch) parse_config_boolean "$key" "$value"; STATUS_WATCH="$CONFIG_BOOLEAN_VALUE" ;;
        interval) assign_config_setting STATUS_INTERVAL SF_STATUS_INTERVAL "$value" ;;
        yes) parse_config_boolean "$key" "$value"; ASSUME_YES="$CONFIG_BOOLEAN_VALUE" ;;
        dry_run) parse_config_boolean "$key" "$value"; DRY_RUN="$CONFIG_BOOLEAN_VALUE" ;;
        force) parse_config_boolean "$key" "$value"; FORCE_CLEANUP="$CONFIG_BOOLEAN_VALUE" ;;
        app_management_cidr) assign_config_setting APP_MANAGEMENT_CIDR SF_APP_MANAGEMENT_CIDR "$value" ;;
        core_management_cidr) assign_config_setting CORE_MANAGEMENT_CIDR SF_CORE_MANAGEMENT_CIDR "$value" ;;
        core_hitl_cidr) assign_config_setting CORE_HITL_CIDR SF_CORE_HITL_CIDR "$value" ;;
        participant_cidr) assign_config_setting PARTICIPANT_CIDR SF_PARTICIPANT_CIDR "$value" ;;
        core_minimal_ref) assign_config_setting CORE_MINIMAL_REF SF_CORE_MINIMAL_REF "$value" ;;
        core_ref) assign_config_setting CORE_REPO_REF SF_CORE_REPO_REF "$value" ;;
        scenarioforge_ref) assign_config_setting SCENARIOFORGE_REF SF_SCENARIOFORGE_REF "$value" ;;
        flag_generators_ref) assign_config_setting FLAG_GENERATORS_REF SF_FLAG_GENERATORS_REF "$value" ;;
        *) die "$CONFIG_FILE:$CONFIG_LINE: unknown Proxmox config key: $key" ;;
    esac
}

on_unexpected_error() {
    local line="$1" exit_code="$2"
    emit ERROR "unexpected installer failure at line $line (exit $exit_code)" >&2
    if [[ "$RUNTIME_TRACKING" -eq 1 ]]; then
        write_runtime_status failed "Installer stopped unexpectedly" "line $line, exit $exit_code"
    fi
    if [[ "$COMMAND" == "cleanup" ]]; then
        emit WARN "cleanup stopped; any resources not yet reported as removed were left intact" >&2
    elif [[ -f "$STATE_FILE" ]]; then
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
  install-scenarioforge-lab.sh cleanup [--dry-run] [--force] [--yes]
  install-scenarioforge-lab.sh --cleanup [--dry-run] [--force] [--yes]
  install-scenarioforge-lab.sh --help

Provision three cloud-image VMs on the current Proxmox VE node:
  - Debian 12 + CORE GUI/XFCE from raistlinJ/core via coreemu-minimal --from-source
  - Ubuntu 24.04 + XFCE and a native ScenarioForge Python service behind nginx
  - Debian 12 + a minimal XFCE participant desktop

Important options:
  --config FILE                Read lower-precedence key=value options from FILE
  --storage ID                 VM disk storage (default: local-lvm)
  --snippet-storage ID         Directory storage for Cloud-Init snippets (default: local)
  --uplink-bridge NAME         Existing LAN/Internet bridge (default: vmbr0)
  --management-bridge NAME     Isolated CORE management bridge (default: sfmgmt0)
  --hitl-bridge NAME           Isolated participant/HITL bridge (default: sfhitl0)
  --core-vmid ID               CORE VMID (default: 9401)
  --app-vmid ID                ScenarioForge VMID (default: 9402)
  --participant-vmid ID        Participant VMID (default: 9403)
  --ssh-public-key FILE        Add one OpenSSH public key to all guest users
  --core-password PASSWORD     Set the corevm password (default: generated)
  --app-password PASSWORD      Set the scenarioforge VM password (default: generated)
  --participant-password PASS  Set the participant password (default: generated)
  --web-admin-password PASS    Set the coreadmin Web UI password (default: generated)
  --flag-generators            Install raistlinJ/flag-generators catalogs on APP
  --vulnhub                    Install the repo's Vulhub vulnerability snapshot on APP
  --wait-minutes N             Bootstrap timeout (default: 90)
  --no-wait                    Return after the participant's temporary uplink is removed
  --verbose                    Show detailed progress and guest bootstrap activity
  --watch                      Keep printing status until all three guests are ready
  --interval SECONDS           Status watch interval (default: 10, minimum: 2)
  --yes                        Do not ask for confirmation
  --dry-run                    Validate and print mutations without applying them
  --cleanup                    Alias for the cleanup command
  --force                      Allow cleanup of a healthy, running completed lab

Network/address overrides:
  --app-management-cidr CIDR   Default: 172.31.250.2/24
  --core-management-cidr CIDR  Default: 172.31.250.3/24
  --core-hitl-cidr CIDR        Default: 10.254.200.3/24
  --participant-cidr CIDR      Default: 10.254.200.10/24

Repository overrides:
  --core-minimal-ref REF       Default: main
  --core-ref REF               Default: master
  --scenarioforge-ref REF      Default: main
  --flag-generators-ref REF    Default: tested metadata snapshot 5f612eecb8ff

Environment variables with the SF_ prefix can set every default; see
scripts/proxmox/README.md for the complete list and config-file format.
EOF
}

parse_args() {
    load_config_from_args apply_proxmox_config_value "$@"
    if [[ $# -gt 0 && "$1" != -* ]]; then
        COMMAND="$1"
        shift
    fi

    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) usage; exit 0 ;;
            --version) printf '%s\n' "$SCRIPT_VERSION"; exit 0 ;;
            --config) [[ $# -ge 2 ]] || die "--config requires a file"; shift 2 ;;
            --config=*) shift ;;
            --storage) VM_STORAGE="${2:?missing value for --storage}"; shift 2 ;;
            --snippet-storage) SNIPPET_STORAGE="${2:?missing value for --snippet-storage}"; shift 2 ;;
            --uplink-bridge) UPLINK_BRIDGE="${2:?missing value for --uplink-bridge}"; shift 2 ;;
            --management-bridge) MANAGEMENT_BRIDGE="${2:?missing value for --management-bridge}"; shift 2 ;;
            --hitl-bridge) HITL_BRIDGE="${2:?missing value for --hitl-bridge}"; shift 2 ;;
            --core-vmid) CORE_VMID="${2:?missing value for --core-vmid}"; shift 2 ;;
            --app-vmid) APP_VMID="${2:?missing value for --app-vmid}"; shift 2 ;;
            --participant-vmid) PARTICIPANT_VMID="${2:?missing value for --participant-vmid}"; shift 2 ;;
            --ssh-public-key) SSH_PUBLIC_KEY_FILE="${2:?missing value for --ssh-public-key}"; shift 2 ;;
            --core-password) REQUESTED_CORE_PASSWORD="${2:?missing value for --core-password}"; shift 2 ;;
            --app-password) REQUESTED_APP_PASSWORD="${2:?missing value for --app-password}"; shift 2 ;;
            --participant-password) REQUESTED_PARTICIPANT_PASSWORD="${2:?missing value for --participant-password}"; shift 2 ;;
            --web-admin-password) REQUESTED_WEB_ADMIN_PASSWORD="${2:?missing value for --web-admin-password}"; shift 2 ;;
            --flag-generators) INSTALL_FLAG_GENERATORS=1; shift ;;
            --vulnhub) INSTALL_VULNHUB=1; shift ;;
            --wait-minutes) WAIT_MINUTES="${2:?missing value for --wait-minutes}"; shift 2 ;;
            --app-management-cidr) APP_MANAGEMENT_CIDR="${2:?missing value for --app-management-cidr}"; shift 2 ;;
            --core-management-cidr) CORE_MANAGEMENT_CIDR="${2:?missing value for --core-management-cidr}"; shift 2 ;;
            --core-hitl-cidr) CORE_HITL_CIDR="${2:?missing value for --core-hitl-cidr}"; shift 2 ;;
            --participant-cidr) PARTICIPANT_CIDR="${2:?missing value for --participant-cidr}"; shift 2 ;;
            --core-minimal-ref) CORE_MINIMAL_REF="${2:?missing value for --core-minimal-ref}"; shift 2 ;;
            --core-ref) CORE_REPO_REF="${2:?missing value for --core-ref}"; shift 2 ;;
            --scenarioforge-ref) SCENARIOFORGE_REF="${2:?missing value for --scenarioforge-ref}"; shift 2 ;;
            --flag-generators-ref) FLAG_GENERATORS_REF="${2:?missing value for --flag-generators-ref}"; shift 2 ;;
            --no-wait) WAIT_FOR_BOOTSTRAP=0; shift ;;
            --verbose) VERBOSE=1; shift ;;
            --watch) STATUS_WATCH=1; shift ;;
            --interval) STATUS_INTERVAL="${2:?missing value for --interval}"; shift 2 ;;
            --yes) ASSUME_YES=1; shift ;;
            --dry-run) DRY_RUN=1; shift ;;
            --cleanup) COMMAND="cleanup"; shift ;;
            --force) FORCE_CLEANUP=1; shift ;;
            *) die "unknown argument: $1" ;;
        esac
    done

    [[ "$COMMAND" == "install" || "$COMMAND" == "status" || "$COMMAND" == "cleanup" ]] || die "unknown command: $COMMAND"
    [[ "$VERBOSE" == "0" || "$VERBOSE" == "1" ]] || die "SF_VERBOSE must be 0 or 1"
    [[ "$INSTALL_FLAG_GENERATORS" == "0" || "$INSTALL_FLAG_GENERATORS" == "1" ]] \
        || die "SF_INSTALL_FLAG_GENERATORS must be 0 or 1"
    [[ "$INSTALL_VULNHUB" == "0" || "$INSTALL_VULNHUB" == "1" ]] \
        || die "SF_INSTALL_VULNHUB must be 0 or 1"
    [[ "$STATUS_WATCH" -eq 0 || "$COMMAND" == "status" ]] || die "--watch is only valid with the status command"
    [[ "$FORCE_CLEANUP" -eq 0 || "$COMMAND" == "cleanup" ]] || die "--force is only valid with the cleanup command"
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

validate_password_override() {
    local label="$1" value="$2"
    [[ -n "$value" ]] || return 0
    (( ${#value} <= 256 )) || die "$label must not exceed 256 characters"
    [[ "$value" != *$'\n'* && "$value" != *$'\r'* ]] \
        || die "$label must not contain newline characters"
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
    validate_ref "flag-generators ref" "$FLAG_GENERATORS_REF"
    validate_password_override "CORE password" "$REQUESTED_CORE_PASSWORD"
    validate_password_override "APP password" "$REQUESTED_APP_PASSWORD"
    validate_password_override "participant password" "$REQUESTED_PARTICIPANT_PASSWORD"
    validate_password_override "Web administrator password" "$REQUESTED_WEB_ADMIN_PASSWORD"
    [[ "$CORE_MINIMAL_URL" == https://* && "$CORE_REPO_URL" == https://* && "$SCENARIOFORGE_URL" == https://* ]] \
        || die "repository URLs must use HTTPS"
    [[ "$FLAG_GENERATORS_URL" == https://* || "$FLAG_GENERATORS_URL" == ssh://* \
        || "$FLAG_GENERATORS_URL" == git@*:* ]] \
        || die "flag-generators URL must use HTTPS or SSH"
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
    validate_network_reload

    config="$(storage_config "$VM_STORAGE")"
    [[ "$(storage_field "$config" disable)" != "1" ]] || die "storage '$VM_STORAGE' is disabled"
    storage_has_content "$config" images || die "storage '$VM_STORAGE' does not allow VM images"

    config="$(storage_config "$SNIPPET_STORAGE")"
    [[ "$(storage_field "$config" disable)" != "1" ]] || die "storage '$SNIPPET_STORAGE' is disabled"
    [[ "$(storage_field "$config" type)" == "dir" ]] \
        || die "snippet storage '$SNIPPET_STORAGE' must be directory-backed"
    verbose "Preflight passed: VMIDs are free, uplink exists, and storage capabilities are compatible"
}

validate_network_reload() {
    local version_output
    command -v ifreload >/dev/null 2>&1 \
        || die "ifupdown2 is required to apply bridge changes without rebooting; install it from the configured Proxmox repositories"
    if ! version_output="$(ifreload -V 2>&1)"; then
        die "could not query ifupdown2 with 'ifreload -V': ${version_output:-no output}"
    fi
    [[ "$version_output" == *ifupdown2:* ]] \
        || die "ifreload did not report an ifupdown2 version: $version_output"
    [[ "$version_output" =~ (pve|pmx|proxmox) ]] \
        || die "incompatible ifupdown2 build '$version_output'; install the supported package from the configured Proxmox repositories"
    verbose "Compatible network reload tool detected: $version_output"
}

confirm_install() {
    log "Proxmox node:        $PVE_NODE"
    log "VM storage:         $VM_STORAGE"
    log "Cloud-Init snippets:$SNIPPET_STORAGE"
    log "VMIDs:              CORE=$CORE_VMID APP=$APP_VMID PARTICIPANT=$PARTICIPANT_VMID"
    log "Bridges:            uplink=$UPLINK_BRIDGE management=$MANAGEMENT_BRIDGE HITL=$HITL_BRIDGE"
    log "Addresses:          app=$APP_MANAGEMENT_CIDR core=$CORE_MANAGEMENT_CIDR participant=$PARTICIPANT_CIDR"
    verbose "Repositories: coreemu-minimal=$CORE_MINIMAL_REF CORE=$CORE_REPO_REF ScenarioForge=$SCENARIOFORGE_REF"
    if [[ "$INSTALL_FLAG_GENERATORS" == "1" || "$INSTALL_VULNHUB" == "1" ]]; then
        log "Optional content:     flag-generators=$INSTALL_FLAG_GENERATORS vulnhub=$INSTALL_VULNHUB (ref $FLAG_GENERATORS_REF)"
    fi
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
        if [[ "$bridge" == "$MANAGEMENT_BRIDGE" ]]; then
            CREATED_MANAGEMENT_BRIDGE=0
        else
            CREATED_HITL_BRIDGE=0
        fi
        if [[ -f "$STATE_FILE" ]]; then
            write_state
        fi
        return 0
    fi
    log "Creating isolated bridge $bridge"
    if [[ "$bridge" == "$MANAGEMENT_BRIDGE" ]]; then
        CREATED_MANAGEMENT_BRIDGE=creating
    else
        CREATED_HITL_BRIDGE=creating
    fi
    if [[ -f "$STATE_FILE" ]]; then
        write_state
    fi
    run pvesh create "/nodes/$PVE_NODE/network" \
        --iface "$bridge" --type bridge --autostart 1 --comments "$description"
    if [[ "$bridge" == "$MANAGEMENT_BRIDGE" ]]; then
        CREATED_MANAGEMENT_BRIDGE=1
    else
        CREATED_HITL_BRIDGE=1
    fi
    if [[ -f "$STATE_FILE" ]]; then
        write_state
    fi
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
    log "Applying ScenarioForge bridge changes"
    local task_payload upid error_file line apply_exit
    error_file="$(mktemp /tmp/scenarioforge-network-apply.XXXXXX)"
    if task_payload="$(pvesh set "/nodes/$PVE_NODE/network" --output-format json 2>"$error_file")"; then
        while IFS= read -r line; do
            [[ -z "$line" ]] || verbose "Proxmox network apply: $line"
        done < "$error_file"
    else
        apply_exit=$?
        while IFS= read -r line; do
            [[ -z "$line" ]] || warn "Proxmox network apply: $line"
        done <<<"$task_payload"
        while IFS= read -r line; do
            [[ -z "$line" ]] || warn "Proxmox network apply: $line"
        done < "$error_file"
        rm -f -- "$error_file"
        die "Proxmox rejected the network reload (exit $apply_exit); staged changes remain unapplied"
    fi
    rm -f -- "$error_file"
    upid="$(python3 -c '
import json
import sys
value = json.load(sys.stdin)
print(value.get("data", "") if isinstance(value, dict) else value)
' <<<"$task_payload")"
    [[ -n "$upid" ]] || die "Proxmox did not return a task ID while applying network configuration"
    wait_for_pve_task "$upid"
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

prepare_optional_content() {
    [[ "$INSTALL_FLAG_GENERATORS" == "1" || "$INSTALL_VULNHUB" == "1" ]] || return 0
    local command_name source_dir staging_dir
    for command_name in git tar ssh-keygen ssh scp; do
        command -v "$command_name" >/dev/null 2>&1 \
            || die "--flag-generators/--vulnhub requires host command: $command_name"
    done
    [[ "$FLAG_GENERATORS_URL" != https://*@* ]] \
        || die "do not embed credentials in SF_FLAG_GENERATORS_URL; configure the host Git credential helper or use an SSH URL"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        emit DRY-RUN "clone authenticated flag-generators ref $FLAG_GENERATORS_REF and prepare the requested APP payload"
        return 0
    fi

    source_dir="$WORK_DIR/flag-generators-source"
    staging_dir="$WORK_DIR/optional-content"
    log "Cloning the private flag-generators repository on the installer host (ref $FLAG_GENERATORS_REF)"
    git init --quiet "$source_dir"
    git -C "$source_dir" remote add origin "$FLAG_GENERATORS_URL"
    if ! git -C "$source_dir" fetch --quiet --depth 1 origin "$FLAG_GENERATORS_REF" \
        || ! git -C "$source_dir" checkout --quiet --detach FETCH_HEAD; then
        die "could not clone flag-generators; authenticate GitHub on the installer host or set SF_FLAG_GENERATORS_URL to an authorized SSH URL"
    fi
    FLAG_GENERATORS_RESOLVED_COMMIT="$(git -C "$source_dir" rev-parse HEAD)"
    log "Resolved flag-generators ref to $FLAG_GENERATORS_RESOLVED_COMMIT"
    if [[ "$FLAG_GENERATORS_RESOLVED_COMMIT" == "$TESTED_FLAG_GENERATORS_COMMIT" ]]; then
        log "The optional content matches the tested snapshot; portable catalog metadata will be verified"
    else
        warn "The optional content does not match the tested snapshot; its own portable catalog metadata, if present, will be imported"
    fi
    install -d -m 0700 "$staging_dir"
    if [[ "$INSTALL_FLAG_GENERATORS" == "1" ]]; then
        [[ -d "$source_dir/flag_generators" && -d "$source_dir/flag_node_generators" ]] \
            || die "flag-generators ref $FLAG_GENERATORS_REF is missing its generator catalog directories"
        cp -a -- "$source_dir/flag_generators" "$source_dir/flag_node_generators" "$staging_dir/"
        if [[ -f "$source_dir/pack.json" ]]; then
            cp -a -- "$source_dir/pack.json" "$staging_dir/"
        elif [[ "$FLAG_GENERATORS_RESOLVED_COMMIT" == "$TESTED_FLAG_GENERATORS_COMMIT" ]]; then
            die "tested flag-generators snapshot is missing pack.json metadata"
        else
            warn "custom flag-generators ref has no pack.json; validation, curation, and authored notes cannot be imported"
        fi
    fi
    if [[ "$INSTALL_VULNHUB" == "1" ]]; then
        [[ -d "$source_dir/vulnhub/content" ]] \
            || die "flag-generators ref $FLAG_GENERATORS_REF is missing vulnhub/content"
        cp -a -- "$source_dir/vulnhub" "$staging_dir/"
    fi
    OPTIONAL_CONTENT_ARCHIVE="$WORK_DIR/scenarioforge-optional-content.tar.gz"
    tar -C "$staging_dir" -czf "$OPTIONAL_CONTENT_ARCHIVE" .
    OPTIONAL_CONTENT_SHA256="$(sha256sum "$OPTIONAL_CONTENT_ARCHIVE" | awk '{print $1}')"
    CATALOG_TRANSFER_KEY="$WORK_DIR/catalog-transfer-key"
    ssh-keygen -q -t ed25519 -N '' -C scenarioforge-installer-transfer -f "$CATALOG_TRANSFER_KEY"
    CATALOG_TRANSFER_PUBLIC_KEY_FILE="$CATALOG_TRANSFER_KEY.pub"
    log "Prepared requested optional content ($(du -h "$OPTIONAL_CONTENT_ARCHIVE" | awk '{print $1}')) without embedding GitHub credentials in a guest"
}

random_password() {
    local password="" chunk
    while (( ${#password} < 10 )); do
        chunk="$(openssl rand -base64 12 | tr -dc 'A-Za-z0-9')"
        password+="$chunk"
    done
    printf '%s\n' "${password:0:10}"
}

random_mac() {
    local hex
    hex="$(openssl rand -hex 5)"
    printf '02:%s:%s:%s:%s:%s\n' "${hex:0:2}" "${hex:2:2}" "${hex:4:2}" "${hex:6:2}" "${hex:8:2}"
}

shell_assignment() {
    printf '%s=%q\n' "$1" "$2"
}

write_runtime_status() {
    local runtime_state="$1" phase="$2" detail="$3" runtime_dir
    runtime_dir="${RUNTIME_STATUS_FILE%/*}"
    if [[ "$RUNTIME_STATUS_FILE" != /* || -z "$runtime_dir" || "$runtime_dir" == "/" ]]; then
        warn "cannot write runtime status to unsafe path: $RUNTIME_STATUS_FILE"
        return 0
    fi
    if ! install -d -m 0755 "$runtime_dir"; then
        warn "cannot create runtime status directory: $runtime_dir"
        return 0
    fi
    if ! {
        shell_assignment RUNTIME_PID "$$"
        shell_assignment RUNTIME_STATE "$runtime_state"
        shell_assignment RUNTIME_PERCENT "${INSTALL_PERCENT:-0}"
        shell_assignment RUNTIME_PHASE "$phase"
        shell_assignment RUNTIME_DETAIL "$detail"
        shell_assignment RUNTIME_UPDATED "$(timestamp)"
    } > "$RUNTIME_STATUS_TEMP_FILE"; then
        warn "cannot write runtime status: $RUNTIME_STATUS_TEMP_FILE"
        return 0
    fi
    if ! chmod 0600 "$RUNTIME_STATUS_TEMP_FILE" \
        || ! mv -f -- "$RUNTIME_STATUS_TEMP_FILE" "$RUNTIME_STATUS_FILE"; then
        warn "cannot publish runtime status: $RUNTIME_STATUS_FILE"
    fi
    return 0
}

record_install_phase() {
    INSTALL_PHASE="$*"
    if [[ "$COMMAND" == "install" && "$DRY_RUN" -eq 0 \
        && "$INSTALL_STATE_INITIALIZED" -eq 1 && -f "$STATE_FILE" ]]; then
        write_state
    fi
}

encode_file() {
    base64 < "$1" | tr -d '\n'
}

public_key_yaml() {
    local include_transfer_key="${1:-0}" key_file wrote_header=0
    local -a key_files=("$SSH_PUBLIC_KEY_FILE")
    if [[ "$include_transfer_key" == "1" ]]; then
        key_files+=("$CATALOG_TRANSFER_PUBLIC_KEY_FILE")
    fi
    for key_file in "${key_files[@]}"; do
        [[ -n "$key_file" ]] || continue
        if [[ "$wrote_header" -eq 0 ]]; then
            printf '    ssh_authorized_keys:\n'
            wrote_header=1
        fi
        printf '      - '\''%s'\''\n' "$(<"$key_file")"
    done
}

write_guest_bootstraps() {
    cat > "$WORK_DIR/core-bootstrap.sh" <<'CORE_SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
exec > >(tee -a /var/log/scenarioforge-core-bootstrap.log) 2>&1
source /etc/scenarioforge-installer.env

# Docker's daemon performs registry lookups from the host namespace. On VMware,
# querying Fusion's DNS proxy directly can return spurious NXDOMAIN responses,
# while systemd-resolved handles the same upstream correctly.
if [[ "${CORE_USE_SYSTEMD_RESOLVED_STUB:-0}" == 1 \
    && -e /run/systemd/resolve/stub-resolv.conf ]]; then
    ln -sfn /run/systemd/resolve/stub-resolv.conf /etc/resolv.conf
    systemctl restart systemd-resolved
fi

install -d -m 0755 /var/lib/scenarioforge
set_bootstrap_status() {
    local percent="$1"
    shift
    printf '%s\n' "$percent" > /var/lib/scenarioforge/bootstrap-percent
    printf '%s\n' "$*" > /var/lib/scenarioforge/bootstrap-status
    printf 'BOOTSTRAP [%s%%]: %s\n' "$percent" "$*"
}
on_bootstrap_error() {
    local exit_code="$1" line="$2" command="${3:-unknown command}" percent=0
    trap - ERR
    [[ ! -f /var/lib/scenarioforge/bootstrap-percent ]] \
        || read -r percent < /var/lib/scenarioforge/bootstrap-percent
    set_bootstrap_status "$percent" "failed (exit $exit_code at bootstrap line $line: $command)"
    exit "$exit_code"
}
fail_bootstrap() {
    local percent=0
    [[ ! -f /var/lib/scenarioforge/bootstrap-percent ]] \
        || read -r percent < /var/lib/scenarioforge/bootstrap-percent
    set_bootstrap_status "$percent" "failed: $*"
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}
trap 'on_bootstrap_error "$?" "$LINENO" "$BASH_COMMAND"' ERR

export DEBIAN_FRONTEND=noninteractive
set_bootstrap_status 5 'preparing coreemu-minimal source installer'
install -d -m 0755 /opt/bootstrap
if [[ ! -d /opt/bootstrap/coreemu-minimal/.git ]]; then
    git clone --branch "$CORE_MINIMAL_REF" "$CORE_MINIMAL_URL" /opt/bootstrap/coreemu-minimal
fi

cd /opt/bootstrap/coreemu-minimal/9.2.1
set_bootstrap_status 10 'installing system packages and building CORE from source'
printf 'n\n' | ./setup-coreemu9.2.1.sh --from-source "$CORE_REPO_URL" "$CORE_REPO_REF"

if [[ "$(dpkg --print-architecture)" == arm64 ]]; then
    set_bootstrap_status 60 'installing amd64 container emulation with QEMU/binfmt'
    apt-get update
    apt-get install -y --no-install-recommends qemu-user-static binfmt-support
    systemctl restart systemd-binfmt.service
    if command -v update-binfmts >/dev/null 2>&1; then
        update-binfmts --enable qemu-x86_64
    fi
    systemctl restart binfmt-support.service || true
    command -v qemu-x86_64-static >/dev/null
    if [[ ! -r /proc/sys/fs/binfmt_misc/qemu-x86_64 ]] \
        || ! grep -q '^flags:.*F' /proc/sys/fs/binfmt_misc/qemu-x86_64; then
        fail_bootstrap 'amd64 QEMU binfmt handler is unavailable or missing the fix-binary flag'
    fi
fi

set_bootstrap_status 65 'configuring the CORE XFCE desktop and graphical client'
command -v core-gui >/dev/null
systemctl set-default graphical.target
systemctl enable --now lightdm
install -d -o corevm -g corevm -m 0755 /home/corevm/Desktop
cat > /home/corevm/Desktop/core-gui.desktop <<'CORE_DESKTOP'
[Desktop Entry]
Type=Application
Name=CORE Network Emulator
Comment=Create and run CORE network scenarios
Exec=/usr/bin/core-gui
Icon=applications-engineering
Terminal=false
Categories=Education;Network;
CORE_DESKTOP
chown corevm:corevm /home/corevm/Desktop/core-gui.desktop
chmod 0755 /home/corevm/Desktop/core-gui.desktop

set_bootstrap_status 70 'configuring Docker for CORE networking'
install -d -m 0755 /etc/docker
if [[ -s /etc/docker/daemon.json ]]; then
    jq '. + {"bridge":"none","iptables":false}' /etc/docker/daemon.json > /etc/docker/daemon.json.new
else
    printf '%s\n' '{"bridge":"none","iptables":false}' > /etc/docker/daemon.json.new
fi
install -m 0644 /etc/docker/daemon.json.new /etc/docker/daemon.json
rm -f /etc/docker/daemon.json.new

set_bootstrap_status 75 'installing ScenarioForge custom CORE services'
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

set_bootstrap_status 85 'restarting Docker and core-daemon'
systemctl restart docker
systemctl is-active --quiet docker
systemctl restart core-daemon

grpc_ready() {
    timeout 2 bash -c '</dev/tcp/'"$CORE_MANAGEMENT_IP"'/50051' 2>/dev/null
}

set_bootstrap_status 90 'waiting for core-daemon gRPC on 0.0.0.0:50051'
core_ready=0
for attempt in $(seq 1 60); do
    if systemctl is-active --quiet core-daemon && grpc_ready; then
        core_ready=1
        break
    fi
    if systemctl is-failed --quiet core-daemon; then
        break
    fi
    sleep 2
done
if [[ "$core_ready" -ne 1 ]]; then
    echo "core-daemon did not accept IPv4 TCP connections at $CORE_MANAGEMENT_IP:50051" >&2
    systemctl status core-daemon --no-pager -l || true
    journalctl -u core-daemon -n 100 --no-pager || true
    ss -lntp || true
    fail_bootstrap "core-daemon did not accept IPv4 TCP connections at $CORE_MANAGEMENT_IP:50051"
fi

set_bootstrap_status 97 'verifying the CORE HITL interface'
if ip -4 addr show dev ens19 | grep -q 'inet '; then
    fail_bootstrap 'ens19 unexpectedly has an IPv4 address'
fi
if ! systemctl is-active --quiet lightdm; then
    set_bootstrap_status 98 'restarting and verifying the CORE XFCE graphical login'
    systemctl reset-failed lightdm || true
    systemctl restart lightdm || true
    for attempt in $(seq 1 15); do
        systemctl is-active --quiet lightdm && break
        sleep 2
    done
fi
if ! systemctl is-active --quiet lightdm; then
    systemctl status lightdm --no-pager -l || true
    journalctl -u lightdm -n 100 --no-pager || true
    tail -n 100 /var/log/lightdm/lightdm.log /var/log/lightdm/x-0.log 2>/dev/null || true
    fail_bootstrap 'CORE XFCE graphical login did not become active'
fi
command -v core-gui >/dev/null

touch /var/lib/scenarioforge/core-ready
set_bootstrap_status 100 'ready'
echo 'CORE provisioning complete.'
CORE_SCRIPT

    cat > "$WORK_DIR/app-bootstrap.sh" <<'APP_SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
exec > >(tee -a /var/log/scenarioforge-app-bootstrap.log) 2>&1
source /etc/scenarioforge-installer.env

install -d -m 0755 /var/lib/scenarioforge
set_bootstrap_status() {
    local percent="$1"
    shift
    printf '%s\n' "$percent" > /var/lib/scenarioforge/bootstrap-percent
    printf '%s\n' "$*" > /var/lib/scenarioforge/bootstrap-status
    printf 'BOOTSTRAP [%s%%]: %s\n' "$percent" "$*"
}
on_bootstrap_error() {
    local exit_code="$1" line="$2" command="${3:-unknown command}" percent=0
    trap - ERR
    [[ ! -f /var/lib/scenarioforge/bootstrap-percent ]] \
        || read -r percent < /var/lib/scenarioforge/bootstrap-percent
    set_bootstrap_status "$percent" "failed (exit $exit_code at bootstrap line $line: $command)"
    exit "$exit_code"
}
fail_bootstrap() {
    local percent=0
    [[ ! -f /var/lib/scenarioforge/bootstrap-percent ]] \
        || read -r percent < /var/lib/scenarioforge/bootstrap-percent
    set_bootstrap_status "$percent" "failed: $*"
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}
trap 'on_bootstrap_error "$?" "$LINENO" "$BASH_COMMAND"' ERR

export DEBIAN_FRONTEND=noninteractive
set_bootstrap_status 5 'installing XFCE and native ScenarioForge system packages'
apt-get update
apt-get install -y --no-install-recommends \
    build-essential dbus-x11 epiphany-browser evince graphviz jq lightdm lightdm-gtk-greeter \
    mousepad nginx openssl python3-dev python3-full python3-venv terminator xdot xfce4 xorg \
    x11-xserver-utils xserver-xorg-input-all xserver-xorg-video-all xterm
# GNU install applies ownership only to explicitly named directories. Name
# .config too: a root-owned parent prevents xfconfd from creating its settings
# and XFCE reports "Unable to load a failsafe session" at first login.
install -d -o scenarioforge -g scenarioforge -m 0755 \
    /home/scenarioforge/.config /home/scenarioforge/.config/autostart
systemctl set-default graphical.target
systemctl enable --now lightdm
for desktop_command in epiphany evince jq mousepad terminator xdot; do
    command -v "$desktop_command" >/dev/null
done
cat > /usr/share/applications/scenarioforge-json-viewer.desktop <<'JSON_VIEWER_DESKTOP'
[Desktop Entry]
Type=Application
Name=JSON Viewer
Comment=View JSON files in the lightweight Mousepad editor
Exec=mousepad %F
Icon=text-x-json
Terminal=false
MimeType=application/json;application/ld+json;
Categories=Utility;TextEditor;
StartupNotify=true
JSON_VIEWER_DESKTOP
install -d -o scenarioforge -g scenarioforge -m 0755 /home/scenarioforge/Desktop
cat > /home/scenarioforge/Desktop/scenarioforge.desktop <<'SCENARIOFORGE_DESKTOP'
[Desktop Entry]
Type=Application
Name=ScenarioForge
Comment=Open the local ScenarioForge Web GUI
Exec=epiphany https://localhost/
Icon=web-browser
Terminal=false
Categories=Education;Network;WebBrowser;
SCENARIOFORGE_DESKTOP
chown scenarioforge:scenarioforge /home/scenarioforge/Desktop/scenarioforge.desktop
chmod 0755 /home/scenarioforge/Desktop/scenarioforge.desktop

# Start the APP desktop at a useful working size while preserving VMware/SPICE
# dynamic resize support. Never shrink an already larger display, and tolerate
# hypervisors that do not advertise every fallback mode.
cat > /usr/local/bin/scenarioforge-app-display <<'APP_DISPLAY_SCRIPT'
#!/bin/sh
command -v xrandr >/dev/null 2>&1 || exit 0
output="$(xrandr --query 2>/dev/null | awk '$2 == "connected" { print $1; exit }')"
[ -n "$output" ] || exit 0
current="$(xrandr --query 2>/dev/null | awk '$2 == "connected" { for (i = 3; i <= NF; i++) if ($i ~ /^[0-9]+x[0-9]+\+/) { split($i, size, /[x+]/); print size[1], size[2]; exit } }')"
set -- $current
if [ "${1:-0}" -ge 1600 ] 2>/dev/null && [ "${2:-0}" -ge 900 ] 2>/dev/null; then
    exit 0
fi
for mode in 1600x900 1440x900 1366x768; do
    xrandr --output "$output" --mode "$mode" >/dev/null 2>&1 && exit 0
done
exit 0
APP_DISPLAY_SCRIPT
chmod 0755 /usr/local/bin/scenarioforge-app-display
cat > /home/scenarioforge/.config/autostart/scenarioforge-display.desktop <<'APP_DISPLAY_DESKTOP'
[Desktop Entry]
Type=Application
Name=ScenarioForge display setup
Comment=Set a comfortable initial APP desktop resolution
Exec=/usr/local/bin/scenarioforge-app-display
OnlyShowIn=XFCE;
NoDisplay=true
X-GNOME-Autostart-enabled=true
APP_DISPLAY_DESKTOP
chown scenarioforge:scenarioforge /home/scenarioforge/.config/autostart/scenarioforge-display.desktop

set_bootstrap_status 20 'cloning the ScenarioForge repository'
if [[ ! -d /opt/scenarioforge/.git ]]; then
    git clone --branch "$SCENARIOFORGE_REF" "$SCENARIOFORGE_URL" /opt/scenarioforge
else
    git -C /opt/scenarioforge fetch origin "$SCENARIOFORGE_REF"
    git -C /opt/scenarioforge checkout "$SCENARIOFORGE_REF"
    git -C /opt/scenarioforge pull --ff-only origin "$SCENARIOFORGE_REF"
fi
chown -R scenarioforge:scenarioforge /opt/scenarioforge

set_bootstrap_status 27 'installing uv for ScenarioForge dependency management'
python3 -m venv /opt/uv
/opt/uv/bin/python -m pip install --disable-pip-version-check --no-cache-dir --upgrade uv
ln -sfn /opt/uv/bin/uv /usr/local/bin/uv
ln -sfn /opt/uv/bin/uvx /usr/local/bin/uvx
uv --version

set_bootstrap_status 30 'synchronizing the native ScenarioForge Python environment with uv'
runuser -u scenarioforge -- env HOME=/home/scenarioforge UV_CACHE_DIR=/home/scenarioforge/.cache/uv \
    uv sync --frozen --no-dev --project /opt/scenarioforge

install_optional_content() {
    [[ "$INSTALL_FLAG_GENERATORS" == "1" || "$INSTALL_VULNHUB" == "1" ]] || return 0
    local archive=/tmp/scenarioforge-optional-content.tar.gz payload_dir generator_zip vulnhub_zip
    set_bootstrap_status 45 'waiting for requested generator/vulnerability content from the installer host'
    for attempt in $(seq 1 180); do
        [[ -f "$archive" ]] && break
        [[ "$attempt" -ne 180 ]] || fail_bootstrap 'optional content transfer did not arrive within 15 minutes'
        sleep 5
    done
    [[ "$(sha256sum "$archive" | awk '{print $1}')" == "$OPTIONAL_CONTENT_SHA256" ]] \
        || fail_bootstrap 'optional content archive checksum mismatch'
    if [[ -f /home/scenarioforge/.ssh/authorized_keys ]]; then
        sed -i '/[[:space:]]scenarioforge-installer-transfer$/d' \
            /home/scenarioforge/.ssh/authorized_keys
    fi
    payload_dir="$(mktemp -d /tmp/scenarioforge-optional.XXXXXX)"
    tar -xzf "$archive" -C "$payload_dir"
    rm -f -- "$archive"

    if [[ "$INSTALL_FLAG_GENERATORS" == "1" ]]; then
        set_bootstrap_status 50 'importing flag-generator and flag-node-generator catalogs'
        [[ -d "$payload_dir/flag_generators" && -d "$payload_dir/flag_node_generators" ]] \
            || fail_bootstrap 'optional payload is missing generator catalogs'
        generator_zip=/tmp/scenarioforge-generator-catalogs.zip
        python3 - "$payload_dir" "$generator_zip" <<'GENERATOR_ZIP'
from pathlib import Path
import sys
import zipfile

source = Path(sys.argv[1])
with zipfile.ZipFile(sys.argv[2], "w", compression=zipfile.ZIP_DEFLATED) as archive:
    metadata = source / "pack.json"
    if metadata.is_file():
        archive.write(metadata, "pack.json")
    for catalog_dir in ("flag_generators", "flag_node_generators"):
        for path in (source / catalog_dir).rglob("*"):
            if path.is_file():
                archive.write(path, path.relative_to(source).as_posix())
GENERATOR_ZIP
        chown scenarioforge:scenarioforge "$generator_zip"
        runuser -u scenarioforge -- env \
            HOME=/home/scenarioforge PYTHONPATH=/opt/scenarioforge \
            /opt/scenarioforge/.venv/bin/python - "$generator_zip" \
            "$FLAG_GENERATORS_RESOLVED_COMMIT" "$TESTED_FLAG_GENERATORS_COMMIT" <<'GENERATOR_INSTALL'
import sys
from webapp import app_backend

ok, note = app_backend._install_generator_pack_or_bundle(
    zip_path=sys.argv[1],
    pack_label="raistlinJ flag-generators",
    pack_origin="https://github.com/raistlinJ/flag-generators",
)
if not ok:
    raise SystemExit(f"Generator catalog import failed: {note}")

resolved_commit = str(sys.argv[2] or "").strip()
tested_commit = str(sys.argv[3] or "").strip()
state = app_backend._load_installed_generator_packs_state()
packs = state.get("packs") if isinstance(state, dict) else []
target_pack = next((pack for pack in reversed(packs or []) if isinstance(pack, dict)), None)
installed = target_pack.get("installed") if isinstance(target_pack, dict) else None
if not isinstance(installed, list):
    raise SystemExit("Could not find imported generator pack state")
validated = sum(item.get("validated_ok") is True for item in installed if isinstance(item, dict))
disabled = sum(bool(item.get("disabled")) for item in installed if isinstance(item, dict))
enabled_node = sum(
    str(item.get("kind") or "") == "flag-node-generator" and not bool(item.get("disabled"))
    for item in installed
    if isinstance(item, dict)
)
if resolved_commit == tested_commit and (
    len(installed) != 148 or validated != 147 or disabled != 4 or enabled_node != 85
):
    raise SystemExit(
        "Tested generator metadata did not produce the expected state: "
        f"total={len(installed)}, validated={validated}, disabled={disabled}, "
        f"enabled flag-node={enabled_node}"
    )
print(
    f"Imported portable generator metadata: {validated}/{len(installed)} validated, "
    f"{len(installed) - disabled} enabled, {disabled} disabled"
)

flag_generators, flag_errors = app_backend._flag_generators_from_all_installed_sources()
node_generators, node_errors = app_backend._flag_node_generators_from_all_installed_sources()
if not flag_generators or not node_generators:
    errors = [*(flag_errors or []), *(node_errors or [])]
    detail = f": {errors[0]}" if errors else ""
    raise SystemExit(
        "Generator catalog import did not expose both generator kinds" + detail
    )
print(
    f"{note}; visible catalogs contain {len(flag_generators)} flag generators "
    f"and {len(node_generators)} flag-node generators"
)
GENERATOR_INSTALL
        rm -f -- "$generator_zip"
    fi

    if [[ "$INSTALL_VULNHUB" == "1" ]]; then
        set_bootstrap_status 55 'installing the pinned Vulhub vulnerability catalog snapshot'
        [[ -d "$payload_dir/vulnhub/content" ]] \
            || fail_bootstrap 'optional payload is missing the Vulhub catalog'
        vulnhub_zip=/tmp/scenarioforge-vulnhub-catalog.zip
        python3 - "$payload_dir/vulnhub" "$vulnhub_zip" <<'VULNHUB_ZIP'
from pathlib import Path
import sys
import zipfile

source = Path(sys.argv[1])
with zipfile.ZipFile(sys.argv[2], "w", compression=zipfile.ZIP_DEFLATED) as archive:
    for path in source.rglob("*"):
        if path.is_file():
            archive.write(path, path.relative_to(source).as_posix())
VULNHUB_ZIP
        chown scenarioforge:scenarioforge "$vulnhub_zip"
        runuser -u scenarioforge -- env \
            HOME=/home/scenarioforge PYTHONPATH=/opt/scenarioforge \
            CORETG_CATALOG_ARCH_SCAN_REGISTRY=0 \
            /opt/scenarioforge/.venv/bin/python - "$vulnhub_zip" \
            "$FLAG_GENERATORS_RESOLVED_COMMIT" "$TESTED_FLAG_GENERATORS_COMMIT" <<'VULNHUB_INSTALL'
import sys
from webapp import app_backend

entry = app_backend._install_vuln_catalog_zip_file(
    zip_file_path=sys.argv[1],
    label="raistlinJ/flag-generators Vulhub snapshot",
    origin="https://github.com/raistlinJ/flag-generators",
)
if int(entry.get("compose_count") or 0) < 1:
    raise SystemExit("Vulhub import produced an empty catalog")
resolved_commit = str(sys.argv[2] or "").strip()
tested_commit = str(sys.argv[3] or "").strip()
state = app_backend._load_vuln_catalogs_state()
catalogs = state.get("catalogs") if isinstance(state, dict) else []
target = next(
    (
        catalog
        for catalog in catalogs or []
        if isinstance(catalog, dict)
        and str(catalog.get("id") or "") == str(entry.get("id") or "")
    ),
    None,
)
if target is None:
    raise SystemExit("Could not find imported Vulhub catalog state")
items = app_backend._normalize_vuln_catalog_items(target)
validated = sum(item.get("validated_ok") is True for item in items)
disabled = sum(bool(item.get("disabled")) for item in items)
if resolved_commit == tested_commit and (
    len(items) != 306 or validated != 294 or disabled != 12
):
    raise SystemExit(
        "Tested Vulhub metadata did not produce the expected state: "
        f"total={len(items)}, validated={validated}, disabled={disabled}"
    )
print(
    f"Imported portable Vulhub metadata: {validated}/{len(items)} validated, "
    f"{len(items) - disabled} enabled, {disabled} disabled"
)
print(f"Installed Vulhub catalog {entry['id']} with {entry['compose_count']} recipes")
VULNHUB_INSTALL
        rm -f -- "$vulnhub_zip"
    fi
    chown -R scenarioforge:scenarioforge \
        /opt/scenarioforge/outputs/installed_generators \
        /opt/scenarioforge/outputs/installed_vuln_catalogs 2>/dev/null || true
    rm -rf -- "$payload_dir"
    set_bootstrap_status 60 'requested generator/vulnerability content is installed'
}

install_optional_content

flask_secret="$(openssl rand -hex 32)"
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
CORETG_HOST=127.0.0.1
CORETG_PORT=9090
CORETG_USE_RELOADER=0
CORETG_SECRETS_DIR=/home/scenarioforge/.scenarioforge/secrets
FLASK_SECRET=$flask_secret
ENV_FILE
chown scenarioforge:scenarioforge /opt/scenarioforge/.scenarioforge.env
chmod 0600 /opt/scenarioforge/.scenarioforge.env

cd /opt/scenarioforge
set_bootstrap_status 65 'creating the ScenarioForge administrator account'
install -d -o scenarioforge -g scenarioforge -m 0700 \
    outputs/users /home/scenarioforge/.scenarioforge /home/scenarioforge/.scenarioforge/secrets
runuser -u scenarioforge -- env SF_BOOTSTRAP_ADMIN_PASSWORD="$SCENARIOFORGE_ADMIN_PASSWORD" \
    /opt/scenarioforge/.venv/bin/python -c 'import json, os; from pathlib import Path; from werkzeug.security import generate_password_hash; p=Path("outputs/users/users.json"); p.parent.mkdir(parents=True, exist_ok=True); p.write_text(json.dumps({"users":[{"username":"coreadmin","password_hash":generate_password_hash(os.environ["SF_BOOTSTRAP_ADMIN_PASSWORD"]),"role":"admin"}]}, indent=2))'

set_bootstrap_status 72 'configuring the native ScenarioForge systemd service'
cat > /etc/systemd/system/scenarioforge-web.service <<'APP_SERVICE'
[Unit]
Description=ScenarioForge Web Application
Wants=network-online.target
After=network-online.target

[Service]
Type=simple
User=scenarioforge
Group=scenarioforge
WorkingDirectory=/opt/scenarioforge
Environment=HOME=/home/scenarioforge
Environment=PYTHONUNBUFFERED=1
EnvironmentFile=/opt/scenarioforge/.scenarioforge.env
ExecStart=/opt/scenarioforge/.venv/bin/python -m webapp.app_backend
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
APP_SERVICE

set_bootstrap_status 78 'configuring native nginx and TLS'
install -d -m 0700 /etc/nginx/scenarioforge
openssl req -x509 -nodes -newkey rsa:3072 -days 365 \
    -keyout /etc/nginx/scenarioforge/server.key \
    -out /etc/nginx/scenarioforge/server.crt \
    -subj "/CN=$HOSTNAME"
chmod 0600 /etc/nginx/scenarioforge/server.key
cat > /etc/nginx/sites-available/scenarioforge <<'NGINX_CONFIG'
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl default_server;
    listen [::]:443 ssl default_server;
    server_name _;
    client_max_body_size 1024m;

    ssl_certificate /etc/nginx/scenarioforge/server.crt;
    ssl_certificate_key /etc/nginx/scenarioforge/server.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    location /healthz {
        access_log off;
        return 200 'ok';
        add_header Content-Type text/plain;
    }

    location / {
        proxy_pass http://127.0.0.1:9090;
        proxy_http_version 1.1;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_request_buffering off;
        proxy_buffering off;
        proxy_connect_timeout 60s;
        proxy_send_timeout 3700s;
        proxy_read_timeout 3700s;
    }
}
NGINX_CONFIG
rm -f /etc/nginx/sites-enabled/default
ln -sfn /etc/nginx/sites-available/scenarioforge /etc/nginx/sites-enabled/scenarioforge
nginx -t

set_bootstrap_status 85 'starting native ScenarioForge and nginx services'
systemctl daemon-reload
systemctl enable scenarioforge-web nginx
systemctl restart nginx
systemctl start scenarioforge-web

set_bootstrap_status 90 'waiting for the native ScenarioForge HTTPS health check'
for attempt in $(seq 1 60); do
    if systemctl is-active --quiet scenarioforge-web \
        && curl -fsS http://127.0.0.1:9090/healthz >/dev/null \
        && curl -kfsS https://127.0.0.1/healthz >/dev/null; then
        break
    fi
    if [[ "$attempt" -eq 60 ]]; then
        systemctl status scenarioforge-web nginx --no-pager -l || true
        journalctl -u scenarioforge-web -u nginx -n 100 --no-pager || true
        fail_bootstrap 'native ScenarioForge HTTPS health check did not pass within five minutes'
    fi
    sleep 5
done

set_bootstrap_status 95 'verifying the APP XFCE graphical login'
if ! runuser -u scenarioforge -- test -w /home/scenarioforge/.config; then
    ls -ld /home/scenarioforge /home/scenarioforge/.config
    fail_bootstrap 'APP XFCE configuration directory is not writable by scenarioforge'
fi
if ! systemctl is-active --quiet lightdm; then
    systemctl reset-failed lightdm || true
    systemctl restart lightdm || true
    for attempt in $(seq 1 15); do
        systemctl is-active --quiet lightdm && break
        sleep 2
    done
fi
if ! systemctl is-active --quiet lightdm; then
    systemctl status lightdm --no-pager -l || true
    journalctl -u lightdm -n 100 --no-pager || true
    tail -n 100 /var/log/lightdm/lightdm.log /var/log/lightdm/x-0.log 2>/dev/null || true
    fail_bootstrap 'APP XFCE graphical login did not become active'
fi
touch /var/lib/scenarioforge/app-ready
set_bootstrap_status 100 'ready'
echo 'ScenarioForge provisioning complete.'
APP_SCRIPT

    cat > "$WORK_DIR/participant-bootstrap.sh" <<'PARTICIPANT_SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
exec > >(tee -a /var/log/scenarioforge-participant-bootstrap.log) 2>&1

install -d -m 0755 /var/lib/scenarioforge
set_bootstrap_status() {
    local percent="$1"
    shift
    printf '%s\n' "$percent" > /var/lib/scenarioforge/bootstrap-percent
    printf '%s\n' "$*" > /var/lib/scenarioforge/bootstrap-status
    printf 'BOOTSTRAP [%s%%]: %s\n' "$percent" "$*"
}
on_bootstrap_error() {
    local exit_code="$1" line="$2" command="${3:-unknown command}" percent=0
    trap - ERR
    [[ ! -f /var/lib/scenarioforge/bootstrap-percent ]] \
        || read -r percent < /var/lib/scenarioforge/bootstrap-percent
    set_bootstrap_status "$percent" "failed (exit $exit_code at bootstrap line $line: $command)"
    exit "$exit_code"
}
fail_bootstrap() {
    local percent=0
    [[ ! -f /var/lib/scenarioforge/bootstrap-percent ]] \
        || read -r percent < /var/lib/scenarioforge/bootstrap-percent
    set_bootstrap_status "$percent" "failed: $*"
    printf 'ERROR: %s\n' "$*" >&2
    exit 1
}
trap 'on_bootstrap_error "$?" "$LINENO" "$BASH_COMMAND"' ERR

export DEBIAN_FRONTEND=noninteractive
set_bootstrap_status 10 'updating Debian package metadata'
apt-get update
set_bootstrap_status 25 'installing the minimal XFCE desktop'
apt-get install -y --no-install-recommends \
    dbus-x11 lightdm lightdm-gtk-greeter xfce4 xorg \
    xserver-xorg-input-all xserver-xorg-video-all xterm
set_bootstrap_status 85 'enabling the XFCE graphical login'
systemctl set-default graphical.target
systemctl enable --now lightdm
if ! systemctl is-active --quiet lightdm; then
    systemctl reset-failed lightdm || true
    systemctl restart lightdm || true
    for attempt in $(seq 1 15); do
        systemctl is-active --quiet lightdm && break
        sleep 2
    done
fi
if ! systemctl is-active --quiet lightdm; then
    systemctl status lightdm --no-pager -l || true
    journalctl -u lightdm -n 100 --no-pager || true
    tail -n 100 /var/log/lightdm/lightdm.log /var/log/lightdm/x-0.log 2>/dev/null || true
    fail_bootstrap 'participant XFCE graphical login did not become active'
fi

touch /var/lib/scenarioforge/participant-ready
set_bootstrap_status 100 'ready'
echo 'Participant XFCE provisioning complete.'
PARTICIPANT_SCRIPT
    chmod 0755 "$WORK_DIR/core-bootstrap.sh" "$WORK_DIR/app-bootstrap.sh" \
        "$WORK_DIR/participant-bootstrap.sh"
}

write_cloud_init_files() {
    local core_password_hash app_password_hash participant_password_hash standard_public_key app_public_key
    local core_script_b64 app_script_b64 participant_script_b64 core_config_b64 app_config_b64
    core_password_hash="$(printf '%s\n' "$CORE_PASSWORD" | openssl passwd -6 -stdin)"
    app_password_hash="$(printf '%s\n' "$APP_PASSWORD" | openssl passwd -6 -stdin)"
    participant_password_hash="$(printf '%s\n' "$PARTICIPANT_PASSWORD" | openssl passwd -6 -stdin)"
    standard_public_key="$(public_key_yaml 0)"
    app_public_key="$(public_key_yaml 1)"

    {
        shell_assignment CORE_MINIMAL_URL "$CORE_MINIMAL_URL"
        shell_assignment CORE_MINIMAL_REF "$CORE_MINIMAL_REF"
        shell_assignment CORE_REPO_URL "$CORE_REPO_URL"
        shell_assignment CORE_REPO_REF "$CORE_REPO_REF"
        shell_assignment SCENARIOFORGE_URL "$SCENARIOFORGE_URL"
        shell_assignment SCENARIOFORGE_REF "$SCENARIOFORGE_REF"
        shell_assignment CORE_USE_SYSTEMD_RESOLVED_STUB "$CORE_USE_SYSTEMD_RESOLVED_STUB"
        shell_assignment CORE_MANAGEMENT_IP "$(plain_ip "$CORE_MANAGEMENT_CIDR")"
    } > "$WORK_DIR/core-installer.env"
    {
        shell_assignment SCENARIOFORGE_URL "$SCENARIOFORGE_URL"
        shell_assignment SCENARIOFORGE_REF "$SCENARIOFORGE_REF"
        shell_assignment CORE_MANAGEMENT_IP "$(plain_ip "$CORE_MANAGEMENT_CIDR")"
        shell_assignment CORE_HITL_CIDR "$CORE_HITL_CIDR"
        shell_assignment CORE_PASSWORD "$CORE_PASSWORD"
        shell_assignment SCENARIOFORGE_ADMIN_PASSWORD "$SCENARIOFORGE_ADMIN_PASSWORD"
        shell_assignment INSTALL_FLAG_GENERATORS "$INSTALL_FLAG_GENERATORS"
        shell_assignment INSTALL_VULNHUB "$INSTALL_VULNHUB"
        shell_assignment OPTIONAL_CONTENT_SHA256 "$OPTIONAL_CONTENT_SHA256"
        shell_assignment FLAG_GENERATORS_RESOLVED_COMMIT "$FLAG_GENERATORS_RESOLVED_COMMIT"
        shell_assignment TESTED_FLAG_GENERATORS_COMMIT "$TESTED_FLAG_GENERATORS_COMMIT"
    } > "$WORK_DIR/app-installer.env"
    chmod 0600 "$WORK_DIR/core-installer.env" "$WORK_DIR/app-installer.env"

    core_script_b64="$(encode_file "$WORK_DIR/core-bootstrap.sh")"
    app_script_b64="$(encode_file "$WORK_DIR/app-bootstrap.sh")"
    participant_script_b64="$(encode_file "$WORK_DIR/participant-bootstrap.sh")"
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
$standard_public_key
chpasswd:
  expire: false
package_update: true
packages: [git, curl, ca-certificates, qemu-guest-agent, spice-vdagent]
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
  - [systemctl, start, spice-vdagentd.socket, spice-vdagentd.service]
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
$app_public_key
chpasswd:
  expire: false
package_update: true
packages: [git, curl, ca-certificates, qemu-guest-agent, spice-vdagent]
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
  - [systemctl, start, spice-vdagentd.socket, spice-vdagentd.service]
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
$standard_public_key
chpasswd:
  expire: false
package_update: true
packages: [qemu-guest-agent, spice-vdagent]
write_files:
  - path: /usr/local/sbin/scenarioforge-participant-bootstrap
    owner: root:root
    permissions: '0700'
    encoding: b64
    content: $participant_script_b64
runcmd:
  - [systemctl, enable, --now, qemu-guest-agent]
  - [systemctl, start, spice-vdagentd.socket, spice-vdagentd.service]
  - [bash, /usr/local/sbin/scenarioforge-participant-bootstrap]
final_message: Participant XFCE VM is ready
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
  bootstrap-uplink:
    match: {macaddress: '$PARTICIPANT_NET1_MAC'}
    set-name: ens19
    dhcp4: true
    dhcp6: false
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
        --serial0 socket --vga std,clipboard=vnc --onboot 1 "$@"
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
        --net0 "virtio=$PARTICIPANT_NET0_MAC,bridge=$HITL_BRIDGE" \
        --net1 "virtio=$PARTICIPANT_NET1_MAC,bridge=$UPLINK_BRIDGE"
    run qm set "$PARTICIPANT_VMID" --cicustom \
        "user=$SNIPPET_STORAGE:snippets/scenarioforge-participant-user.yaml,network=$SNIPPET_STORAGE:snippets/scenarioforge-participant-network.yaml"
}

write_state() {
    [[ "$DRY_RUN" -eq 0 ]] || return
    install -d -m 0700 "$STATE_DIR"
    chmod 0700 "$STATE_DIR"
    {
        shell_assignment INSTALLER_VERSION "$SCRIPT_VERSION"
        shell_assignment INSTALLER_PID "$$"
        shell_assignment PVE_NODE "$PVE_NODE"
        shell_assignment VM_STORAGE "$VM_STORAGE"
        shell_assignment SNIPPET_STORAGE "$SNIPPET_STORAGE"
        shell_assignment UPLINK_BRIDGE "$UPLINK_BRIDGE"
        shell_assignment MANAGEMENT_BRIDGE "$MANAGEMENT_BRIDGE"
        shell_assignment HITL_BRIDGE "$HITL_BRIDGE"
        shell_assignment CREATED_MANAGEMENT_BRIDGE "${CREATED_MANAGEMENT_BRIDGE:-0}"
        shell_assignment CREATED_HITL_BRIDGE "${CREATED_HITL_BRIDGE:-0}"
        shell_assignment CORE_VMID "$CORE_VMID"
        shell_assignment APP_VMID "$APP_VMID"
        shell_assignment PARTICIPANT_VMID "$PARTICIPANT_VMID"
        shell_assignment CORE_NAME "$CORE_NAME"
        shell_assignment APP_NAME "$APP_NAME"
        shell_assignment PARTICIPANT_NAME "$PARTICIPANT_NAME"
        shell_assignment INSTALL_COMPLETE "${INSTALL_COMPLETE:-0}"
        shell_assignment PARTICIPANT_BOOTSTRAP_REQUIRED "$PARTICIPANT_BOOTSTRAP_REQUIRED"
        shell_assignment PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED "$PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED"
        shell_assignment INSTALL_PERCENT "${INSTALL_PERCENT:-0}"
        shell_assignment INSTALL_STARTED_EPOCH "${INSTALL_STARTED_EPOCH:-}"
        shell_assignment INSTALL_PHASE "${INSTALL_PHASE:-Preparing installer state}"
        shell_assignment CORE_MANAGEMENT_CIDR "$CORE_MANAGEMENT_CIDR"
        shell_assignment APP_MANAGEMENT_CIDR "$APP_MANAGEMENT_CIDR"
        shell_assignment CORE_HITL_CIDR "$CORE_HITL_CIDR"
        shell_assignment PARTICIPANT_CIDR "$PARTICIPANT_CIDR"
        shell_assignment APP_NET0_MAC "$APP_NET0_MAC"
        shell_assignment INSTALL_FLAG_GENERATORS "$INSTALL_FLAG_GENERATORS"
        shell_assignment INSTALL_VULNHUB "$INSTALL_VULNHUB"
        shell_assignment FLAG_GENERATORS_REF "$FLAG_GENERATORS_REF"
        shell_assignment FLAG_GENERATORS_RESOLVED_COMMIT "$FLAG_GENERATORS_RESOLVED_COMMIT"
    } > "$STATE_TEMP_FILE"
    {
        shell_assignment CORE_VM_USERNAME corevm
        shell_assignment CORE_VM_PASSWORD "$CORE_PASSWORD"
        shell_assignment APP_VM_USERNAME scenarioforge
        shell_assignment APP_VM_PASSWORD "$APP_PASSWORD"
        shell_assignment PARTICIPANT_VM_USERNAME participant
        shell_assignment PARTICIPANT_VM_PASSWORD "$PARTICIPANT_PASSWORD"
        shell_assignment SCENARIOFORGE_ADMIN_USERNAME coreadmin
        shell_assignment SCENARIOFORGE_ADMIN_PASSWORD "$SCENARIOFORGE_ADMIN_PASSWORD"
    } > "$CREDENTIALS_TEMP_FILE"
    chmod 0600 "$STATE_TEMP_FILE" "$CREDENTIALS_TEMP_FILE"
    mv -f -- "$CREDENTIALS_TEMP_FILE" "$CREDENTIALS_FILE"
    mv -f -- "$STATE_TEMP_FILE" "$STATE_FILE"
    INSTALL_STATE_INITIALIZED=1
}

mark_install_complete() {
    [[ "$DRY_RUN" -eq 0 && -f "$STATE_FILE" ]] || return
    INSTALL_COMPLETE=1
    INSTALL_PERCENT=100
    INSTALL_PHASE="Installation complete"
    write_state
    emit PROGRESS "[100%] ScenarioForge lab installation complete"
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

guest_bootstrap_percent() {
    local vmid="$1" marker="$2" current
    if [[ "$marker" != "-" ]] && guest_marker_exists "$vmid" "$marker"; then
        printf '100\n'
        return
    fi
    current="$(guest_command_output "$vmid" cat /var/lib/scenarioforge/bootstrap-percent)"
    if [[ "$current" =~ ^[0-9]+$ ]] && (( current >= 0 && current <= 100 )); then
        printf '%s\n' "$current"
    else
        printf '0\n'
    fi
}

guest_bootstrap_failure_text() {
    local vmid="$1" phase cloud_state
    phase="$(guest_command_output "$vmid" cat /var/lib/scenarioforge/bootstrap-status)"
    if [[ "$phase" == failed* ]]; then
        printf '%s\n' "$phase"
        return
    fi
    cloud_state="$(guest_command_output "$vmid" systemctl show cloud-final --property ActiveState --value)"
    if [[ "$cloud_state" == "failed" ]]; then
        printf 'cloud-final failed while bootstrap phase was: %s\n' "${phase:-unknown}"
    fi
}

format_elapsed() {
    local started="$1" now elapsed hours minutes seconds
    [[ "$started" =~ ^[0-9]+$ ]] || { printf 'unknown'; return; }
    now="$(date +%s)"
    elapsed=$(( now - started ))
    (( elapsed >= 0 )) || elapsed=0
    hours=$(( elapsed / 3600 ))
    minutes=$(( (elapsed % 3600) / 60 ))
    seconds=$(( elapsed % 60 ))
    printf '%02dh:%02dm:%02ds' "$hours" "$minutes" "$seconds"
}

current_install_percent() {
    local current="${INSTALL_PERCENT:-0}" core_percent app_percent participant_percent weighted
    [[ "$current" =~ ^[0-9]+$ ]] || current=0
    if [[ "${INSTALL_COMPLETE:-0}" == "1" ]]; then
        printf '100\n'
        return
    fi
    if (( current >= 55 )); then
        core_percent="$(guest_bootstrap_percent "$CORE_VMID" /var/lib/scenarioforge/core-ready)"
        app_percent="$(guest_bootstrap_percent "$APP_VMID" /var/lib/scenarioforge/app-ready)"
        if [[ "${PARTICIPANT_BOOTSTRAP_REQUIRED:-0}" == "1" ]]; then
            participant_percent="$(guest_bootstrap_percent "$PARTICIPANT_VMID" /var/lib/scenarioforge/participant-ready)"
            if (( core_percent == 100 && app_percent == 100 && participant_percent == 100 )) \
                && [[ "${PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED:-0}" != "1" ]]; then
                weighted=100
            else
                weighted=$(( 55 + (core_percent + app_percent + participant_percent) * 44 / 300 ))
            fi
        else
            if (( core_percent == 100 && app_percent == 100 )); then
                weighted=100
            else
                weighted=$(( 55 + (core_percent + app_percent) * 44 / 200 ))
            fi
        fi
        (( weighted > 100 )) && weighted=100
        (( weighted > current )) && current="$weighted"
    fi
    printf '%s\n' "$current"
}

guest_progress_text() {
    local vmid="$1" bootstrap_log="$2" marker="$3" current percent failure
    percent="$(guest_bootstrap_percent "$vmid" "$marker")"
    current="$(guest_command_output "$vmid" cat /var/lib/scenarioforge/bootstrap-status)"
    failure="$(guest_bootstrap_failure_text "$vmid")"
    if [[ -n "$failure" ]]; then
        printf '[%3d%%] FAILED: %s\n' "$percent" "$failure"
        return
    fi
    if [[ -z "$current" ]]; then
        current="$(guest_last_log_line "$vmid" "$bootstrap_log")"
    fi
    if [[ -z "$current" ]]; then
        current="$(guest_last_log_line "$vmid" /var/log/cloud-init-output.log)"
    fi
    printf '[%3d%%] %s\n' "$percent" "${current:-waiting for guest agent / Cloud-Init}"
}

report_guest_activity() {
    [[ "$VERBOSE" -eq 1 ]] || return 0
    local label="$1" vmid="$2" path="$3" current previous
    current="$(guest_last_log_line "$vmid" "$path")"
    [[ -n "$current" ]] || return 0
    case "$label" in
        CORE)
            previous="$LAST_CORE_ACTIVITY"
            LAST_CORE_ACTIVITY="$current"
            ;;
        APP)
            previous="$LAST_APP_ACTIVITY"
            LAST_APP_ACTIVITY="$current"
            ;;
        PARTICIPANT)
            previous="$LAST_PARTICIPANT_ACTIVITY"
            LAST_PARTICIPANT_ACTIVITY="$current"
            ;;
    esac
    if [[ "$current" != "$previous" ]]; then
        emit DEBUG "$label guest: $current"
    fi
}

wait_for_participant_bootstrap() {
    local deadline failure percent elapsed
    deadline=$(( $(date +%s) + WAIT_MINUTES * 60 ))
    log "Waiting for the participant XFCE install before removing its temporary uplink"
    while :; do
        if guest_marker_exists "$PARTICIPANT_VMID" /var/lib/scenarioforge/participant-ready; then
            return 0
        fi
        failure="$(guest_bootstrap_failure_text "$PARTICIPANT_VMID")"
        if [[ -n "$failure" ]]; then
            PROVISIONING_FAILURE_DETAIL="PARTICIPANT=$failure"
            warn "Participant provisioning failed: $failure"
            return 1
        fi
        report_guest_activity PARTICIPANT "$PARTICIPANT_VMID" /var/log/scenarioforge-participant-bootstrap.log
        percent="$(guest_bootstrap_percent "$PARTICIPANT_VMID" /var/lib/scenarioforge/participant-ready)"
        elapsed="$(format_elapsed "$INSTALL_STARTED_EPOCH")"
        emit PROGRESS "[$(printf '%3d' "$INSTALL_PERCENT")%] Participant bootstrap heartbeat (elapsed $elapsed): ${percent}% working"
        write_runtime_status running "$INSTALL_PHASE" "participant desktop bootstrap; elapsed $elapsed"
        (( $(date +%s) < deadline )) || return 1
        sleep 20
    done
}

detach_participant_bootstrap_uplink() {
    if ! qm config "$PARTICIPANT_VMID" 2>/dev/null | grep -q '^net1:'; then
        PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED=0
        write_state
        return
    fi
    log "Removing the participant VM's temporary package-download uplink"
    run qm set "$PARTICIPANT_VMID" --delete net1
    if qm config "$PARTICIPANT_VMID" 2>/dev/null | grep -q '^net1:'; then
        die "participant temporary uplink net1 is still attached; remove it with: qm set $PARTICIPANT_VMID --delete net1"
    fi
    PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED=0
    write_state
}

wait_for_provisioning() {
    local deadline now core_ready=0 app_ready=0 participant_ready=0
    local core_percent app_percent participant_percent elapsed
    local core_failure app_failure participant_failure
    deadline=$(( $(date +%s) + WAIT_MINUTES * 60 ))
    log "Waiting up to $WAIT_MINUTES minutes for all three guests to finish provisioning"
    while :; do
        guest_marker_exists "$CORE_VMID" /var/lib/scenarioforge/core-ready && core_ready=1
        guest_marker_exists "$APP_VMID" /var/lib/scenarioforge/app-ready && app_ready=1
        guest_marker_exists "$PARTICIPANT_VMID" /var/lib/scenarioforge/participant-ready && participant_ready=1
        core_failure=""
        app_failure=""
        participant_failure=""
        [[ "$core_ready" -eq 1 ]] || core_failure="$(guest_bootstrap_failure_text "$CORE_VMID")"
        [[ "$app_ready" -eq 1 ]] || app_failure="$(guest_bootstrap_failure_text "$APP_VMID")"
        [[ "$participant_ready" -eq 1 ]] \
            || participant_failure="$(guest_bootstrap_failure_text "$PARTICIPANT_VMID")"
        if [[ -n "$core_failure" || -n "$app_failure" || -n "$participant_failure" ]]; then
            PROVISIONING_FAILURE_DETAIL="CORE=${core_failure:-not failed}; APP=${app_failure:-not failed}; PARTICIPANT=${participant_failure:-not failed}"
            warn "Guest provisioning failed: $PROVISIONING_FAILURE_DETAIL"
            return 1
        fi
        report_guest_activity CORE "$CORE_VMID" /var/log/scenarioforge-core-bootstrap.log
        report_guest_activity APP "$APP_VMID" /var/log/scenarioforge-app-bootstrap.log
        report_guest_activity PARTICIPANT "$PARTICIPANT_VMID" /var/log/scenarioforge-participant-bootstrap.log
        core_percent="$(guest_bootstrap_percent "$CORE_VMID" /var/lib/scenarioforge/core-ready)"
        app_percent="$(guest_bootstrap_percent "$APP_VMID" /var/lib/scenarioforge/app-ready)"
        participant_percent="$(guest_bootstrap_percent "$PARTICIPANT_VMID" /var/lib/scenarioforge/participant-ready)"
        INSTALL_PERCENT=$(( 55 + (core_percent + app_percent + participant_percent) * 44 / 300 ))
        (( INSTALL_PERCENT > 99 )) && INSTALL_PERCENT=99
        elapsed="$(format_elapsed "$INSTALL_STARTED_EPOCH")"
        emit PROGRESS "[$(printf '%3d' "$INSTALL_PERCENT")%] Guest bootstrap heartbeat (elapsed $elapsed): CORE=${core_percent}% $([[ $core_ready -eq 1 ]] && echo ready || echo working), APP=${app_percent}% $([[ $app_ready -eq 1 ]] && echo ready || echo working), PARTICIPANT=${participant_percent}% $([[ $participant_ready -eq 1 ]] && echo ready || echo working)"
        write_runtime_status running "$INSTALL_PHASE" "guest bootstrap heartbeat; elapsed $elapsed"
        if [[ "$core_ready" -eq 1 && "$app_ready" -eq 1 && "$participant_ready" -eq 1 ]]; then
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

transfer_optional_content_to_app() {
    [[ "$INSTALL_FLAG_GENERATORS" == "1" || "$INSTALL_VULNHUB" == "1" ]] || return 0
    [[ -f "$OPTIONAL_CONTENT_ARCHIVE" && -f "$CATALOG_TRANSFER_KEY" ]] \
        || die "optional content payload or one-time transfer key is missing"
    local deadline app_ip="" elapsed remote_archive=/tmp/scenarioforge-optional-content.tar.gz
    local -a ssh_options=(
        -i "$CATALOG_TRANSFER_KEY"
        -o BatchMode=yes
        -o ConnectTimeout=5
        -o IdentitiesOnly=yes
        -o LogLevel=ERROR
        -o StrictHostKeyChecking=no
        -o UserKnownHostsFile=/dev/null
    )
    deadline=$(( $(date +%s) + WAIT_MINUTES * 60 ))
    log "Waiting for the APP guest agent and one-time SSH content-transfer access"
    while :; do
        app_ip="$(app_uplink_ip)"
        if [[ -n "$app_ip" ]] \
            && ssh "${ssh_options[@]}" "scenarioforge@$app_ip" true >/dev/null 2>&1; then
            break
        fi
        elapsed="$(format_elapsed "$INSTALL_STARTED_EPOCH")"
        emit PROGRESS "[ 53%] Optional-content transfer waiting for APP SSH (elapsed $elapsed)"
        (( $(date +%s) < deadline )) \
            || die "timed out waiting for APP SSH while installing optional catalogs"
        sleep 10
    done
    log "Transferring requested generator/vulnerability content to APP at $app_ip"
    scp -q "${ssh_options[@]}" "$OPTIONAL_CONTENT_ARCHIVE" \
        "scenarioforge@$app_ip:$remote_archive.part"
    local remote_sha
    remote_sha="$(ssh "${ssh_options[@]}" "scenarioforge@$app_ip" \
        "sha256sum /tmp/scenarioforge-optional-content.tar.gz.part | cut -d ' ' -f 1")"
    [[ "$remote_sha" == "$OPTIONAL_CONTENT_SHA256" ]] \
        || die "APP optional-content transfer checksum verification failed"
    ssh "${ssh_options[@]}" "scenarioforge@$app_ip" \
        "mv -f -- /tmp/scenarioforge-optional-content.tar.gz.part /tmp/scenarioforge-optional-content.tar.gz"
    log "Optional content transfer verified; APP will install it before starting ScenarioForge"
}

vm_status_line() {
    local label="$1" vmid="$2" marker="$3" status="missing" bootstrap="unknown" agent="n/a" phase="" failure=""
    if qm status "$vmid" >/dev/null 2>&1; then
        status="$(qm status "$vmid" | awk '{print $2}')"
        if [[ "$status" == "running" ]]; then
            if [[ "$marker" == "-" ]]; then
                if qm agent "$vmid" ping >/dev/null 2>&1; then agent="ready"; else agent="optional"; fi
                bootstrap="n/a"
            else
                if qm agent "$vmid" ping >/dev/null 2>&1; then agent="ready"; else agent="waiting"; fi
                if guest_marker_exists "$vmid" "$marker"; then
                    bootstrap="ready"
                else
                    failure="$(guest_bootstrap_failure_text "$vmid")"
                    phase="$(guest_command_output "$vmid" cat /var/lib/scenarioforge/bootstrap-status)"
                    if [[ -n "$failure" || "$phase" == failed* ]]; then
                        bootstrap="failed"
                    else
                        bootstrap="in-progress"
                    fi
                fi
            fi
        fi
    fi
    printf '  %-13s VMID %-6s %-8s agent=%-7s bootstrap=%s\n' "$label" "$vmid" "$status" "$agent" "$bootstrap"
}

show_status() {
    local host_state="installer process not detected" display_percent elapsed participant_marker="-"
    [[ -f "$STATE_FILE" ]] \
        || die "no installer state found at $STATE_FILE; if an install is running, use: $0 status --watch"
    PARTICIPANT_BOOTSTRAP_REQUIRED=0
    PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED=0
    # shellcheck disable=SC1090
    source "$STATE_FILE"
    if [[ "${PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED:-0}" == "1" ]] \
        && ! qm config "$PARTICIPANT_VMID" 2>/dev/null | grep -q '^net1:'; then
        # Permit status/watch to recognize a manually completed recovery even
        # when the failed host installer did not get to rewrite state.env.
        PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED=0
    fi
    if [[ "$PARTICIPANT_BOOTSTRAP_REQUIRED" == "1" ]]; then
        participant_marker=/var/lib/scenarioforge/participant-ready
    fi
    if [[ "${INSTALL_COMPLETE:-0}" == "1" ]]; then
        host_state="complete"
    elif [[ "${INSTALLER_PID:-}" =~ ^[0-9]+$ ]] && kill -0 "$INSTALLER_PID" 2>/dev/null; then
        host_state="active (PID $INSTALLER_PID)"
    fi
    display_percent="$(current_install_percent)"
    if [[ "$display_percent" == "100" && "${INSTALL_COMPLETE:-0}" != "1" ]]; then
        host_state="guest provisioning complete"
    fi
    elapsed="$(format_elapsed "${INSTALL_STARTED_EPOCH:-}")"
    printf 'ScenarioForge Proxmox lab on %s\n' "$PVE_NODE"
    printf '  Install progress: %s%% (elapsed %s)\n' "$display_percent" "$elapsed"
    printf '  Host installer:  %s - %s\n' "$host_state" "${INSTALL_PHASE:-phase unavailable}"
    vm_status_line CORE "$CORE_VMID" /var/lib/scenarioforge/core-ready
    vm_status_line APP "$APP_VMID" /var/lib/scenarioforge/app-ready
    vm_status_line PARTICIPANT "$PARTICIPANT_VMID" "$participant_marker"
    printf '  CORE progress:    %s\n' "$(guest_progress_text "$CORE_VMID" /var/log/scenarioforge-core-bootstrap.log /var/lib/scenarioforge/core-ready)"
    printf '  APP progress:     %s\n' "$(guest_progress_text "$APP_VMID" /var/log/scenarioforge-app-bootstrap.log /var/lib/scenarioforge/app-ready)"
    if [[ "$PARTICIPANT_BOOTSTRAP_REQUIRED" == "1" ]]; then
        printf '  PARTICIPANT:      %s\n' "$(guest_progress_text "$PARTICIPANT_VMID" /var/log/scenarioforge-participant-bootstrap.log /var/lib/scenarioforge/participant-ready)"
    fi
    if [[ "${PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED:-0}" == "1" ]]; then
        printf '  Participant NIC: temporary uplink net1 remains attached until XFCE provisioning finishes\n'
    fi
    if [[ "${INSTALL_FLAG_GENERATORS:-0}" == "1" || "${INSTALL_VULNHUB:-0}" == "1" ]]; then
        printf '  Optional content: flag-generators=%s vulnhub=%s\n' \
            "${INSTALL_FLAG_GENERATORS:-0}" "${INSTALL_VULNHUB:-0}"
    fi
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

show_completion_credentials() {
    local app_ip app_address web_url
    app_ip="$(app_uplink_ip)"
    if [[ -n "$app_ip" ]]; then
        app_address="$app_ip"
        web_url="https://$app_ip/"
    else
        app_address="DHCP address pending (VMID $APP_VMID)"
        web_url="DHCP address pending; rerun the status command"
    fi

    printf '\nScenarioForge lab credentials\n'
    printf '  CORE VM         VMID %s | address %s | username corevm | password %s\n' \
        "$CORE_VMID" "$(plain_ip "$CORE_MANAGEMENT_CIDR")" "$CORE_PASSWORD"
    printf '  APP VM          VMID %s | address %s | username scenarioforge | password %s\n' \
        "$APP_VMID" "$app_address" "$APP_PASSWORD"
    printf '  PARTICIPANT VM  VMID %s | address %s | username participant | password %s\n' \
        "$PARTICIPANT_VMID" "$(plain_ip "$PARTICIPANT_CIDR")" "$PARTICIPANT_PASSWORD"
    printf '  WEB ADMIN       URL %s | username coreadmin | password %s\n' \
        "$web_url" "$SCENARIOFORGE_ADMIN_PASSWORD"
    printf '  DESKTOPS       Open Proxmox Console/noVNC for XFCE; VNC clipboard is enabled by default\n'
    printf '  APP BROWSER    Epiphany is installed with a ScenarioForge launcher on the XFCE desktop\n'
    printf '  APP TOOLS      Terminator, Evince (PDF), xdot (Graphviz), and Mousepad/jq (JSON)\n'
    printf '  APP SERVICE     Native systemd units: scenarioforge-web and nginx (no app-side Docker Compose)\n'
    printf '  Stored at       %s (root-only, mode 0600)\n' "$CREDENTIALS_FILE"
    printf '  Security        This completion output contains secrets; protect terminal logs and captures.\n\n'
}

show_prestate_runtime_status() {
    local mode="" RUNTIME_PID="" RUNTIME_STATE="" RUNTIME_PERCENT="0" RUNTIME_PHASE="" RUNTIME_DETAIL="" RUNTIME_UPDATED=""
    [[ -f "$RUNTIME_STATUS_FILE" ]] || return 1
    if [[ -L "$RUNTIME_STATUS_FILE" || ! -O "$RUNTIME_STATUS_FILE" ]]; then
        warn "ignoring runtime status that is a symlink or is not owned by root: $RUNTIME_STATUS_FILE"
        return 2
    fi
    mode="$(python3 -c 'import os, sys; print(os.stat(sys.argv[1]).st_mode & 0o022)' "$RUNTIME_STATUS_FILE")"
    if [[ "$mode" != "0" ]]; then
        warn "ignoring group/world-writable runtime status: $RUNTIME_STATUS_FILE"
        return 2
    fi
    # shellcheck disable=SC1090
    source "$RUNTIME_STATUS_FILE"
    emit INFO "Host installer ${RUNTIME_STATE:-unknown} [${RUNTIME_PERCENT:-0}%] (PID ${RUNTIME_PID:-unknown}, updated ${RUNTIME_UPDATED:-unknown}): ${RUNTIME_PHASE:-phase unavailable}"
    if [[ "${RUNTIME_STATE:-}" == "failed" ]]; then
        warn "Installer error: ${RUNTIME_DETAIL:-no error detail was recorded}"
        return 2
    fi
    if [[ ! "${RUNTIME_PID:-}" =~ ^[0-9]+$ ]] || ! kill -0 "$RUNTIME_PID" 2>/dev/null; then
        warn "no active installer process owns this status; inspect the install shell before waiting longer"
        return 2
    fi
    return 0
}

watch_status() {
    local runtime_result
    emit INFO "Watching provisioning every $STATUS_INTERVAL seconds; press Ctrl-C to stop"
    while [[ ! -f "$STATE_FILE" ]]; do
        if show_prestate_runtime_status; then
            emit INFO "Waiting for installer state at $STATE_FILE"
        else
            runtime_result=$?
            if [[ "$runtime_result" -eq 2 ]]; then
                return 0
            fi
            emit INFO "No active install status found; start 'install' in another shell, or verify that shell has not exited"
        fi
        sleep "$STATUS_INTERVAL"
    done
    emit INFO "Installer state detected; beginning VM and guest bootstrap status"
    while :; do
        printf '\n'
        show_status
        if [[ "${INSTALL_COMPLETE:-0}" == "1" ]] \
            || { guest_marker_exists "$CORE_VMID" /var/lib/scenarioforge/core-ready \
                && guest_marker_exists "$APP_VMID" /var/lib/scenarioforge/app-ready \
                && [[ "${PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED:-0}" != "1" ]] \
                && { [[ "$PARTICIPANT_BOOTSTRAP_REQUIRED" != "1" ]] \
                    || guest_marker_exists "$PARTICIPANT_VMID" /var/lib/scenarioforge/participant-ready; }; }; then
            emit INFO "All required guest provisioning is ready"
            return
        fi
        sleep "$STATUS_INTERVAL"
    done
}

cleanup_target_selected() {
    local wanted="$1" vmid
    for vmid in "${CLEANUP_VMIDS[@]}"; do
        [[ "$vmid" == "$wanted" ]] && return 0
    done
    return 1
}

vm_owned_by_installer() {
    local vmid="$1" expected_name="$2" snippet_name="$3" config actual_name
    config="$(qm config "$vmid" 2>/dev/null)" || return 1
    actual_name="$(awk -F': ' '$1 == "name" {print $2; exit}' <<<"$config")"
    [[ "$actual_name" == "$expected_name" || "$config" == *"$snippet_name"* ]]
}

add_cleanup_vm_if_owned() {
    local label="$1" vmid="$2" expected_name="$3" snippet_name="$4"
    if ! qm status "$vmid" >/dev/null 2>&1; then
        verbose "$label VMID $vmid does not exist"
        return
    fi
    if ! vm_owned_by_installer "$vmid" "$expected_name" "$snippet_name"; then
        warn "preserving VMID $vmid: its name and Cloud-Init data do not identify it as the installer-created $label VM"
        return
    fi
    CLEANUP_LABELS+=("$label")
    CLEANUP_VMIDS+=("$vmid")
}

load_cleanup_scope() {
    local current_node="$PVE_NODE" mode
    if [[ -f "$STATE_FILE" ]]; then
        [[ ! -L "$STATE_FILE" && -O "$STATE_FILE" ]] \
            || die "refusing to source cleanup state that is a symlink or is not owned by root: $STATE_FILE"
        mode="$(python3 -c 'import os, sys; print(os.stat(sys.argv[1]).st_mode & 0o022)' "$STATE_FILE")"
        [[ "$mode" == "0" ]] \
            || die "refusing to source group/world-writable cleanup state: $STATE_FILE"
        # shellcheck disable=SC1090
        source "$STATE_FILE"
        [[ "$PVE_NODE" == "$current_node" ]] \
            || die "saved lab belongs to Proxmox node '$PVE_NODE', not '$current_node'"
        CLEANUP_STATE_FOUND=1
        log "Using installer state from $STATE_FILE"
    else
        warn "no installer state found; recovery is limited to exact ScenarioForge VM identities and bridge comments"
    fi

    validate_integer "CORE VMID" "$CORE_VMID" 100
    validate_integer "ScenarioForge VMID" "$APP_VMID" 100
    validate_integer "participant VMID" "$PARTICIPANT_VMID" 100
    [[ "$CORE_VMID" != "$APP_VMID" && "$CORE_VMID" != "$PARTICIPANT_VMID" && "$APP_VMID" != "$PARTICIPANT_VMID" ]] \
        || die "cleanup VMIDs must be unique"
    validate_name "CORE VM name" "$CORE_NAME"
    validate_name "ScenarioForge VM name" "$APP_NAME"
    validate_name "participant VM name" "$PARTICIPANT_NAME"
    validate_name "snippet storage" "$SNIPPET_STORAGE"
    validate_bridge_name "$MANAGEMENT_BRIDGE"
    validate_bridge_name "$HITL_BRIDGE"

    add_cleanup_vm_if_owned CORE "$CORE_VMID" "$CORE_NAME" scenarioforge-core-user.yaml
    add_cleanup_vm_if_owned APP "$APP_VMID" "$APP_NAME" scenarioforge-app-user.yaml
    add_cleanup_vm_if_owned PARTICIPANT "$PARTICIPANT_VMID" "$PARTICIPANT_NAME" scenarioforge-participant-user.yaml
}

discover_cleanup_snippets() {
    local config path filename
    if ! config="$(pvesh get "/storage/$SNIPPET_STORAGE" --output-format json 2>/dev/null)"; then
        warn "cannot inspect snippet storage '$SNIPPET_STORAGE'; its files will be preserved"
        return
    fi
    if [[ "$(storage_field "$config" type)" != "dir" ]]; then
        warn "snippet storage '$SNIPPET_STORAGE' is not directory-backed; its files will be preserved"
        return
    fi
    path="$(storage_field "$config" path)"
    if [[ -z "$path" || "$path" != /* || "$path" == "/" ]]; then
        warn "snippet storage '$SNIPPET_STORAGE' returned an unsafe path; its files will be preserved"
        return
    fi
    for filename in \
        scenarioforge-core-user.yaml scenarioforge-core-network.yaml \
        scenarioforge-app-user.yaml scenarioforge-app-network.yaml \
        scenarioforge-participant-user.yaml scenarioforge-participant-network.yaml; do
        [[ -e "$path/snippets/$filename" ]] && CLEANUP_SNIPPETS+=("$path/snippets/$filename")
    done
    return 0
}

bridge_owned_by_installer() {
    local bridge="$1" recorded_created="$2" expected_comment="$3" config
    config="$(pvesh get "/nodes/$PVE_NODE/network/$bridge" --output-format json 2>/dev/null)" || return 1
    [[ "$(storage_field "$config" type)" == "bridge" ]] || return 1
    [[ "$(storage_field "$config" comments)" == "$expected_comment" ]] || return 1
    if [[ "$recorded_created" == "0" ]]; then
        return 1
    fi
    [[ "$recorded_created" == "1" || "$recorded_created" == "creating" || -z "$recorded_created" ]]
}

discover_cleanup_bridges() {
    if bridge_owned_by_installer "$MANAGEMENT_BRIDGE" "${CREATED_MANAGEMENT_BRIDGE:-}" \
        "ScenarioForge isolated CORE management"; then
        CLEANUP_BRIDGES+=("$MANAGEMENT_BRIDGE")
    fi
    if bridge_owned_by_installer "$HITL_BRIDGE" "${CREATED_HITL_BRIDGE:-}" \
        "ScenarioForge isolated participant HITL"; then
        CLEANUP_BRIDGES+=("$HITL_BRIDGE")
    fi
    return 0
}

cleanup_may_change_network() {
    [[ "${#CLEANUP_BRIDGES[@]}" -gt 0 ]] && return 0
    [[ "${CREATED_MANAGEMENT_BRIDGE:-0}" != "0" ]] \
        && ip link show "$MANAGEMENT_BRIDGE" >/dev/null 2>&1 \
        && return 0
    [[ "${CREATED_HITL_BRIDGE:-0}" != "0" ]] \
        && ip link show "$HITL_BRIDGE" >/dev/null 2>&1
}

preflight_cleanup_network() {
    cleanup_may_change_network || return 0
    if [[ -f /etc/network/interfaces.new ]] && ! cmp -s /etc/network/interfaces /etc/network/interfaces.new; then
        die "Proxmox has unapplied network changes; inspect 'diff -u /etc/network/interfaces /etc/network/interfaces.new', then apply or revert them before retrying cleanup"
    fi
    validate_network_reload
}

cleanup_is_healthy_running_lab() {
    local vmid status
    [[ "${#CLEANUP_VMIDS[@]}" -eq 3 ]] || return 1
    for vmid in "$CORE_VMID" "$APP_VMID" "$PARTICIPANT_VMID"; do
        cleanup_target_selected "$vmid" || return 1
        status="$(qm status "$vmid" 2>/dev/null | awk '{print $2}')"
        [[ "$status" == "running" ]] || return 1
    done
    if [[ "${INSTALL_COMPLETE:-}" == "1" ]]; then
        return 0
    fi
    [[ "${PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED:-0}" != "1" ]] || return 1
    guest_marker_exists "$CORE_VMID" /var/lib/scenarioforge/core-ready \
        && guest_marker_exists "$APP_VMID" /var/lib/scenarioforge/app-ready \
        && { [[ "${PARTICIPANT_BOOTSTRAP_REQUIRED:-0}" != "1" ]] \
            || guest_marker_exists "$PARTICIPANT_VMID" /var/lib/scenarioforge/participant-ready; }
}

confirm_cleanup() {
    local index response
    log "Cleanup scope on Proxmox node $PVE_NODE:"
    for index in "${!CLEANUP_VMIDS[@]}"; do
        log "  VM: ${CLEANUP_LABELS[$index]} VMID ${CLEANUP_VMIDS[$index]} (including its disks)"
    done
    [[ "${#CLEANUP_SNIPPETS[@]}" -eq 0 ]] || log "  Cloud-Init snippets: ${#CLEANUP_SNIPPETS[@]} installer files"
    [[ "${#CLEANUP_BRIDGES[@]}" -eq 0 ]] || log "  Installer-created bridges: ${CLEANUP_BRIDGES[*]}"
    cleanup_metadata_exists \
        && log "  Saved installer/runtime state and credentials"

    if cleanup_is_healthy_running_lab; then
        [[ "$FORCE_CLEANUP" -eq 1 ]] \
            || die "the lab is complete and all three VMs are running; rerun cleanup with --force to remove it"
        warn "--force permits removal of a complete, healthy running lab"
    fi
    if [[ "$DRY_RUN" -eq 1 || "$ASSUME_YES" -eq 1 ]]; then
        return
    fi
    printf 'Type CLEANUP to permanently remove the resources listed above: '
    read -r response
    [[ "$response" == "CLEANUP" ]] || die "cleanup cancelled"
}

stop_and_destroy_cleanup_vms() {
    local index label vmid status
    for index in "${!CLEANUP_VMIDS[@]}"; do
        label="${CLEANUP_LABELS[$index]}"
        vmid="${CLEANUP_VMIDS[$index]}"
        status="$(qm status "$vmid" 2>/dev/null | awk '{print $2}')"
        if [[ "$status" == "running" ]]; then
            log "Requesting a graceful shutdown of $label VMID $vmid (timeout: 60 seconds)"
            if ! run qm shutdown "$vmid" --timeout 60; then
                warn "$label VMID $vmid did not shut down gracefully"
            fi
            status="$(qm status "$vmid" 2>/dev/null | awk '{print $2}')"
            if [[ "$status" == "running" ]]; then
                warn "forcing $label VMID $vmid to stop"
                run qm stop "$vmid"
            fi
        fi
        log "Destroying installer-owned $label VMID $vmid and its disks"
        run qm destroy "$vmid" --purge 1 --destroy-unreferenced-disks 1
    done
}

config_uses_bridge() {
    local config="$1" bridge="$2"
    [[ "$config" == *"bridge=$bridge,"* || "$config" == *"bridge=$bridge"$'\n'* || "$config" == *"bridge=$bridge" ]]
}

bridge_in_use_after_cleanup() {
    local bridge="$1" guest_id config
    while read -r guest_id; do
        [[ -n "$guest_id" ]] || continue
        cleanup_target_selected "$guest_id" && continue
        config="$(qm config "$guest_id" 2>/dev/null || true)"
        config_uses_bridge "$config" "$bridge" && return 0
    done < <(qm list 2>/dev/null | awk 'NR > 1 {print $1}')
    if command -v pct >/dev/null 2>&1; then
        while read -r guest_id; do
            [[ -n "$guest_id" ]] || continue
            config="$(pct config "$guest_id" 2>/dev/null || true)"
            config_uses_bridge "$config" "$bridge" && return 0
        done < <(pct list 2>/dev/null | awk 'NR > 1 {print $1}')
    fi
    return 1
}

remove_cleanup_bridges() {
    local bridge
    local -a removed=()
    for bridge in "${CLEANUP_BRIDGES[@]}"; do
        if bridge_in_use_after_cleanup "$bridge"; then
            warn "preserving installer-created bridge $bridge because another VM or container still uses it"
            continue
        fi
        log "Removing installer-created bridge $bridge"
        run pvesh delete "/nodes/$PVE_NODE/network/$bridge"
        NETWORK_CHANGES=1
        removed+=("$bridge")
    done
    apply_network_changes
    if [[ "$DRY_RUN" -eq 0 ]]; then
        for bridge in "${removed[@]}"; do
            if ip link show "$bridge" >/dev/null 2>&1; then
                die "bridge $bridge still exists after applying its removal"
            fi
        done
    fi
    return 0
}

cleanup_metadata_exists() {
    [[ -e "$STATE_FILE" || -L "$STATE_FILE" \
        || -e "$CREDENTIALS_FILE" || -L "$CREDENTIALS_FILE" \
        || -e "$STATE_TEMP_FILE" || -L "$STATE_TEMP_FILE" \
        || -e "$CREDENTIALS_TEMP_FILE" || -L "$CREDENTIALS_TEMP_FILE" \
        || -e "$RUNTIME_STATUS_FILE" || -L "$RUNTIME_STATUS_FILE" \
        || -e "$RUNTIME_STATUS_TEMP_FILE" || -L "$RUNTIME_STATUS_TEMP_FILE" ]]
}

remove_cleanup_files() {
    local path
    for path in "${CLEANUP_SNIPPETS[@]}"; do
        log "Removing Cloud-Init snippet $path"
        run rm -f -- "$path"
    done
    if cleanup_metadata_exists; then
        log "Removing saved installer state, runtime status, and credentials"
        run rm -f -- "$STATE_FILE" "$CREDENTIALS_FILE" "$STATE_TEMP_FILE" "$CREDENTIALS_TEMP_FILE" \
            "$RUNTIME_STATUS_FILE" "$RUNTIME_STATUS_TEMP_FILE"
        if [[ "$DRY_RUN" -eq 1 ]]; then
            run rmdir "$STATE_DIR"
        elif [[ -d "$STATE_DIR" ]] && ! run rmdir "$STATE_DIR" 2>/dev/null; then
            warn "preserving non-empty state directory $STATE_DIR"
        fi
    fi
}

perform_cleanup() {
    [[ "$STATE_DIR" == /* && "$STATE_DIR" != "/" ]] || die "cleanup state directory must be an absolute, non-root path"
    load_cleanup_scope
    discover_cleanup_snippets
    discover_cleanup_bridges
    preflight_cleanup_network
    if [[ "${#CLEANUP_VMIDS[@]}" -eq 0 && "${#CLEANUP_SNIPPETS[@]}" -eq 0 \
        && "${#CLEANUP_BRIDGES[@]}" -eq 0 && "$CLEANUP_STATE_FOUND" -eq 0 ]]; then
        if ! cleanup_metadata_exists; then
            log "No partial or installer-owned ScenarioForge lab resources were found"
            return
        fi
    fi
    confirm_cleanup
    stop_and_destroy_cleanup_vms
    remove_cleanup_bridges
    remove_cleanup_files
    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "Cleanup dry run complete; no resources were changed"
    else
        log "ScenarioForge Proxmox lab cleanup complete; cached base images were preserved for reuse"
    fi
}

perform_install() {
    INSTALL_STARTED_EPOCH="$(date +%s)"
    configure_install_progress 8
    progress 2 "Validating Proxmox, storage, VMIDs, and requested networks"
    validate_install_inputs
    preflight_proxmox
    confirm_install

    WORK_DIR="$(mktemp -d /tmp/scenarioforge-pve.XXXXXX)"
    trap '[[ -n "${WORK_DIR:-}" && -d "$WORK_DIR" ]] && rm -rf "$WORK_DIR"' EXIT

    if [[ "$INSTALL_FLAG_GENERATORS" == "1" || "$INSTALL_VULNHUB" == "1" ]]; then
        progress 4 "Authenticating and preparing requested APP catalogs"
        prepare_optional_content
    fi

    CORE_PASSWORD="$REQUESTED_CORE_PASSWORD"
    APP_PASSWORD="$REQUESTED_APP_PASSWORD"
    PARTICIPANT_PASSWORD="$REQUESTED_PARTICIPANT_PASSWORD"
    SCENARIOFORGE_ADMIN_PASSWORD="$REQUESTED_WEB_ADMIN_PASSWORD"
    [[ -n "$CORE_PASSWORD" ]] || CORE_PASSWORD="$(random_password)"
    [[ -n "$APP_PASSWORD" ]] || APP_PASSWORD="$(random_password)"
    [[ -n "$PARTICIPANT_PASSWORD" ]] || PARTICIPANT_PASSWORD="$(random_password)"
    [[ -n "$SCENARIOFORGE_ADMIN_PASSWORD" ]] \
        || SCENARIOFORGE_ADMIN_PASSWORD="$(random_password)"
    CORE_NET0_MAC="$(random_mac)"
    CORE_NET1_MAC="$(random_mac)"
    CORE_NET2_MAC="$(random_mac)"
    APP_NET0_MAC="$(random_mac)"
    APP_NET1_MAC="$(random_mac)"
    PARTICIPANT_NET0_MAC="$(random_mac)"
    PARTICIPANT_NET1_MAC="$(random_mac)"
    PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED=1
    INSTALL_COMPLETE=0
    INSTALL_PHASE="Preflight complete; preparing Proxmox resources"
    CREATED_MANAGEMENT_BRIDGE=pending
    CREATED_HITL_BRIDGE=pending
    write_state

    progress 7 "Creating or validating the isolated management and HITL bridges"
    ensure_isolated_bridge "$MANAGEMENT_BRIDGE" "ScenarioForge isolated CORE management"
    ensure_isolated_bridge "$HITL_BRIDGE" "ScenarioForge isolated participant HITL"
    apply_network_changes
    if [[ "$DRY_RUN" -eq 0 ]]; then
        ip link show "$MANAGEMENT_BRIDGE" >/dev/null 2>&1 \
            || die "management bridge did not appear after applying network configuration"
        ip link show "$HITL_BRIDGE" >/dev/null 2>&1 \
            || die "HITL bridge did not appear after applying network configuration"
    fi

    progress 12 "Preparing Cloud-Init snippet storage"
    ensure_snippet_storage

    progress 18 "Downloading and verifying Debian and Ubuntu cloud images"
    DEBIAN_IMAGE="$IMAGE_CACHE/debian-12-genericcloud-amd64.qcow2"
    UBUNTU_IMAGE="$IMAGE_CACHE/noble-server-cloudimg-amd64.img"
    download_verified_image "$DEBIAN_IMAGE_URL" "$DEBIAN_SUMS_URL" sha512 "$DEBIAN_IMAGE"
    download_verified_image "$UBUNTU_IMAGE_URL" "$UBUNTU_SUMS_URL" sha256 "$UBUNTU_IMAGE"

    progress 28 "Generating guest bootstrap scripts and Cloud-Init data"
    write_guest_bootstraps
    write_cloud_init_files
    install_snippets

    progress 38 "Creating the CORE, ScenarioForge, and participant VMs"
    create_vms

    progress 50 "Starting all three VMs"
    run qm start "$CORE_VMID"
    run qm start "$APP_VMID"
    run qm start "$PARTICIPANT_VMID"

    if [[ "$DRY_RUN" -eq 1 ]]; then
        progress 100 "Dry-run validation finished"
        log "Dry run complete; no resources were changed"
        return
    fi
    transfer_optional_content_to_app
    if [[ "$WAIT_FOR_BOOTSTRAP" -eq 1 ]]; then
        progress 55 "Waiting for CORE, ScenarioForge, and participant guest provisioning"
        if ! wait_for_provisioning; then
            if [[ -n "$PROVISIONING_FAILURE_DETAIL" ]]; then
                warn "Provisioning stopped after an explicit guest failure. VMs were left intact for diagnosis."
                write_runtime_status failed "Guest provisioning failed" "$PROVISIONING_FAILURE_DETAIL"
            else
                warn "Provisioning did not finish before the timeout. VMs were left intact for diagnosis."
                write_runtime_status failed "Guest provisioning timed out" "one or more guests did not become ready within $WAIT_MINUTES minutes"
            fi
            warn "Run: $0 status"
            warn "Guest logs: /var/log/scenarioforge-{core,app,participant}-bootstrap.log"
            exit 2
        fi
        detach_participant_bootstrap_uplink
        mark_install_complete
    else
        progress 55 "Waiting for participant isolation before leaving CORE and the app in the background"
        if ! wait_for_participant_bootstrap; then
            warn "The participant's temporary uplink was left attached for diagnosis because its desktop bootstrap did not finish."
            write_runtime_status failed "Participant provisioning failed" "${PROVISIONING_FAILURE_DETAIL:-participant did not become ready within $WAIT_MINUTES minutes}"
            warn "Run: $0 status"
            warn "Guest log: /var/log/scenarioforge-participant-bootstrap.log"
            exit 2
        fi
        detach_participant_bootstrap_uplink
        record_install_phase "CORE and ScenarioForge provisioning continue in the background (--no-wait)"
    fi
    show_status
    show_completion_credentials
    if [[ "$WAIT_FOR_BOOTSTRAP" -eq 1 ]]; then
        write_runtime_status complete "${INSTALL_PHASE:-Installation complete}" ""
        log "Installation complete. Credentials were shown above and saved at $CREDENTIALS_FILE"
    else
        write_runtime_status complete "Host setup complete; guest provisioning continues" ""
        log "Host setup complete; CORE and ScenarioForge provisioning continue in the background. Credentials were shown above and saved at $CREDENTIALS_FILE"
    fi
}

main() {
    sanitize_host_environment
    parse_args "$@"
    trap 'exit_code=$?; on_unexpected_error "$LINENO" "$exit_code"' ERR
    if [[ "$COMMAND" == "install" && "$DRY_RUN" -eq 0 ]]; then
        RUNTIME_TRACKING=1
        write_runtime_status running "Starting installer checks" ""
    fi
    require_root_and_pve
    case "$COMMAND" in
        status)
            if [[ "$STATUS_WATCH" -eq 1 ]]; then
                watch_status
            else
                show_status
            fi
            ;;
        cleanup) perform_cleanup ;;
        install) perform_install ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    main "$@"
fi
