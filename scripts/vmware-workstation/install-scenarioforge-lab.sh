#!/usr/bin/env bash
# Provision the three-VM ScenarioForge lab on VMware Workstation for Linux.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
PROXMOX_INSTALLER="$SCRIPT_DIR/../proxmox/install-scenarioforge-lab.sh"
[[ -r "$PROXMOX_INSTALLER" ]] || {
    printf 'ERROR: shared guest provisioning file not found: %s\n' "$PROXMOX_INSTALLER" >&2
    exit 1
}
# Reuse the tested guest bootstrap and Cloud-Init generators. Its main function is
# guarded, so sourcing it does not perform any Proxmox operations.
# shellcheck source=scripts/proxmox/install-scenarioforge-lab.sh
source "$PROXMOX_INSTALLER"

SCRIPT_VERSION="0.5.0"
INSTALLER_OWNER="scenarioforge-vmware-linux-v1"
EXPECTED_INSTALLER_OWNER="$INSTALLER_OWNER"
VMRUN_TYPE="ws"
VM_BUNDLE_SUFFIX="${VM_BUNDLE_SUFFIX:-}"
VMWARE_NETWORKING_FILE="${VMWARE_NETWORKING_FILE:-/etc/vmware/networking}"
VMWARE_VIRTUAL_HW_VERSION="${VMWARE_VIRTUAL_HW_VERSION:-20}"
VMWARE_DISK_BUS="${VMWARE_DISK_BUS:-scsi}"
VMWARE_ENABLE_3D="${VMWARE_ENABLE_3D:-FALSE}"
VMWARE_PRODUCT_NAME="${VMWARE_PRODUCT_NAME:-VMware Workstation}"
VMWARE_NETWORK_EDITOR_NAME="${VMWARE_NETWORK_EDITOR_NAME:-Virtual Network Editor}"
HOST_VALIDATION_LABEL="${HOST_VALIDATION_LABEL:-Linux, VMware Workstation, networks, paths, and resources}"
DEBIAN_GUEST_OS="${DEBIAN_GUEST_OS:-debian12-64}"
UBUNTU_GUEST_OS="${UBUNTU_GUEST_OS:-ubuntu-64}"
DEBIAN_IMAGE_CACHE_NAME="${DEBIAN_IMAGE_CACHE_NAME:-debian-12-genericcloud-amd64.qcow2}"
UBUNTU_IMAGE_CACHE_NAME="${UBUNTU_IMAGE_CACHE_NAME:-noble-server-cloudimg-amd64.img}"

LAB_DIR="${SF_VMWARE_LAB_DIR:-${HOME}/vmware/ScenarioForge-Lab}"
STATE_DIR="${SCENARIOFORGE_VMWARE_STATE_DIR:-${XDG_STATE_HOME:-${HOME}/.local/state}/scenarioforge-vmware-lab}"
STATE_FILE="$STATE_DIR/state.env"
CREDENTIALS_FILE="$STATE_DIR/credentials.env"
RUNTIME_STATUS_FILE="${SCENARIOFORGE_VMWARE_RUNTIME_STATUS_FILE:-${XDG_RUNTIME_DIR:-/tmp}/scenarioforge-vmware-${UID}.status}"
IMAGE_CACHE="${SF_IMAGE_CACHE:-${XDG_CACHE_HOME:-${HOME}/.cache}/scenarioforge-vmware-lab/images}"

MANAGEMENT_VMNET="${SF_VMWARE_MANAGEMENT_VMNET:-vmnet1}"
HITL_VMNET="${SF_VMWARE_HITL_VMNET:-vmnet2}"

CORE_NAME="${SF_CORE_NAME:-scenarioforge-core}"
APP_NAME="${SF_APP_NAME:-scenarioforge-app}"
PARTICIPANT_NAME="${SF_PARTICIPANT_NAME:-scenarioforge-participant}"
CORE_DIR="$LAB_DIR/$CORE_NAME$VM_BUNDLE_SUFFIX"
APP_DIR="$LAB_DIR/$APP_NAME$VM_BUNDLE_SUFFIX"
PARTICIPANT_DIR="$LAB_DIR/$PARTICIPANT_NAME$VM_BUNDLE_SUFFIX"
CORE_VMX="$CORE_DIR/$CORE_NAME.vmx"
APP_VMX="$APP_DIR/$APP_NAME.vmx"
PARTICIPANT_VMX="$PARTICIPANT_DIR/$PARTICIPANT_NAME.vmx"

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

# These values are consumed by the shared guest-template functions sourced above.
# shellcheck disable=SC2034
CORE_MINIMAL_URL="${SF_CORE_MINIMAL_URL:-https://github.com/raistlinJ/coreemu-minimal.git}"
CORE_MINIMAL_REF="${SF_CORE_MINIMAL_REF:-main}"
# shellcheck disable=SC2034
CORE_REPO_URL="${SF_CORE_REPO_URL:-https://github.com/raistlinJ/core.git}"
CORE_REPO_REF="${SF_CORE_REPO_REF:-master}"
# shellcheck disable=SC2034
SCENARIOFORGE_URL="${SF_SCENARIOFORGE_URL:-https://github.com/raistlinJ/scenarioforge.git}"
SCENARIOFORGE_REF="${SF_SCENARIOFORGE_REF:-main}"

DEBIAN_IMAGE_URL="${SF_DEBIAN_IMAGE_URL:-https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2}"
DEBIAN_SUMS_URL="${SF_DEBIAN_SUMS_URL:-https://cloud.debian.org/images/cloud/bookworm/latest/SHA512SUMS}"
UBUNTU_IMAGE_URL="${SF_UBUNTU_IMAGE_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}"
UBUNTU_SUMS_URL="${SF_UBUNTU_SUMS_URL:-https://cloud-images.ubuntu.com/noble/current/SHA256SUMS}"

SSH_PUBLIC_KEY_FILE="${SF_SSH_PUBLIC_KEY_FILE:-}"
WAIT_MINUTES="${SF_WAIT_MINUTES:-90}"
STATUS_INTERVAL="${SF_STATUS_INTERVAL:-10}"
COMMAND=install
DRY_RUN=0
ASSUME_YES=0
FORCE_CLEANUP=0
WAIT_FOR_BOOTSTRAP=1
STATUS_WATCH=0
VERBOSE="${SF_VERBOSE:-0}"
HEADLESS=0
WORK_DIR=""
INSTALL_PERCENT=0
INSTALL_PHASE=""
INSTALL_COMPLETE=0
INSTALL_STARTED_EPOCH=""
PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED=0
RUNTIME_TRACKING=0
INSTALL_STATE_INITIALIZED=0

timestamp() { date '+%Y-%m-%d %H:%M:%S'; }
emit() {
    local level="$1"
    shift
    printf '%s [scenarioforge-vmware] %-8s %s\n' "$(timestamp)" "$level" "$*"
}
log() { emit INFO "$@"; }
warn() { emit WARN "$@" >&2; }
die() {
    emit ERROR "$@" >&2
    write_runtime_status failed "Installer stopped" "$*"
    exit 1
}
verbose() { [[ "$VERBOSE" -eq 1 ]] && emit DEBUG "$@" || true; }
progress() {
    INSTALL_PERCENT="$1"
    shift
    CURRENT_STEP=$((CURRENT_STEP + 1))
    INSTALL_PHASE="$*"
    emit PROGRESS "[$(printf '%3d' "$INSTALL_PERCENT")%] [$CURRENT_STEP/$TOTAL_STEPS] $*"
    write_runtime_status running "$INSTALL_PHASE" ""
    write_state_if_present
}
run() {
    if [[ "$DRY_RUN" -eq 1 ]]; then
        printf '%s [scenarioforge-vmware] DRY-RUN  ' "$(timestamp)"
        printf '%q ' "$@"
        printf '\n'
        return 0
    fi
    verbose "Running: $(printf '%q ' "$@")"
    "$@"
}

usage() {
    cat <<'EOF'
Usage:
  install-scenarioforge-lab.sh install [options]
  install-scenarioforge-lab.sh status [--watch] [--interval SECONDS]
  install-scenarioforge-lab.sh cleanup [--dry-run] [--force] [--yes]
  install-scenarioforge-lab.sh --cleanup [--dry-run] [--force] [--yes]
  install-scenarioforge-lab.sh --help

Provision three graphical VMs on x86_64 Linux with VMware Workstation:
  - Debian 12 + CORE GUI/XFCE from raistlinJ/core via coreemu-minimal --from-source
  - Ubuntu 24.04 + XFCE and native ScenarioForge behind nginx
  - Debian 12 + a minimal XFCE participant desktop

Important options:
  --config FILE               read lower-precedence key=value options from FILE
  --lab-dir PATH              VM directory (default: ~/vmware/ScenarioForge-Lab)
  --management-vmnet NAME     APP/CORE management network (default: vmnet1)
  --hitl-vmnet NAME           isolated CORE/participant network (default: vmnet2)
  --ssh-public-key FILE       add an OpenSSH public key to all guest users
  --core-password PASSWORD    set the corevm password (default: generated)
  --app-password PASSWORD     set the scenarioforge VM password (default: generated)
  --participant-password PASS set the participant password (default: generated)
  --web-admin-password PASS   set the coreadmin Web UI password (default: generated)
  --flag-generators           install raistlinJ flag-generator catalogs on APP
  --vulnhub                   install the repo's Vulhub vulnerability snapshot on APP
  --wait-minutes N            bootstrap timeout (default: 90)
  --no-wait                   return after participant isolation is complete
  --headless                  start VMs without opening Workstation windows
  --verbose                   show detailed commands and guest progress
  --watch                     keep printing status until provisioning completes
  --interval SECONDS          status interval (default: 10, minimum: 2)
  --yes                       do not ask for confirmation
  --dry-run                   validate and show the plan without changing files or VMs
  --cleanup                   alias for the cleanup command
  --force                     allow cleanup of a complete, running lab

Network/address overrides:
  --app-management-cidr CIDR   default: 172.31.250.2/24
  --core-management-cidr CIDR  default: 172.31.250.3/24
  --core-hitl-cidr CIDR        default: 10.254.200.3/24
  --participant-cidr CIDR      default: 10.254.200.10/24

Repository overrides:
  --core-minimal-ref REF       default: main
  --core-ref REF               default: master
  --scenarioforge-ref REF      default: main
  --flag-generators-ref REF    default: tested metadata snapshot 5f612eecb8ff

Before installation, create vmnet2 in Workstation's Virtual Network Editor as a
custom network with DHCP, NAT, and the host virtual adapter disabled. See the
adjacent README for prerequisites and all SF_* environment overrides.
EOF
}

apply_vmware_config_value() {
    local key="$1" value="$2"
    case "$key" in
        lab_dir) assign_config_setting LAB_DIR SF_VMWARE_LAB_DIR "$value" ;;
        management_vmnet) assign_config_setting MANAGEMENT_VMNET SF_VMWARE_MANAGEMENT_VMNET "$value" ;;
        hitl_vmnet) assign_config_setting HITL_VMNET SF_VMWARE_HITL_VMNET "$value" ;;
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
        no_wait) parse_config_boolean "$key" "$value"; WAIT_FOR_BOOTSTRAP=$((1 - CONFIG_BOOLEAN_VALUE)) ;;
        headless) parse_config_boolean "$key" "$value"; HEADLESS="$CONFIG_BOOLEAN_VALUE" ;;
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
        *) die "$CONFIG_FILE:$CONFIG_LINE: unknown VMware config key: $key" ;;
    esac
}

# shellcheck disable=SC2034
parse_args() {
    load_config_from_args apply_vmware_config_value "$@"
    if [[ $# -gt 0 && "$1" != -* ]]; then COMMAND="$1"; shift; fi
    while [[ $# -gt 0 ]]; do
        case "$1" in
            -h|--help) usage; exit 0 ;;
            --version) printf '%s\n' "$SCRIPT_VERSION"; exit 0 ;;
            --config) [[ $# -ge 2 ]] || die "--config requires a file"; shift 2 ;;
            --config=*) shift ;;
            --cleanup) COMMAND=cleanup; shift ;;
            --lab-dir) LAB_DIR="${2:?missing value for --lab-dir}"; shift 2 ;;
            --management-vmnet) MANAGEMENT_VMNET="${2:?missing value for --management-vmnet}"; shift 2 ;;
            --hitl-vmnet) HITL_VMNET="${2:?missing value for --hitl-vmnet}"; shift 2 ;;
            --ssh-public-key) SSH_PUBLIC_KEY_FILE="${2:?missing value for --ssh-public-key}"; shift 2 ;;
            --core-password) REQUESTED_CORE_PASSWORD="${2:?missing value for --core-password}"; shift 2 ;;
            --app-password) REQUESTED_APP_PASSWORD="${2:?missing value for --app-password}"; shift 2 ;;
            --participant-password) REQUESTED_PARTICIPANT_PASSWORD="${2:?missing value for --participant-password}"; shift 2 ;;
            --web-admin-password) REQUESTED_WEB_ADMIN_PASSWORD="${2:?missing value for --web-admin-password}"; shift 2 ;;
            --flag-generators) INSTALL_FLAG_GENERATORS=1; shift ;;
            --vulnhub) INSTALL_VULNHUB=1; shift ;;
            --wait-minutes) WAIT_MINUTES="${2:?missing value for --wait-minutes}"; shift 2 ;;
            --no-wait) WAIT_FOR_BOOTSTRAP=0; shift ;;
            --headless) HEADLESS=1; shift ;;
            --verbose) VERBOSE=1; shift ;;
            --watch) STATUS_WATCH=1; shift ;;
            --interval) STATUS_INTERVAL="${2:?missing value for --interval}"; shift 2 ;;
            --yes|-y) ASSUME_YES=1; shift ;;
            --dry-run) DRY_RUN=1; shift ;;
            --force) FORCE_CLEANUP=1; shift ;;
            --app-management-cidr) APP_MANAGEMENT_CIDR="${2:?missing value}"; shift 2 ;;
            --core-management-cidr) CORE_MANAGEMENT_CIDR="${2:?missing value}"; shift 2 ;;
            --core-hitl-cidr) CORE_HITL_CIDR="${2:?missing value}"; shift 2 ;;
            --participant-cidr) PARTICIPANT_CIDR="${2:?missing value}"; shift 2 ;;
            --core-minimal-ref) CORE_MINIMAL_REF="${2:?missing value}"; shift 2 ;;
            --core-ref) CORE_REPO_REF="${2:?missing value}"; shift 2 ;;
            --scenarioforge-ref) SCENARIOFORGE_REF="${2:?missing value}"; shift 2 ;;
            --flag-generators-ref) FLAG_GENERATORS_REF="${2:?missing value}"; shift 2 ;;
            *) die "unknown option: $1" ;;
        esac
    done
    case "$COMMAND" in install|status|cleanup) ;; *) die "unknown command: $COMMAND" ;; esac

    CORE_DIR="$LAB_DIR/$CORE_NAME$VM_BUNDLE_SUFFIX"
    APP_DIR="$LAB_DIR/$APP_NAME$VM_BUNDLE_SUFFIX"
    PARTICIPANT_DIR="$LAB_DIR/$PARTICIPANT_NAME$VM_BUNDLE_SUFFIX"
    CORE_VMX="$CORE_DIR/$CORE_NAME.vmx"
    APP_VMX="$APP_DIR/$APP_NAME.vmx"
    PARTICIPANT_VMX="$PARTICIPANT_DIR/$PARTICIPANT_NAME.vmx"
}

validate_uint() {
    local label="$1" value="$2" minimum="$3"
    if [[ ! "$value" =~ ^[0-9]+$ ]] || (( value < minimum )); then
        die "$label must be an integer of at least $minimum"
    fi
}
validate_cidr() {
    local label="$1" cidr="$2"
    python3 - "$label" "$cidr" <<'PY' || exit 1
import ipaddress, sys
try:
    ipaddress.ip_interface(sys.argv[2])
except ValueError as exc:
    print(f"ERROR: {sys.argv[1]} is invalid: {exc}", file=sys.stderr)
    raise SystemExit(1)
PY
}
validate_name() {
    [[ "$2" =~ ^[A-Za-z0-9._-]+$ ]] || die "$1 contains unsupported characters: $2"
}
validate_paths() {
    [[ "$LAB_DIR" == /* && "$LAB_DIR" != / ]] || die "lab directory must be an absolute, non-root path"
    [[ "$STATE_DIR" == /* && "$STATE_DIR" != / ]] || die "state directory must be an absolute, non-root path"
    case "$CORE_DIR $APP_DIR $PARTICIPANT_DIR" in
        *".."*) die "VM paths may not contain '..'" ;;
    esac
}

file_owner_uid() {
    stat -c '%u' "$1" 2>/dev/null || stat -f '%u' "$1"
}

file_mode_octal() {
    stat -c '%a' "$1" 2>/dev/null || stat -f '%Lp' "$1"
}

require_workstation_runtime() {
    [[ "$(uname -s)" == Linux ]] || die "this installer requires an x86_64 Linux host; use the platform-specific installer on other hosts"
    [[ "$(uname -m)" == x86_64 ]] || die "this first release supports x86_64/amd64 Linux hosts only"
    command -v vmrun >/dev/null 2>&1 || die "required command not found: vmrun"
    [[ "$EUID" -ne 0 ]] || die "run this installer as your desktop user, not root, so Workstation owns and displays the VMs correctly"
}
require_linux_workstation() {
    require_workstation_runtime
    local command
    for command in vmware-vdiskmanager qemu-img curl openssl python3 timeout sha256sum sha512sum; do
        command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
    done
    if ! command -v xorriso >/dev/null 2>&1 && ! command -v genisoimage >/dev/null 2>&1; then
        die "xorriso or genisoimage is required to create Cloud-Init seed ISOs"
    fi
}

host_network_exists() {
    vmrun -T "$VMRUN_TYPE" listHostNetworks 2>/dev/null \
        | awk '$2 ~ /^vmnet[0-9]+$/ {print $2}' | grep -Fxq -- "$1"
}
validate_hitl_isolation() {
    local number config="$VMWARE_NETWORKING_FILE" network_row
    number="${HITL_VMNET#vmnet}"
    [[ "$number" =~ ^[0-9]+$ ]] || die "HITL network must be named vmnetN, got: $HITL_VMNET"
    network_row="$(vmrun -T "$VMRUN_TYPE" listHostNetworks 2>/dev/null \
        | awk -v wanted="$HITL_VMNET" '$2 == wanted {print; exit}')"
    [[ -n "$network_row" ]] || die "could not inspect $HITL_VMNET"
    [[ "$(awk '{print $4}' <<<"$network_row")" == false ]] \
        || die "$HITL_VMNET has DHCP enabled; disable it in $VMWARE_NETWORK_EDITOR_NAME"
    [[ "$(awk '{print $3}' <<<"$network_row")" != nat && "$(awk '{print $3}' <<<"$network_row")" != bridged ]] \
        || die "$HITL_VMNET is not an isolated custom/host-only network"
    if [[ -r "$config" ]]; then
        if grep -Eq "^[[:space:]]*answer[[:space:]]+VNET_${number}_(DHCP|NAT|VIRTUAL_ADAPTER)[[:space:]]+yes([[:space:]]|$)" "$config"; then
            die "$HITL_VMNET is not isolated; disable its DHCP, NAT, and host virtual adapter in $VMWARE_NETWORK_EDITOR_NAME"
        fi
        verbose "Verified no DHCP, NAT, or host adapter is enabled for $HITL_VMNET"
    else
        warn "cannot read $config; verify $HITL_VMNET has DHCP, NAT, and its host adapter disabled"
    fi
}

validate_inputs() {
    validate_paths
    validate_name "management vmnet" "$MANAGEMENT_VMNET"
    validate_name "HITL vmnet" "$HITL_VMNET"
    [[ "$MANAGEMENT_VMNET" != "$HITL_VMNET" ]] || die "management and HITL vmnets must be different"
    [[ "$INSTALL_FLAG_GENERATORS" == "0" || "$INSTALL_FLAG_GENERATORS" == "1" ]] \
        || die "SF_INSTALL_FLAG_GENERATORS must be 0 or 1"
    [[ "$INSTALL_VULNHUB" == "0" || "$INSTALL_VULNHUB" == "1" ]] \
        || die "SF_INSTALL_VULNHUB must be 0 or 1"
    validate_ref "flag-generators ref" "$FLAG_GENERATORS_REF"
    validate_password_override "CORE password" "$REQUESTED_CORE_PASSWORD"
    validate_password_override "APP password" "$REQUESTED_APP_PASSWORD"
    validate_password_override "participant password" "$REQUESTED_PARTICIPANT_PASSWORD"
    validate_password_override "Web administrator password" "$REQUESTED_WEB_ADMIN_PASSWORD"
    [[ "$FLAG_GENERATORS_URL" == https://* || "$FLAG_GENERATORS_URL" == ssh://* \
        || "$FLAG_GENERATORS_URL" == git@*:* ]] \
        || die "flag-generators URL must use HTTPS or SSH"
    validate_uint "wait minutes" "$WAIT_MINUTES" 1
    validate_uint "status interval" "$STATUS_INTERVAL" 2
    validate_uint "CORE memory" "$CORE_MEMORY_MB" 2048
    validate_uint "APP memory" "$APP_MEMORY_MB" 2048
    validate_uint "participant memory" "$PARTICIPANT_MEMORY_MB" 1024
    validate_cidr "APP management CIDR" "$APP_MANAGEMENT_CIDR"
    validate_cidr "CORE management CIDR" "$CORE_MANAGEMENT_CIDR"
    validate_cidr "CORE HITL CIDR" "$CORE_HITL_CIDR"
    validate_cidr "participant CIDR" "$PARTICIPANT_CIDR"
    [[ -z "$SSH_PUBLIC_KEY_FILE" || -r "$SSH_PUBLIC_KEY_FILE" ]] \
        || die "SSH public key is not readable: $SSH_PUBLIC_KEY_FILE"
    [[ ! -e "$STATE_FILE" ]] || die "installer state already exists at $STATE_FILE; use status or cleanup"
    local vmx
    for vmx in "$CORE_VMX" "$APP_VMX" "$PARTICIPANT_VMX"; do
        [[ ! -e "$vmx" ]] || die "VM already exists: $vmx"
    done
    host_network_exists "$MANAGEMENT_VMNET" || die "management network $MANAGEMENT_VMNET was not found in $VMWARE_PRODUCT_NAME"
    host_network_exists "$HITL_VMNET" || die "HITL network $HITL_VMNET was not found; create it in $VMWARE_NETWORK_EDITOR_NAME first"
    validate_hitl_isolation
}

confirm_install() {
    log "VMware Workstation lab plan:"
    log "  VM files: $LAB_DIR"
    log "  Management: $MANAGEMENT_VMNET (APP $APP_MANAGEMENT_CIDR <-> CORE $CORE_MANAGEMENT_CIDR)"
    log "  HITL: $HITL_VMNET (CORE ens19, no IP <-> participant $PARTICIPANT_CIDR)"
    log "  Uplink: VMware NAT for CORE and APP; temporary for participant provisioning"
    if [[ "$INSTALL_FLAG_GENERATORS" == "1" || "$INSTALL_VULNHUB" == "1" ]]; then
        log "  Optional content: flag-generators=$INSTALL_FLAG_GENERATORS vulnhub=$INSTALL_VULNHUB (ref $FLAG_GENERATORS_REF)"
    fi
    [[ "$ASSUME_YES" -eq 1 || "$DRY_RUN" -eq 1 ]] && return
    local response
    printf 'Type INSTALL to create the three VMs: '
    read -r response
    [[ "$response" == INSTALL ]] || die "installation cancelled"
}

write_runtime_status() {
    local state="$1" phase="$2" detail="$3" temp
    [[ "$RUNTIME_TRACKING" -eq 1 && "$DRY_RUN" -eq 0 ]] || return 0
    temp="$(mktemp "$RUNTIME_STATUS_FILE.XXXXXX")" || return 0
    {
        shell_assignment RUNTIME_PID "$$"
        shell_assignment RUNTIME_STATE "$state"
        shell_assignment RUNTIME_PERCENT "${INSTALL_PERCENT:-0}"
        shell_assignment RUNTIME_PHASE "$phase"
        shell_assignment RUNTIME_DETAIL "$detail"
        shell_assignment RUNTIME_UPDATED "$(timestamp)"
    } > "$temp"
    chmod 0600 "$temp"
    mv -f -- "$temp" "$RUNTIME_STATUS_FILE"
}

write_state() {
    [[ "$DRY_RUN" -eq 0 ]] || return
    install -d -m 0700 "$STATE_DIR"
    local temp="$STATE_FILE.new" credentials_temp="$CREDENTIALS_FILE.new"
    {
        shell_assignment INSTALLER_VERSION "$SCRIPT_VERSION"
        shell_assignment INSTALLER_OWNER "$INSTALLER_OWNER"
        shell_assignment INSTALLER_UID "$UID"
        shell_assignment LAB_DIR "$LAB_DIR"
        shell_assignment MANAGEMENT_VMNET "$MANAGEMENT_VMNET"
        shell_assignment HITL_VMNET "$HITL_VMNET"
        shell_assignment CORE_NAME "$CORE_NAME"
        shell_assignment APP_NAME "$APP_NAME"
        shell_assignment PARTICIPANT_NAME "$PARTICIPANT_NAME"
        shell_assignment CORE_VMX "$CORE_VMX"
        shell_assignment APP_VMX "$APP_VMX"
        shell_assignment PARTICIPANT_VMX "$PARTICIPANT_VMX"
        shell_assignment CORE_MANAGEMENT_CIDR "$CORE_MANAGEMENT_CIDR"
        shell_assignment APP_MANAGEMENT_CIDR "$APP_MANAGEMENT_CIDR"
        shell_assignment CORE_HITL_CIDR "$CORE_HITL_CIDR"
        shell_assignment PARTICIPANT_CIDR "$PARTICIPANT_CIDR"
        shell_assignment PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED "$PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED"
        shell_assignment INSTALL_STARTED_EPOCH "$INSTALL_STARTED_EPOCH"
        shell_assignment INSTALL_PERCENT "$INSTALL_PERCENT"
        shell_assignment INSTALL_PHASE "$INSTALL_PHASE"
        shell_assignment INSTALL_COMPLETE "$INSTALL_COMPLETE"
        shell_assignment HEADLESS "$HEADLESS"
        shell_assignment INSTALL_FLAG_GENERATORS "$INSTALL_FLAG_GENERATORS"
        shell_assignment INSTALL_VULNHUB "$INSTALL_VULNHUB"
        shell_assignment FLAG_GENERATORS_REF "$FLAG_GENERATORS_REF"
        shell_assignment FLAG_GENERATORS_RESOLVED_COMMIT "$FLAG_GENERATORS_RESOLVED_COMMIT"
    } > "$temp"
    {
        shell_assignment CORE_VM_USERNAME corevm
        shell_assignment CORE_VM_PASSWORD "$CORE_PASSWORD"
        shell_assignment APP_VM_USERNAME scenarioforge
        shell_assignment APP_VM_PASSWORD "$APP_PASSWORD"
        shell_assignment PARTICIPANT_VM_USERNAME participant
        shell_assignment PARTICIPANT_VM_PASSWORD "$PARTICIPANT_PASSWORD"
        shell_assignment SCENARIOFORGE_ADMIN_USERNAME coreadmin
        shell_assignment SCENARIOFORGE_ADMIN_PASSWORD "$SCENARIOFORGE_ADMIN_PASSWORD"
    } > "$credentials_temp"
    chmod 0600 "$temp" "$credentials_temp"
    mv -f -- "$credentials_temp" "$CREDENTIALS_FILE"
    mv -f -- "$temp" "$STATE_FILE"
    INSTALL_STATE_INITIALIZED=1
}
write_state_if_present() {
    [[ "$INSTALL_STATE_INITIALIZED" -eq 1 && -f "$STATE_FILE" ]] && write_state || true
}

load_state() {
    [[ -f "$STATE_FILE" && ! -L "$STATE_FILE" ]] || die "no safe installer state found at $STATE_FILE"
    [[ "$(file_owner_uid "$STATE_FILE")" == "$UID" ]] || die "state file is not owned by the current user: $STATE_FILE"
    (( (8#$(file_mode_octal "$STATE_FILE") & 8#022) == 0 )) || die "state file is group/world writable: $STATE_FILE"
    # shellcheck disable=SC1090
    source "$STATE_FILE"
    [[ "${INSTALLER_OWNER:-}" == "$EXPECTED_INSTALLER_OWNER" ]] || die "state file belongs to a different installer"
    [[ "${INSTALLER_UID:-}" == "$UID" ]] || die "saved lab belongs to a different user"
    validate_name "CORE VM name" "$CORE_NAME"
    validate_name "APP VM name" "$APP_NAME"
    validate_name "participant VM name" "$PARTICIPANT_NAME"
    CORE_DIR="$LAB_DIR/$CORE_NAME$VM_BUNDLE_SUFFIX"
    APP_DIR="$LAB_DIR/$APP_NAME$VM_BUNDLE_SUFFIX"
    PARTICIPANT_DIR="$LAB_DIR/$PARTICIPANT_NAME$VM_BUNDLE_SUFFIX"
    validate_paths
    [[ "$CORE_VMX" == "$CORE_DIR/$CORE_NAME.vmx" \
        && "$APP_VMX" == "$APP_DIR/$APP_NAME.vmx" \
        && "$PARTICIPANT_VMX" == "$PARTICIPANT_DIR/$PARTICIPANT_NAME.vmx" ]] \
        || die "saved VM paths do not match the guarded lab layout"
    if [[ -f "$CREDENTIALS_FILE" && ! -L "$CREDENTIALS_FILE" ]]; then
        [[ "$(file_owner_uid "$CREDENTIALS_FILE")" == "$UID" ]] || die "credentials file is not owned by the current user"
        (( (8#$(file_mode_octal "$CREDENTIALS_FILE") & 8#077) == 0 )) || die "credentials file permissions must be 0600"
        # shellcheck disable=SC1090
        source "$CREDENTIALS_FILE"
        CORE_PASSWORD="${CORE_VM_PASSWORD:-}"
        APP_PASSWORD="${APP_VM_PASSWORD:-}"
        PARTICIPANT_PASSWORD="${PARTICIPANT_VM_PASSWORD:-}"
    fi
    INSTALL_STATE_INITIALIZED=1
}

random_vmware_mac() {
    local bytes
    bytes="$(openssl rand -hex 3)"
    # VMware reserves 00:50:56:00:00:00 through 00:50:56:3f:ff:ff for manual MACs.
    printf '00:50:56:%02x:%s:%s\n' "$(( 16#${bytes:0:2} & 0x3f ))" "${bytes:2:2}" "${bytes:4:2}"
}

download_verified_image() {
    local url="$1" sums_url="$2" algorithm="$3" destination="$4"
    local filename sums expected actual temporary
    filename="${url##*/}"
    sums="$(curl -fsSL --retry 3 "$sums_url")" || die "could not download checksum list: $sums_url"
    expected="$(awk -v name="$filename" '$2 == name || $2 == "*" name {print $1; exit}' <<<"$sums")"
    [[ -n "$expected" ]] || die "checksum list does not contain $filename"
    if [[ -f "$destination" ]]; then
        actual="$("${algorithm}sum" "$destination" | awk '{print $1}')"
        if [[ "$actual" == "$expected" ]]; then log "Using verified cached image $destination"; return; fi
        warn "Cached image checksum changed; replacing it"
    fi
    install -d -m 0755 "$(dirname "$destination")"
    temporary="$destination.part"
    rm -f -- "$temporary"
    log "Downloading $filename"
    curl -fL --retry 3 --progress-bar "$url" -o "$temporary"
    actual="$("${algorithm}sum" "$temporary" | awk '{print $1}')"
    [[ "$actual" == "$expected" ]] || { rm -f -- "$temporary"; die "checksum verification failed for $filename"; }
    mv -f -- "$temporary" "$destination"
}

write_vmware_cloud_init_files() {
    write_guest_bootstraps
    write_cloud_init_files
    local file
    for file in core-user.yaml app-user.yaml participant-user.yaml; do
        sed \
            -e 's/packages: \[git, curl, ca-certificates, qemu-guest-agent, spice-vdagent\]/packages: [git, curl, ca-certificates, open-vm-tools, open-vm-tools-desktop]/' \
            -e 's/packages: \[qemu-guest-agent, spice-vdagent\]/packages: [open-vm-tools, open-vm-tools-desktop]/' \
            -e 's/qemu-guest-agent/open-vm-tools.service/' \
            -e '/spice-vdagentd\.socket.*spice-vdagentd\.service/d' \
            "$WORK_DIR/$file" > "$WORK_DIR/$file.new"
        mv -f -- "$WORK_DIR/$file.new" "$WORK_DIR/$file"
    done
}

create_seed_iso() {
    local role="$1" name="$2" output="$3" seed_dir
    seed_dir="$WORK_DIR/seed-$role"
    install -d -m 0700 "$seed_dir"
    install -m 0600 "$WORK_DIR/$role-user.yaml" "$seed_dir/user-data"
    install -m 0600 "$WORK_DIR/$role-network.yaml" "$seed_dir/network-config"
    printf 'instance-id: scenarioforge-%s-%s\nlocal-hostname: %s\n' "$role" "$(date +%s)" "$name" > "$seed_dir/meta-data"
    if command -v xorriso >/dev/null 2>&1; then
        xorriso -as mkisofs -quiet -output "$output" -volid cidata -joliet -rock \
            "$seed_dir/user-data" "$seed_dir/meta-data" "$seed_dir/network-config"
    else
        genisoimage -quiet -output "$output" -volid cidata -joliet -rock \
            "$seed_dir/user-data" "$seed_dir/meta-data" "$seed_dir/network-config"
    fi
}

prepare_disk() {
    local source="$1" destination="$2" size_gb="$3"
    log "Converting $(basename "$source") to VMware VMDK for $(basename "$(dirname "$destination")")"
    qemu-img convert -p -f qcow2 -O vmdk -o subformat=monolithicSparse,adapter_type=lsilogic \
        "$source" "$destination"
    vmware-vdiskmanager -x "${size_gb}GB" "$destination"
}

append_nic() {
    local vmx="$1" slot="$2" kind="$3" network="$4" mac="$5"
    {
        printf 'ethernet%s.present = "TRUE"\n' "$slot"
        printf 'ethernet%s.virtualDev = "vmxnet3"\n' "$slot"
        printf 'ethernet%s.startConnected = "TRUE"\n' "$slot"
        printf 'ethernet%s.addressType = "static"\n' "$slot"
        printf 'ethernet%s.address = "%s"\n' "$slot" "$mac"
        printf 'ethernet%s.connectionType = "%s"\n' "$slot" "$kind"
        [[ "$kind" != custom ]] || printf 'ethernet%s.vnet = "%s"\n' "$slot" "$network"
    } >> "$vmx"
}

create_vmx() {
    local vmx="$1" name="$2" guest_os="$3" memory="$4" cores="$5" disk="$6" seed="$7"
    install -d -m 0755 "$(dirname "$vmx")"
    cat > "$vmx" <<EOF
.encoding = "UTF-8"
config.version = "8"
virtualHW.version = "$VMWARE_VIRTUAL_HW_VERSION"
pciBridge0.present = "TRUE"
pciBridge4.present = "TRUE"
pciBridge4.virtualDev = "pcieRootPort"
pciBridge4.functions = "8"
pciBridge5.present = "TRUE"
pciBridge5.virtualDev = "pcieRootPort"
pciBridge5.functions = "8"
pciBridge6.present = "TRUE"
pciBridge6.virtualDev = "pcieRootPort"
pciBridge6.functions = "8"
pciBridge7.present = "TRUE"
pciBridge7.virtualDev = "pcieRootPort"
pciBridge7.functions = "8"
displayName = "$name"
guestOS = "$guest_os"
firmware = "efi"
memsize = "$memory"
numvcpus = "$cores"
cpuid.coresPerSocket = "$cores"
sata0.present = "TRUE"
sata0:1.present = "TRUE"
sata0:1.deviceType = "cdrom-image"
sata0:1.fileName = "$(basename "$seed")"
sata0:1.startConnected = "TRUE"
usb.present = "TRUE"
ehci.present = "TRUE"
usb_xhci.present = "TRUE"
sound.present = "TRUE"
sound.autodetect = "TRUE"
mks.enable3d = "$VMWARE_ENABLE_3D"
tools.syncTime = "TRUE"
scenarioforge.install.owner = "$INSTALLER_OWNER"
scenarioforge.install.role = "$name"
EOF
    case "$VMWARE_DISK_BUS" in
        nvme)
            {
                printf 'nvme0.present = "TRUE"\n'
                printf 'nvme0:0.present = "TRUE"\n'
                printf 'nvme0:0.fileName = "%s"\n' "$(basename "$disk")"
            } >> "$vmx"
            ;;
        scsi)
            {
                printf 'scsi0.present = "TRUE"\n'
                printf 'scsi0.virtualDev = "lsilogic"\n'
                printf 'scsi0:0.present = "TRUE"\n'
                printf 'scsi0:0.fileName = "%s"\n' "$(basename "$disk")"
            } >> "$vmx"
            ;;
        *) die "unsupported VMware disk bus: $VMWARE_DISK_BUS" ;;
    esac
}

create_vms() {
    local debian="$IMAGE_CACHE/$DEBIAN_IMAGE_CACHE_NAME"
    local ubuntu="$IMAGE_CACHE/$UBUNTU_IMAGE_CACHE_NAME"
    install -d -m 0755 "$CORE_DIR" "$APP_DIR" "$PARTICIPANT_DIR"

    prepare_disk "$debian" "$CORE_DIR/$CORE_NAME.vmdk" "$CORE_DISK_GB"
    create_seed_iso core "$CORE_NAME" "$CORE_DIR/$CORE_NAME-cidata.iso"
    create_vmx "$CORE_VMX" "$CORE_NAME" "$DEBIAN_GUEST_OS" "$CORE_MEMORY_MB" "$CORE_CORES" \
        "$CORE_DIR/$CORE_NAME.vmdk" "$CORE_DIR/$CORE_NAME-cidata.iso"
    append_nic "$CORE_VMX" 0 custom "$MANAGEMENT_VMNET" "$CORE_NET0_MAC"
    append_nic "$CORE_VMX" 1 custom "$HITL_VMNET" "$CORE_NET1_MAC"
    append_nic "$CORE_VMX" 2 nat "" "$CORE_NET2_MAC"

    prepare_disk "$ubuntu" "$APP_DIR/$APP_NAME.vmdk" "$APP_DISK_GB"
    create_seed_iso app "$APP_NAME" "$APP_DIR/$APP_NAME-cidata.iso"
    create_vmx "$APP_VMX" "$APP_NAME" "$UBUNTU_GUEST_OS" "$APP_MEMORY_MB" "$APP_CORES" \
        "$APP_DIR/$APP_NAME.vmdk" "$APP_DIR/$APP_NAME-cidata.iso"
    append_nic "$APP_VMX" 0 nat "" "$APP_NET0_MAC"
    append_nic "$APP_VMX" 1 custom "$MANAGEMENT_VMNET" "$APP_NET1_MAC"

    prepare_disk "$debian" "$PARTICIPANT_DIR/$PARTICIPANT_NAME.vmdk" "$PARTICIPANT_DISK_GB"
    create_seed_iso participant "$PARTICIPANT_NAME" "$PARTICIPANT_DIR/$PARTICIPANT_NAME-cidata.iso"
    create_vmx "$PARTICIPANT_VMX" "$PARTICIPANT_NAME" "$DEBIAN_GUEST_OS" \
        "$PARTICIPANT_MEMORY_MB" "$PARTICIPANT_CORES" "$PARTICIPANT_DIR/$PARTICIPANT_NAME.vmdk" \
        "$PARTICIPANT_DIR/$PARTICIPANT_NAME-cidata.iso"
    append_nic "$PARTICIPANT_VMX" 0 custom "$HITL_VMNET" "$PARTICIPANT_NET0_MAC"
    append_nic "$PARTICIPANT_VMX" 1 nat "" "$PARTICIPANT_NET1_MAC"
}

start_vm() {
    local vmx="$1" mode=gui
    [[ "$HEADLESS" -eq 0 ]] || mode=nogui
    vmrun -T "$VMRUN_TYPE" start "$vmx" "$mode"
}
vm_running() { vmrun -T "$VMRUN_TYPE" list 2>/dev/null | tail -n +2 | grep -Fxq -- "$1"; }

guest_file_exists() {
    local vmx="$1" username="$2" password="$3" path="$4"
    timeout 5 vmrun -T "$VMRUN_TYPE" -gu "$username" -gp "$password" \
        fileExistsInGuest "$vmx" "$path" >/dev/null 2>&1
}
guest_file_text() {
    local vmx="$1" username="$2" password="$3" path="$4" temp
    temp="$(mktemp "${TMPDIR:-/tmp}/scenarioforge-vmware-read.XXXXXX")"
    if timeout 5 vmrun -T "$VMRUN_TYPE" -gu "$username" -gp "$password" \
        CopyFileFromGuestToHost "$vmx" "$path" "$temp" >/dev/null 2>&1; then
        tr -d '\r' < "$temp"
    fi
    rm -f -- "$temp"
}
guest_percent() {
    local vmx="$1" username="$2" password="$3" marker="$4" current
    if guest_file_exists "$vmx" "$username" "$password" "$marker"; then printf '100\n'; return; fi
    current="$(guest_file_text "$vmx" "$username" "$password" /var/lib/scenarioforge/bootstrap-percent || true)"
    [[ "$current" =~ ^[0-9]+$ ]] && (( current <= 100 )) && printf '%s\n' "$current" || printf '0\n'
}
guest_phase() {
    local text
    text="$(guest_file_text "$1" "$2" "$3" /var/lib/scenarioforge/bootstrap-status || true)"
    printf '%s\n' "${text:-waiting for VMware Tools / Cloud-Init}"
}

detach_participant_uplink() {
    [[ "$PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED" == 1 ]] || return
    log "Stopping the participant briefly to remove its temporary NAT uplink"
    if vm_running "$PARTICIPANT_VMX"; then vmrun -T "$VMRUN_TYPE" stop "$PARTICIPANT_VMX" soft || true; fi
    local deadline=$(( $(date +%s) + 60 ))
    while vm_running "$PARTICIPANT_VMX" && (( $(date +%s) < deadline )); do sleep 2; done
    if vm_running "$PARTICIPANT_VMX"; then
        warn "participant did not stop gracefully; forcing power off before network isolation"
        vmrun -T "$VMRUN_TYPE" stop "$PARTICIPANT_VMX" hard
    fi
    vmrun -T "$VMRUN_TYPE" deleteNetworkAdapter "$PARTICIPANT_VMX" 1
    if vmrun -T "$VMRUN_TYPE" listNetworkAdapters "$PARTICIPANT_VMX" 2>/dev/null | grep -Eq '^1[[:space:]]'; then
        die "participant NAT adapter is still attached; remove ethernet1 in $VMWARE_PRODUCT_NAME before using the lab"
    fi
    PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED=0
    write_state
    start_vm "$PARTICIPANT_VMX"
}

wait_for_participant() {
    local deadline=$(( $(date +%s) + WAIT_MINUTES * 60 )) percent phase elapsed
    while :; do
        if guest_file_exists "$PARTICIPANT_VMX" participant "$PARTICIPANT_PASSWORD" /var/lib/scenarioforge/participant-ready; then return; fi
        percent="$(guest_percent "$PARTICIPANT_VMX" participant "$PARTICIPANT_PASSWORD" /var/lib/scenarioforge/participant-ready)"
        phase="$(guest_phase "$PARTICIPANT_VMX" participant "$PARTICIPANT_PASSWORD")"
        [[ "$phase" != failed* ]] || die "participant provisioning failed: $phase"
        elapsed="$(format_elapsed "$INSTALL_STARTED_EPOCH")"
        emit PROGRESS "[$(printf '%3d' "$INSTALL_PERCENT")%] Participant ${percent}% (elapsed $elapsed): $phase"
        (( $(date +%s) < deadline )) || die "participant provisioning timed out after $WAIT_MINUTES minutes; its temporary NAT adapter was left attached for diagnosis"
        sleep 20
    done
}

wait_for_all_guests() {
    local deadline=$(( $(date +%s) + WAIT_MINUTES * 60 )) cp ap pp cphase aphase pphase elapsed
    while :; do
        cp="$(guest_percent "$CORE_VMX" corevm "$CORE_PASSWORD" /var/lib/scenarioforge/core-ready)"
        ap="$(guest_percent "$APP_VMX" scenarioforge "$APP_PASSWORD" /var/lib/scenarioforge/app-ready)"
        pp="$(guest_percent "$PARTICIPANT_VMX" participant "$PARTICIPANT_PASSWORD" /var/lib/scenarioforge/participant-ready)"
        cphase="$(guest_phase "$CORE_VMX" corevm "$CORE_PASSWORD")"
        aphase="$(guest_phase "$APP_VMX" scenarioforge "$APP_PASSWORD")"
        pphase="$(guest_phase "$PARTICIPANT_VMX" participant "$PARTICIPANT_PASSWORD")"
        [[ "$cphase" != failed* ]] || die "CORE provisioning failed: $cphase"
        [[ "$aphase" != failed* ]] || die "APP provisioning failed: $aphase"
        [[ "$pphase" != failed* ]] || die "participant provisioning failed: $pphase"
        INSTALL_PERCENT=$(( 60 + (cp + ap + pp) * 39 / 300 ))
        elapsed="$(format_elapsed "$INSTALL_STARTED_EPOCH")"
        emit PROGRESS "[$(printf '%3d' "$INSTALL_PERCENT")%] Guest bootstrap (elapsed $elapsed): CORE=${cp}% APP=${ap}% PARTICIPANT=${pp}%"
        verbose "CORE: $cphase | APP: $aphase | PARTICIPANT: $pphase"
        write_runtime_status running "$INSTALL_PHASE" "CORE=$cp APP=$ap PARTICIPANT=$pp"
        write_state
        (( cp == 100 && ap == 100 && pp == 100 )) && return
        (( $(date +%s) < deadline )) || die "guest provisioning timed out after $WAIT_MINUTES minutes; run '$0 status' for the last reported phases"
        sleep 20
    done
}

vm_power_text() { vm_running "$1" && printf running || printf stopped; }
app_ip() {
    timeout 15 vmrun -T "$VMRUN_TYPE" getGuestIPAddress "$APP_VMX" -wait 2>/dev/null | tail -n 1 || true
}
transfer_optional_content_to_app() {
    [[ "$INSTALL_FLAG_GENERATORS" == "1" || "$INSTALL_VULNHUB" == "1" ]] || return 0
    [[ -f "$OPTIONAL_CONTENT_ARCHIVE" && -f "$CATALOG_TRANSFER_KEY" ]] \
        || die "optional content payload or one-time transfer key is missing"
    local deadline address="" elapsed remote_archive=/tmp/scenarioforge-optional-content.tar.gz
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
    log "Waiting for VMware Tools and one-time APP SSH content-transfer access"
    while :; do
        address="$(app_ip)"
        if [[ -n "$address" ]] \
            && ssh "${ssh_options[@]}" "scenarioforge@$address" true >/dev/null 2>&1; then
            break
        fi
        elapsed="$(format_elapsed "$INSTALL_STARTED_EPOCH")"
        emit PROGRESS "[ 58%] Optional-content transfer waiting for APP SSH (elapsed $elapsed)"
        (( $(date +%s) < deadline )) \
            || die "timed out waiting for APP SSH while installing optional catalogs"
        sleep 10
    done
    log "Transferring requested generator/vulnerability content to APP at $address"
    scp -q "${ssh_options[@]}" "$OPTIONAL_CONTENT_ARCHIVE" \
        "scenarioforge@$address:$remote_archive.part"
    local remote_sha
    remote_sha="$(ssh "${ssh_options[@]}" "scenarioforge@$address" \
        "sha256sum /tmp/scenarioforge-optional-content.tar.gz.part | cut -d ' ' -f 1")"
    [[ "$remote_sha" == "$OPTIONAL_CONTENT_SHA256" ]] \
        || die "APP optional-content transfer checksum verification failed"
    ssh "${ssh_options[@]}" "scenarioforge@$address" \
        "mv -f -- /tmp/scenarioforge-optional-content.tar.gz.part /tmp/scenarioforge-optional-content.tar.gz"
    log "Optional content transfer verified; APP will install it before starting ScenarioForge"
}
show_credentials() {
    local address
    address="$(app_ip)"
    printf '\nCredentials\n'
    printf '  CORE VM:        corevm / %s\n' "$CORE_VM_PASSWORD"
    printf '  APP VM:         scenarioforge / %s\n' "$APP_VM_PASSWORD"
    printf '  PARTICIPANT VM: participant / %s\n' "$PARTICIPANT_VM_PASSWORD"
    printf '  ScenarioForge:  coreadmin / %s\n' "$SCENARIOFORGE_ADMIN_PASSWORD"
    [[ -z "$address" ]] || printf '  Web GUI:         https://%s/\n' "$address"
    printf '  APP browser:     Epiphany with a ScenarioForge desktop launcher\n'
    printf '  APP tools:       Terminator, Evince (PDF), xdot (Graphviz), and Mousepad/jq (JSON)\n'
    printf '  Stored securely: %s (mode 0600)\n\n' "$CREDENTIALS_FILE"
}

show_status_once() {
    load_state
    local cp ap pp cphase aphase pphase address percent
    cp="$(guest_percent "$CORE_VMX" corevm "${CORE_VM_PASSWORD:-}" /var/lib/scenarioforge/core-ready)"
    ap="$(guest_percent "$APP_VMX" scenarioforge "${APP_VM_PASSWORD:-}" /var/lib/scenarioforge/app-ready)"
    pp="$(guest_percent "$PARTICIPANT_VMX" participant "${PARTICIPANT_VM_PASSWORD:-}" /var/lib/scenarioforge/participant-ready)"
    cphase="$(guest_phase "$CORE_VMX" corevm "${CORE_VM_PASSWORD:-}")"
    aphase="$(guest_phase "$APP_VMX" scenarioforge "${APP_VM_PASSWORD:-}")"
    pphase="$(guest_phase "$PARTICIPANT_VMX" participant "${PARTICIPANT_VM_PASSWORD:-}")"
    percent="${INSTALL_PERCENT:-0}"
    if [[ "$INSTALL_COMPLETE" != 1 && "$PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED" != 1 \
        && "$cp" == 100 && "$ap" == 100 && "$pp" == 100 ]]; then
        INSTALL_COMPLETE=1
        INSTALL_PERCENT=100
        INSTALL_PHASE="Installation complete"
        write_state
    fi
    if [[ "$INSTALL_COMPLETE" != 1 && "$percent" -ge 60 ]]; then percent=$(( 60 + (cp + ap + pp) * 39 / 300 )); fi
    [[ "$INSTALL_COMPLETE" != 1 ]] || percent=100
    address="$(app_ip)"
    printf 'ScenarioForge VMware lab [%3d%%]\n' "$percent"
    printf '  CORE        %-7s bootstrap=%3s%%  %s\n' "$(vm_power_text "$CORE_VMX")" "$cp" "$cphase"
    printf '  APP         %-7s bootstrap=%3s%%  %s\n' "$(vm_power_text "$APP_VMX")" "$ap" "$aphase"
    printf '  PARTICIPANT %-7s bootstrap=%3s%%  %s\n' "$(vm_power_text "$PARTICIPANT_VMX")" "$pp" "$pphase"
    printf '  Management: APP %s <-> CORE %s on %s\n' "$APP_MANAGEMENT_CIDR" "$CORE_MANAGEMENT_CIDR" "$MANAGEMENT_VMNET"
    printf '  HITL:       CORE ens19 <-> participant %s on %s\n' "$PARTICIPANT_CIDR" "$HITL_VMNET"
    printf '  Temp NAT:   %s\n' "$([[ "$PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED" == 1 ]] && echo attached || echo removed)"
    if [[ "${INSTALL_FLAG_GENERATORS:-0}" == "1" || "${INSTALL_VULNHUB:-0}" == "1" ]]; then
        printf '  Optional:   flag-generators=%s vulnhub=%s\n' \
            "${INSTALL_FLAG_GENERATORS:-0}" "${INSTALL_VULNHUB:-0}"
    fi
    [[ -z "$address" ]] || printf '  Web GUI:    https://%s/\n' "$address"
    printf '  Credentials: %s\n' "$CREDENTIALS_FILE"
}

show_status() {
    if [[ "$STATUS_WATCH" -eq 0 ]]; then show_status_once; return; fi
    log "Watching every $STATUS_INTERVAL seconds; press Ctrl-C to stop"
    while [[ ! -f "$STATE_FILE" ]]; do
        if [[ -f "$RUNTIME_STATUS_FILE" && ! -L "$RUNTIME_STATUS_FILE" \
            && "$(file_owner_uid "$RUNTIME_STATUS_FILE")" == "$UID" \
            && $(( 8#$(file_mode_octal "$RUNTIME_STATUS_FILE") & 8#022 )) -eq 0 ]]; then
            # shellcheck disable=SC1090
            source "$RUNTIME_STATUS_FILE"
            emit INFO "Installer ${RUNTIME_STATE:-unknown} [${RUNTIME_PERCENT:-0}%]: ${RUNTIME_PHASE:-starting}"
            [[ "${RUNTIME_STATE:-}" != failed ]] || { warn "${RUNTIME_DETAIL:-installer failed}"; return 2; }
        else
            emit INFO "Waiting for installer state at $STATE_FILE"
        fi
        sleep "$STATUS_INTERVAL"
    done
    while :; do
        printf '\n'
        show_status_once
        [[ "${INSTALL_COMPLETE:-0}" == 1 ]] && return
        sleep "$STATUS_INTERVAL"
    done
}

vmx_owned() {
    [[ -f "$1" && ! -L "$1" ]] \
        && grep -Fqx "scenarioforge.install.owner = \"$INSTALLER_OWNER\"" "$1"
}
safe_vm_dir() {
    local directory="$1" expected="$2"
    [[ "$directory" == "$LAB_DIR/$expected" && "$directory" != / && ! -L "$directory" ]]
}
cleanup_healthy() {
    [[ "${INSTALL_COMPLETE:-0}" == 1 ]] || return 1
    vm_running "$CORE_VMX" && vm_running "$APP_VMX" && vm_running "$PARTICIPANT_VMX"
}
perform_cleanup() {
    load_state
    local vmx directory name response
    log "Cleanup scope:"
    for vmx in "$CORE_VMX" "$APP_VMX" "$PARTICIPANT_VMX"; do
        if vmx_owned "$vmx"; then
            log "  installer-owned VM: $vmx"
        else
            warn "preserving unverified or missing VM: $vmx"
        fi
    done
    log "  state and credentials: $STATE_DIR"
    log "  cached base images are preserved: $IMAGE_CACHE"
    if cleanup_healthy; then
        if [[ "$DRY_RUN" -eq 0 ]]; then
            [[ "$FORCE_CLEANUP" -eq 1 ]] || die "the lab is complete and running; use cleanup --force to remove it"
            warn "--force permits removal of a complete running lab"
        else
            log "  lab is complete and running; an actual cleanup would also require --force"
        fi
    fi
    if [[ "$DRY_RUN" -eq 0 && "$ASSUME_YES" -eq 0 ]]; then
        printf 'Type CLEANUP to permanently remove the listed VMs: '
        read -r response
        [[ "$response" == CLEANUP ]] || die "cleanup cancelled"
    fi
    for vmx in "$CORE_VMX" "$APP_VMX" "$PARTICIPANT_VMX"; do
        vmx_owned "$vmx" || continue
        if vm_running "$vmx"; then
            if [[ "$DRY_RUN" -eq 1 ]]; then
                run vmrun -T "$VMRUN_TYPE" stop "$vmx" soft
            else
                run vmrun -T "$VMRUN_TYPE" stop "$vmx" soft || true
                local deadline=$(( $(date +%s) + 60 ))
                while vm_running "$vmx" && (( $(date +%s) < deadline )); do sleep 2; done
                vm_running "$vmx" && run vmrun -T "$VMRUN_TYPE" stop "$vmx" hard
            fi
        fi
        directory="$(dirname "$vmx")"
        name="$(basename "$directory")"
        safe_vm_dir "$directory" "$name" || die "refusing unsafe VM directory: $directory"
        log "Removing installer-owned VM directory $directory"
        run rm -rf -- "$directory"
    done
    log "Removing installer state and credentials"
    run rm -f -- "$STATE_FILE" "$CREDENTIALS_FILE" "$RUNTIME_STATUS_FILE" \
        "$STATE_FILE.new" "$CREDENTIALS_FILE.new" "$RUNTIME_STATUS_FILE.new"
    if [[ "$DRY_RUN" -eq 0 && -d "$STATE_DIR" ]]; then rmdir "$STATE_DIR" 2>/dev/null || true; fi
    log "Cleanup complete; verified image cache preserved at $IMAGE_CACHE"
}

perform_install() {
    INSTALL_STARTED_EPOCH="$(date +%s)"
    RUNTIME_TRACKING=1
    if [[ "$DRY_RUN" -eq 1 ]]; then
        configure_install_progress 2
    else
        configure_install_progress 6
    fi
    progress 2 "Validating $HOST_VALIDATION_LABEL"
    require_linux_workstation
    validate_inputs
    confirm_install
    if [[ "$DRY_RUN" -eq 1 ]]; then
        if [[ "$INSTALL_FLAG_GENERATORS" == "1" || "$INSTALL_VULNHUB" == "1" ]]; then
            progress 4 "Authenticating and preparing requested APP catalogs"
            prepare_optional_content
        fi
        progress 100 "Dry-run validation complete; no resources were changed"
        return
    fi

    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/scenarioforge-vmware.XXXXXX")"
    trap '[[ -n "${WORK_DIR:-}" && -d "$WORK_DIR" ]] && rm -rf -- "$WORK_DIR"' EXIT
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
    CORE_NET0_MAC="$(random_vmware_mac)"
    CORE_NET1_MAC="$(random_vmware_mac)"
    CORE_NET2_MAC="$(random_vmware_mac)"
    APP_NET0_MAC="$(random_vmware_mac)"
    APP_NET1_MAC="$(random_vmware_mac)"
    PARTICIPANT_NET0_MAC="$(random_vmware_mac)"
    PARTICIPANT_NET1_MAC="$(random_vmware_mac)"
    PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED=1
    write_state

    progress 10 "Downloading and verifying Debian 12 and Ubuntu 24.04 cloud images"
    download_verified_image "$DEBIAN_IMAGE_URL" "$DEBIAN_SUMS_URL" sha512 "$IMAGE_CACHE/$DEBIAN_IMAGE_CACHE_NAME"
    download_verified_image "$UBUNTU_IMAGE_URL" "$UBUNTU_SUMS_URL" sha256 "$IMAGE_CACHE/$UBUNTU_IMAGE_CACHE_NAME"

    progress 25 "Generating CORE, native ScenarioForge, participant, XFCE, and Cloud-Init configuration"
    write_vmware_cloud_init_files

    progress 35 "Converting cloud disks and creating VMware VMX/seed ISO files"
    create_vms

    progress 55 "Starting the CORE, APP, and participant VMs"
    start_vm "$CORE_VMX"
    start_vm "$APP_VMX"
    start_vm "$PARTICIPANT_VMX"

    transfer_optional_content_to_app
    INSTALL_PHASE="Waiting for Cloud-Init and guest bootstrap"
    INSTALL_PERCENT=60
    write_state
    if [[ "$WAIT_FOR_BOOTSTRAP" -eq 1 ]]; then
        wait_for_all_guests
    else
        wait_for_participant
    fi
    progress 99 "Removing the participant's temporary NAT adapter and restoring its graphical session"
    detach_participant_uplink
    if [[ "$WAIT_FOR_BOOTSTRAP" -eq 1 ]]; then
        INSTALL_COMPLETE=1
        INSTALL_PERCENT=100
        INSTALL_PHASE="Installation complete"
        write_state
        write_runtime_status complete "$INSTALL_PHASE" ""
        emit PROGRESS "[100%] ScenarioForge VMware lab installation complete"
    else
        INSTALL_PHASE="Participant isolated; CORE and APP provisioning continue"
        write_state
        write_runtime_status complete "$INSTALL_PHASE" ""
        warn "CORE and APP are still provisioning; use '$0 status --watch'"
    fi
    show_status_once
    show_credentials
}

on_error() {
    local line="$1" code="$2"
    emit ERROR "unexpected installer failure at line $line (exit $code)" >&2
    write_runtime_status failed "Installer stopped unexpectedly" "line $line, exit $code"
    [[ -f "$STATE_FILE" ]] && warn "VMs and credentials were left intact; inspect with: $0 status"
}

main() {
    parse_args "$@"
    trap 'code=$?; on_error "$LINENO" "$code"' ERR
    case "$COMMAND" in
        install) perform_install ;;
        status) require_workstation_runtime; show_status ;;
        cleanup) require_workstation_runtime; perform_cleanup ;;
    esac
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
