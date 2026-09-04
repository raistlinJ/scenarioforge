#!/usr/bin/env bash
# Provision the three-VM ScenarioForge lab with VMware Fusion on macOS.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WORKSTATION_INSTALLER="$SCRIPT_DIR/../vmware-workstation/install-scenarioforge-lab.sh"
[[ -r "$WORKSTATION_INSTALLER" ]] || {
    printf 'ERROR: shared VMware installer not found: %s\n' "$WORKSTATION_INSTALLER" >&2
    exit 1
}
# Fusion and Workstation use the same VMX/vmrun model. Source the tested Linux
# implementation, then replace only the macOS host and architecture seams.
# shellcheck source=scripts/vmware-workstation/install-scenarioforge-lab.sh
source "$WORKSTATION_INSTALLER"

SCRIPT_VERSION="0.1.0"
INSTALLER_OWNER="scenarioforge-vmware-fusion-v1"
EXPECTED_INSTALLER_OWNER="$INSTALLER_OWNER"
VMRUN_TYPE="fusion"
VMWARE_PRODUCT_NAME="VMware Fusion"
VMWARE_NETWORK_EDITOR_NAME="VMware Fusion Network settings"
HOST_VALIDATION_LABEL="macOS, VMware Fusion, networks, paths, and resources"
VM_BUNDLE_SUFFIX=".vmwarevm"
VMWARE_NETWORKING_FILE="${SF_FUSION_NETWORKING_FILE:-/Library/Preferences/VMware Fusion/networking}"
FUSION_APP="${SF_FUSION_APP:-/Applications/VMware Fusion.app}"
FUSION_VMRUN="$FUSION_APP/Contents/Library/vmrun"
FUSION_VDISK_MANAGER="$FUSION_APP/Contents/Library/vmware-vdiskmanager"

LAB_DIR="${SF_FUSION_LAB_DIR:-${HOME}/Virtual Machines.localized/ScenarioForge-Lab}"
STATE_DIR="${SCENARIOFORGE_FUSION_STATE_DIR:-${HOME}/Library/Application Support/ScenarioForge/fusion-lab}"
STATE_FILE="$STATE_DIR/state.env"
CREDENTIALS_FILE="$STATE_DIR/credentials.env"
RUNTIME_STATUS_FILE="${SCENARIOFORGE_FUSION_RUNTIME_STATUS_FILE:-${TMPDIR:-/tmp}scenarioforge-fusion-${UID}.status}"
IMAGE_CACHE="${SF_FUSION_IMAGE_CACHE:-${HOME}/Library/Caches/ScenarioForge/fusion-lab/images}"
MANAGEMENT_VMNET="${SF_FUSION_MANAGEMENT_VMNET:-vmnet1}"
HITL_VMNET="${SF_FUSION_HITL_VMNET:-vmnet2}"

HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
    arm64)
        GUEST_ARCH="arm64"
        DEBIAN_IMAGE_URL="${SF_DEBIAN_IMAGE_URL:-https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-arm64.qcow2}"
        UBUNTU_IMAGE_URL="${SF_UBUNTU_IMAGE_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img}"
        DEBIAN_IMAGE_CACHE_NAME="debian-12-genericcloud-arm64.qcow2"
        UBUNTU_IMAGE_CACHE_NAME="noble-server-cloudimg-arm64.img"
        DEBIAN_GUEST_OS="arm-debian12-64"
        UBUNTU_GUEST_OS="arm-ubuntu-64"
        VMWARE_DISK_BUS="nvme"
        # Hardware version 20 is supported across the Fusion 13 family; newer
        # Fusion releases can run VMs created with an older hardware version.
        VMWARE_VIRTUAL_HW_VERSION="20"
        VMWARE_ENABLE_3D="TRUE"
        ;;
    x86_64)
        GUEST_ARCH="amd64"
        DEBIAN_IMAGE_URL="${SF_DEBIAN_IMAGE_URL:-https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-genericcloud-amd64.qcow2}"
        UBUNTU_IMAGE_URL="${SF_UBUNTU_IMAGE_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}"
        DEBIAN_IMAGE_CACHE_NAME="debian-12-genericcloud-amd64.qcow2"
        UBUNTU_IMAGE_CACHE_NAME="noble-server-cloudimg-amd64.img"
        DEBIAN_GUEST_OS="debian12-64"
        UBUNTU_GUEST_OS="ubuntu-64"
        VMWARE_DISK_BUS="scsi"
        VMWARE_VIRTUAL_HW_VERSION="20"
        VMWARE_ENABLE_3D="FALSE"
        ;;
    *)
        printf 'ERROR: unsupported Mac architecture: %s\n' "$HOST_ARCH" >&2
        exit 1
        ;;
esac

CORE_DIR="$LAB_DIR/$CORE_NAME$VM_BUNDLE_SUFFIX"
APP_DIR="$LAB_DIR/$APP_NAME$VM_BUNDLE_SUFFIX"
PARTICIPANT_DIR="$LAB_DIR/$PARTICIPANT_NAME$VM_BUNDLE_SUFFIX"
CORE_VMX="$CORE_DIR/$CORE_NAME.vmx"
APP_VMX="$APP_DIR/$APP_NAME.vmx"
PARTICIPANT_VMX="$PARTICIPANT_DIR/$PARTICIPANT_NAME.vmx"

emit() {
    local level="$1"
    shift
    printf '%s [scenarioforge-fusion] %-8s %s\n' "$(timestamp)" "$level" "$*"
}

vmrun() { "$FUSION_VMRUN" "$@"; }
vmware-vdiskmanager() { "$FUSION_VDISK_MANAGER" "$@"; }
sha256sum() { shasum -a 256 "$@"; }
sha512sum() { shasum -a 512 "$@"; }

# macOS does not ship GNU timeout. Keep the inherited guest polling behavior
# without requiring Homebrew coreutils.
timeout() {
    local seconds="${1:?timeout duration required}"
    shift
    python3 - "$seconds" "$@" <<'PY'
import subprocess
import sys

seconds = float(sys.argv[1])
try:
    completed = subprocess.run(sys.argv[2:], timeout=seconds, check=False)
except subprocess.TimeoutExpired:
    raise SystemExit(124)
raise SystemExit(completed.returncode)
PY
}

usage() {
    cat <<'EOF'
Usage:
  install-scenarioforge-lab.sh install [options]
  install-scenarioforge-lab.sh status [--watch] [--interval SECONDS]
  install-scenarioforge-lab.sh cleanup [--dry-run] [--force] [--yes]
  install-scenarioforge-lab.sh --cleanup [--dry-run] [--force] [--yes]
  install-scenarioforge-lab.sh --help

Provision three graphical VMs with VMware Fusion on Intel or Apple silicon:
  - Debian 12 + CORE GUI/XFCE from raistlinJ/core via coreemu-minimal --from-source
  - Ubuntu 24.04 + XFCE, browser, tools, and native ScenarioForge behind nginx
  - Debian 12 + a minimal XFCE participant desktop

Important options:
  --config FILE               read lower-precedence key=value options from FILE
  --lab-dir PATH              VM directory (default: ~/Virtual Machines.localized/ScenarioForge-Lab)
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
  --headless                  start VMs without opening Fusion windows
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

Create vmnet2 in VMware Fusion > Settings > Network as a custom network with
DHCP, NAT, and host access disabled. See the adjacent README for details.
EOF
}

apply_vmware_config_value() {
    local key="$1" value="$2"
    case "$key" in
        lab_dir) assign_config_setting LAB_DIR SF_FUSION_LAB_DIR "$value" ;;
        management_vmnet) assign_config_setting MANAGEMENT_VMNET SF_FUSION_MANAGEMENT_VMNET "$value" ;;
        hitl_vmnet) assign_config_setting HITL_VMNET SF_FUSION_HITL_VMNET "$value" ;;
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
        *) die "$CONFIG_FILE:$CONFIG_LINE: unknown Fusion config key: $key" ;;
    esac
}

require_workstation_runtime() {
    [[ "$(uname -s)" == Darwin ]] || die "this installer requires macOS; use the platform-specific installer on other hosts"
    [[ "$EUID" -ne 0 ]] || die "run this installer as your macOS desktop user, not root"
    [[ -x "$FUSION_VMRUN" ]] || die "VMware Fusion vmrun was not found at $FUSION_VMRUN"
    [[ -x "$FUSION_VDISK_MANAGER" ]] || die "VMware Fusion disk manager was not found at $FUSION_VDISK_MANAGER"
}

require_linux_workstation() {
    require_workstation_runtime
    local command
    for command in qemu-img curl openssl python3 shasum hdiutil; do
        command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
    done
    vmrun -T "$VMRUN_TYPE" listHostNetworks >/dev/null 2>&1 \
        || die "VMware Fusion is installed but vmrun could not inspect its networks; open Fusion once and complete first-run setup"
}

create_seed_iso() {
    local role="$1" name="$2" output="$3" seed_dir
    seed_dir="$WORK_DIR/seed-$role"
    install -d -m 0700 "$seed_dir"
    install -m 0600 "$WORK_DIR/$role-user.yaml" "$seed_dir/user-data"
    install -m 0600 "$WORK_DIR/$role-network.yaml" "$seed_dir/network-config"
    printf 'instance-id: scenarioforge-%s-%s\nlocal-hostname: %s\n' \
        "$role" "$(date +%s)" "$name" > "$seed_dir/meta-data"
    rm -f -- "$output"
    hdiutil makehybrid -quiet -iso -joliet -default-volume-name cidata \
        -o "$output" "$seed_dir"
}

confirm_install() {
    log "VMware Fusion lab plan ($GUEST_ARCH guests on $HOST_ARCH macOS):"
    log "  VM bundles: $LAB_DIR"
    log "  Management: $MANAGEMENT_VMNET (APP $APP_MANAGEMENT_CIDR <-> CORE $CORE_MANAGEMENT_CIDR)"
    log "  HITL: $HITL_VMNET (CORE ens19, no IP <-> participant $PARTICIPANT_CIDR)"
    log "  Uplink: VMware NAT for CORE and APP; temporary for participant provisioning"
    if [[ "$HOST_ARCH" == arm64 ]]; then
        warn "Apple silicon uses ARM64 guests; x86-only vulnerability containers may require emulation or remain unavailable"
    fi
    if [[ "$INSTALL_FLAG_GENERATORS" == 1 || "$INSTALL_VULNHUB" == 1 ]]; then
        log "  Optional content: flag-generators=$INSTALL_FLAG_GENERATORS vulnhub=$INSTALL_VULNHUB (ref $FLAG_GENERATORS_REF)"
    fi
    [[ "$ASSUME_YES" -eq 1 || "$DRY_RUN" -eq 1 ]] && return
    local response
    printf 'Type INSTALL to create the three Fusion VMs: '
    read -r response
    [[ "$response" == INSTALL ]] || die "installation cancelled"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
