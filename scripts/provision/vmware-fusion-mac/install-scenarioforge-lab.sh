#!/usr/bin/env bash
# Provision the three-VM ScenarioForge lab with VMware Fusion on macOS.

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
WORKSTATION_INSTALLER="$SCRIPT_DIR/../vmware-workstation-linux/install-scenarioforge-lab.sh"
[[ -r "$WORKSTATION_INSTALLER" ]] || {
    printf 'ERROR: shared VMware installer not found: %s\n' "$WORKSTATION_INSTALLER" >&2
    exit 1
}
# Fusion and Workstation use the same VMX/vmrun model. Source the tested Linux
# implementation, then replace only the macOS host and architecture seams.
# shellcheck source=scripts/provision/vmware-workstation-linux/install-scenarioforge-lab.sh
source "$WORKSTATION_INSTALLER"

SCRIPT_VERSION="0.2.0"
INSTALLER_OWNER="scenarioforge-vmware-fusion-v1"
EXPECTED_INSTALLER_OWNER="$INSTALLER_OWNER"
VMRUN_TYPE="fusion"
VMWARE_PRODUCT_NAME="VMware Fusion"
VMWARE_NETWORK_EDITOR_NAME="VMware Fusion Network settings"
HOST_VALIDATION_LABEL="macOS, VMware Fusion, networks, paths, and resources"
VM_BUNDLE_SUFFIX=".vmwarevm"
# Fusion 13 on Apple silicon rejects the legacy es1371 device it otherwise
# chooses for a VMX that only enables sound. hdaudio is supported by Fusion on
# both host architectures and is what Fusion emits for newly created ARM VMs.
VMWARE_SOUND_DEVICE="hdaudio"
VMWARE_NETWORKING_FILE="${SF_FUSION_NETWORKING_FILE:-/Library/Preferences/VMware Fusion/networking}"
FUSION_APP="${SF_FUSION_APP:-/Applications/VMware Fusion.app}"
FUSION_VMRUN="$FUSION_APP/Contents/Library/vmrun"
FUSION_VDISK_MANAGER="$FUSION_APP/Contents/Library/vmware-vdiskmanager"
FUSION_VMNET_CLI="$FUSION_APP/Contents/Library/vmnet-cli"

LAB_DIR="${SF_FUSION_LAB_DIR:-${HOME}/Virtual Machines.localized/ScenarioForge-Lab}"
STATE_DIR="${SCENARIOFORGE_FUSION_STATE_DIR:-${HOME}/Library/Application Support/ScenarioForge/fusion-lab}"
STATE_FILE="$STATE_DIR/state.env"
CREDENTIALS_FILE="$STATE_DIR/credentials.env"
RUNTIME_STATUS_FILE="${SCENARIOFORGE_FUSION_RUNTIME_STATUS_FILE:-${TMPDIR:-/tmp}scenarioforge-fusion-${UID}.status}"
IMAGE_CACHE="${SF_FUSION_IMAGE_CACHE:-${HOME}/Library/Caches/ScenarioForge/fusion-lab/images}"
MANAGEMENT_VMNET="${SF_FUSION_MANAGEMENT_VMNET:-vmnet1}"
HITL_VMNET="${SF_FUSION_HITL_VMNET:-vmnet2}"
MANAGE_HITL_NETWORK="${SF_FUSION_MANAGE_HITL_NETWORK:-ask}"
FUSION_NETWORK_PLAN=0
FUSION_ORIGINAL_HITL_VMNET=""
FUSION_PLANNED_HITL_VMNET=""
FUSION_PLANNED_HITL_SUBNET=""
FUSION_PLANNED_HITL_NETMASK=""

HOST_ARCH="$(uname -m)"
case "$HOST_ARCH" in
    arm64)
        GUEST_ARCH="arm64"
        DEBIAN_IMAGE_URL="${SF_DEBIAN_IMAGE_URL:-https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-arm64.qcow2}"
        UBUNTU_IMAGE_URL="${SF_UBUNTU_IMAGE_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-arm64.img}"
        DEBIAN_IMAGE_CACHE_NAME="debian-12-generic-arm64.qcow2"
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
        DEBIAN_IMAGE_URL="${SF_DEBIAN_IMAGE_URL:-https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-amd64.qcow2}"
        UBUNTU_IMAGE_URL="${SF_UBUNTU_IMAGE_URL:-https://cloud-images.ubuntu.com/noble/current/noble-server-cloudimg-amd64.img}"
        DEBIAN_IMAGE_CACHE_NAME="debian-12-generic-amd64.qcow2"
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
  --manage-hitl-network       create a dedicated isolated vmnet when needed
  --no-manage-hitl-network    require a preconfigured isolated HITL vmnet
  --ssh-public-key FILE       add an OpenSSH public key to all guest users
  --core-password PASSWORD    set the corevm password (default: generated)
  --app-password PASSWORD     set the scenarioforge VM password (default: generated)
  --participant-password PASS set the participant password (default: generated)
  --web-admin-password PASS   set the coreadmin Web UI password (default: generated)
  --flag-generators           install raistlinJ flag-generator catalogs on APP
  --vulnhub                   install the repo's Vulhub vulnerability snapshot on APP
  --wait-minutes N            bootstrap timeout (default: 90)
  --no-wait                   return after participant isolation is complete
  --desktop-shortcut          create a host desktop browser shortcut (default)
  --no-desktop-shortcut       skip the host desktop browser shortcut
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

When the requested HITL vmnet is unsafe or missing, an interactive install can
propose an unused isolated replacement and confirm it before requesting macOS
administrator credentials. See the adjacent README for details.
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
        manage_hitl_network)
            parse_config_boolean "$key" "$value"
            assign_config_setting MANAGE_HITL_NETWORK SF_FUSION_MANAGE_HITL_NETWORK "$CONFIG_BOOLEAN_VALUE"
            ;;
        desktop_shortcut)
            parse_config_boolean "$key" "$value"
            assign_config_setting CREATE_DESKTOP_SHORTCUT SF_DESKTOP_SHORTCUT "$CONFIG_BOOLEAN_VALUE"
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
    [[ -x "$FUSION_VMNET_CLI" ]] || die "VMware Fusion network manager was not found at $FUSION_VMNET_CLI"
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

fusion_network_config_value() {
    local vmnet="$1" key="$2" number
    number="${vmnet#vmnet}"
    awk -v wanted="VNET_${number}_${key}" \
        '$1 == "answer" && $2 == wanted { value=$3 } END { print value }' \
        "$VMWARE_NETWORKING_FILE" 2>/dev/null
}

fusion_hitl_network_is_safe() {
    local vmnet="$1" row dhcp nat adapter subnet
    [[ "$vmnet" =~ ^vmnet[0-9]+$ && -r "$VMWARE_NETWORKING_FILE" ]] || return 1
    row="$(vmrun -T "$VMRUN_TYPE" listHostNetworks 2>/dev/null \
        | awk -v wanted="$vmnet" '$2 == wanted {print; exit}')"
    if [[ -n "$row" ]]; then
        [[ "$(awk '{print $4}' <<<"$row")" == false ]] || return 1
        [[ "$(awk '{print $3}' <<<"$row")" != nat \
            && "$(awk '{print $3}' <<<"$row")" != bridged ]] || return 1
    fi
    dhcp="$(fusion_network_config_value "$vmnet" DHCP)"
    nat="$(fusion_network_config_value "$vmnet" NAT)"
    adapter="$(fusion_network_config_value "$vmnet" VIRTUAL_ADAPTER)"
    subnet="$(fusion_network_config_value "$vmnet" HOSTONLY_SUBNET)"
    [[ "$dhcp" == no && "$nat" != yes && "$adapter" == no && -n "$subnet" ]]
}

fusion_vmnet_is_configured() {
    local vmnet="$1" number
    number="${vmnet#vmnet}"
    vmrun -T "$VMRUN_TYPE" listHostNetworks 2>/dev/null \
        | awk '$2 ~ /^vmnet[0-9]+$/ {print $2}' | grep -Fxq -- "$vmnet" \
        || grep -Eq "^[[:space:]]*answer[[:space:]]+VNET_${number}_" \
            "$VMWARE_NETWORKING_FILE" 2>/dev/null
}

fusion_vmnet_is_used_by_running_vm() {
    local vmnet="$1" vmx
    while IFS= read -r vmx; do
        [[ -r "$vmx" ]] || continue
        grep -Fq ".vnet = \"$vmnet\"" "$vmx" && return 0
    done < <(vmrun -T "$VMRUN_TYPE" list 2>/dev/null | tail -n +2)
    return 1
}

fusion_choose_unused_vmnet() {
    local requested="$1" number candidate
    if [[ "$requested" =~ ^vmnet([0-9]+)$ ]]; then
        number="${BASH_REMATCH[1]}"
        if (( number >= 2 && number != 8 )) \
            && [[ "$requested" != "$MANAGEMENT_VMNET" ]] \
            && ! fusion_vmnet_is_configured "$requested" \
            && ! fusion_vmnet_is_used_by_running_vm "$requested"; then
            printf '%s\n' "$requested"
            return
        fi
    fi
    for number in $(seq 2 255); do
        [[ "$number" -ne 8 ]] || continue
        candidate="vmnet$number"
        [[ "$candidate" != "$MANAGEMENT_VMNET" ]] || continue
        fusion_vmnet_is_configured "$candidate" && continue
        fusion_vmnet_is_used_by_running_vm "$candidate" && continue
        printf '%s\n' "$candidate"
        return
    done
    return 1
}

fusion_hitl_network_values() {
    python3 - "$CORE_HITL_CIDR" "$PARTICIPANT_CIDR" <<'PY'
import ipaddress
import sys

core = ipaddress.ip_interface(sys.argv[1])
participant = ipaddress.ip_interface(sys.argv[2])
if core.network != participant.network:
    print("CORE and participant HITL addresses must be in the same subnet", file=sys.stderr)
    raise SystemExit(1)
print(core.network.network_address)
print(core.network.netmask)
PY
}

prepare_host_network_plan() {
    fusion_hitl_network_is_safe "$HITL_VMNET" && return 0
    [[ "$MANAGEMENT_VMNET" != "$HITL_VMNET" ]] || return 0
    case "$MANAGE_HITL_NETWORK" in
        0) return ;;
        1|ask) ;;
        *) die "SF_FUSION_MANAGE_HITL_NETWORK must be 0, 1, or unset" ;;
    esac
    if [[ "$MANAGE_HITL_NETWORK" == ask && "$ASSUME_YES" -eq 1 && "$DRY_RUN" -eq 0 ]]; then
        die "$HITL_VMNET is not safely isolated; rerun with --manage-hitl-network to authorize creation of a dedicated vmnet"
    fi
    local values
    FUSION_ORIGINAL_HITL_VMNET="$HITL_VMNET"
    FUSION_PLANNED_HITL_VMNET="$(fusion_choose_unused_vmnet "$HITL_VMNET")" \
        || die "no unused Fusion vmnet number is available for the isolated HITL network"
    values="$(fusion_hitl_network_values)" \
        || die "CORE and participant HITL CIDRs do not describe one shared network"
    FUSION_PLANNED_HITL_SUBNET="$(sed -n '1p' <<<"$values")"
    FUSION_PLANNED_HITL_NETMASK="$(sed -n '2p' <<<"$values")"
    HITL_VMNET="$FUSION_PLANNED_HITL_VMNET"
    FUSION_NETWORK_PLAN=1
}

validate_host_network_plan() {
    host_network_exists "$MANAGEMENT_VMNET" \
        || die "management network $MANAGEMENT_VMNET was not found in VMware Fusion"
    if [[ "$FUSION_NETWORK_PLAN" -eq 1 ]]; then
        fusion_vmnet_is_configured "$HITL_VMNET" \
            && die "planned HITL network $HITL_VMNET became configured before installation"
        fusion_vmnet_is_used_by_running_vm "$HITL_VMNET" \
            && die "planned HITL network $HITL_VMNET is now referenced by a running VM"
        return 0
    fi
    validate_host_networks
}

validate_host_networks() {
    host_network_exists "$MANAGEMENT_VMNET" \
        || die "management network $MANAGEMENT_VMNET was not found in VMware Fusion"
    fusion_hitl_network_is_safe "$HITL_VMNET" \
        || die "$HITL_VMNET is not isolated; disable its DHCP, NAT, and host Mac adapter or use --manage-hitl-network"
}

build_fusion_networking_candidate() {
    local action="$1" source="$2" destination="$3" vmnet="$4" subnet="$5" netmask="$6"
    python3 - "$action" "$source" "$destination" "$vmnet" "$subnet" "$netmask" <<'PY'
from pathlib import Path
import re
import sys

action, source_name, destination_name, vmnet, subnet, netmask = sys.argv[1:]
number = vmnet.removeprefix("vmnet")
prefix = f"VNET_{number}_"
source = Path(source_name)
destination = Path(destination_name)
lines = source.read_text(encoding="utf-8").splitlines()

values = {}
for line in lines:
    match = re.match(r"\s*answer\s+(VNET_[0-9]+_\S+)\s+(\S+)", line)
    if match and match.group(1).startswith(prefix):
        values[match.group(1)[len(prefix):]] = match.group(2)

begin = f"# scenarioforge-fusion managed {vmnet} begin"
end = f"# scenarioforge-fusion managed {vmnet} end"
if action == "add":
    if values:
        raise SystemExit(f"refusing to overwrite existing {vmnet} configuration")
    if lines and lines[-1] != "":
        lines.append("")
    lines.extend([
        begin,
        f"answer {prefix}DHCP no",
        f"answer {prefix}HOSTONLY_NETMASK {netmask}",
        f"answer {prefix}HOSTONLY_SUBNET {subnet}",
        f"answer {prefix}NAT no",
        f"answer {prefix}VIRTUAL_ADAPTER no",
        end,
    ])
elif action == "remove":
    if not values:
        destination.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        raise SystemExit(3)
    required = {
        "DHCP": "no",
        "HOSTONLY_NETMASK": netmask,
        "HOSTONLY_SUBNET": subnet,
        "VIRTUAL_ADAPTER": "no",
    }
    for key, expected in required.items():
        if values.get(key) != expected:
            raise SystemExit(f"{vmnet} {key} changed; preserving the network")
    if values.get("NAT", "no") != "no":
        raise SystemExit(f"{vmnet} NAT changed; preserving the network")
    lines = [
        line for line in lines
        if not re.match(rf"\s*answer\s+{re.escape(prefix)}", line)
        and line not in {begin, end}
    ]
else:
    raise SystemExit(f"unknown networking candidate action: {action}")

destination.write_text("\n".join(lines).rstrip() + "\n", encoding="utf-8")
PY
}

fusion_reload_networking() {
    sudo "$FUSION_VMNET_CLI" --configure \
        && sudo "$FUSION_VMNET_CLI" --stop \
        && sudo "$FUSION_VMNET_CLI" --start
}

fusion_restore_networking() {
    local backup="$1"
    warn "Restoring the previous VMware Fusion network configuration"
    sudo install -o root -g wheel -m 0644 "$backup" "$VMWARE_NETWORKING_FILE" \
        && fusion_reload_networking
}

apply_host_network_plan() {
    [[ "$FUSION_NETWORK_PLAN" -eq 1 ]] || return 0
    local backup="$WORK_DIR/fusion-networking.before" candidate="$WORK_DIR/fusion-networking.candidate"
    cp -p -- "$VMWARE_NETWORKING_FILE" "$backup"
    build_fusion_networking_candidate add "$backup" "$candidate" "$HITL_VMNET" \
        "$FUSION_PLANNED_HITL_SUBNET" "$FUSION_PLANNED_HITL_NETMASK"
    cmp -s "$backup" "$VMWARE_NETWORKING_FILE" \
        || die "Fusion network configuration changed while preparing the update; rerun the installer"
    INSTALLER_CREATED_HITL_VMNET="$HITL_VMNET"
    INSTALLER_CREATED_HITL_SUBNET="$FUSION_PLANNED_HITL_SUBNET"
    INSTALLER_CREATED_HITL_NETMASK="$FUSION_PLANNED_HITL_NETMASK"
    write_state
    log "Creating isolated $HITL_VMNET; macOS may request an administrator password"
    if ! sudo install -o root -g wheel -m 0644 "$candidate" "$VMWARE_NETWORKING_FILE" \
        || ! fusion_reload_networking; then
        fusion_restore_networking "$backup" || true
        INSTALLER_CREATED_HITL_VMNET=""
        write_state
        die "could not apply the VMware Fusion network configuration"
    fi
    local attempt
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        fusion_hitl_network_is_safe "$HITL_VMNET" && return
        sleep 1
    done
    fusion_restore_networking "$backup" || true
    INSTALLER_CREATED_HITL_VMNET=""
    write_state
    die "Fusion did not activate $HITL_VMNET as an isolated network; the previous configuration was restored"
}

describe_host_network_cleanup() {
    [[ -n "${INSTALLER_CREATED_HITL_VMNET:-}" ]] || return 0
    log "  Installer-created Fusion network: $INSTALLER_CREATED_HITL_VMNET"
    log "  Fusion networking services will restart briefly during removal"
}

cleanup_host_networks() {
    local vmnet="${INSTALLER_CREATED_HITL_VMNET:-}"
    [[ -n "$vmnet" ]] || return 0
    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "Would remove installer-created isolated network $vmnet"
        return 0
    fi
    fusion_vmnet_is_used_by_running_vm "$vmnet" \
        && die "another running VM references installer-created $vmnet; stop or reconfigure it before cleanup"
    if ! fusion_vmnet_is_configured "$vmnet"; then
        log "Installer-created network $vmnet is already absent"
        return 0
    fi
    local backup="$STATE_DIR/fusion-networking.cleanup-before" candidate="$STATE_DIR/fusion-networking.cleanup-candidate"
    cp -p -- "$VMWARE_NETWORKING_FILE" "$backup"
    if ! build_fusion_networking_candidate remove "$backup" "$candidate" "$vmnet" \
        "$INSTALLER_CREATED_HITL_SUBNET" "$INSTALLER_CREATED_HITL_NETMASK"; then
        die "$vmnet changed since installation; preserving it and installer state for manual review"
    fi
    cmp -s "$backup" "$VMWARE_NETWORKING_FILE" \
        || die "Fusion network configuration changed while preparing cleanup; rerun cleanup"
    log "Removing installer-created isolated network $vmnet; macOS may request an administrator password"
    if ! sudo install -o root -g wheel -m 0644 "$candidate" "$VMWARE_NETWORKING_FILE" \
        || ! fusion_reload_networking; then
        fusion_restore_networking "$backup" || true
        die "could not remove $vmnet; the previous network configuration was restored"
    fi
    local attempt
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        fusion_vmnet_is_configured "$vmnet" || break
        sleep 1
    done
    fusion_vmnet_is_configured "$vmnet" \
        && die "Fusion still reports $vmnet after cleanup; installer state was preserved"
    rm -f -- "$backup" "$candidate"
    INSTALLER_CREATED_HITL_VMNET=""
}

confirm_install() {
    log "VMware Fusion lab plan ($GUEST_ARCH guests on $HOST_ARCH macOS):"
    log "  VM bundles: $LAB_DIR"
    log "  Management: $MANAGEMENT_VMNET (APP $APP_MANAGEMENT_CIDR <-> CORE $CORE_MANAGEMENT_CIDR)"
    log "  HITL: $HITL_VMNET (CORE ens19, no IP <-> participant $PARTICIPANT_CIDR)"
    log "  Uplink: VMware NAT for CORE and APP; temporary for participant provisioning"
    log "  Host desktop shortcut: $CREATE_DESKTOP_SHORTCUT (1=enabled, 0=disabled)"
    if [[ "$FUSION_NETWORK_PLAN" -eq 1 ]]; then
        warn "Requested $FUSION_ORIGINAL_HITL_VMNET is missing or not safely isolated"
        log "  Network change: create $HITL_VMNET as $FUSION_PLANNED_HITL_SUBNET/$FUSION_PLANNED_HITL_NETMASK"
        log "  Network safety: DHCP=off NAT=off host-Mac-adapter=off"
        warn "Fusion networking services will restart briefly; existing VM networking may momentarily disconnect"
        warn "macOS will request administrator credentials when the change is applied"
    fi
    if [[ "$HOST_ARCH" == arm64 ]]; then
        warn "Apple silicon uses ARM64 guests; x86-only vulnerability containers may require emulation or remain unavailable"
    fi
    if [[ "$INSTALL_FLAG_GENERATORS" == 1 || "$INSTALL_VULNHUB" == 1 ]]; then
        log "  Optional content: flag-generators=$INSTALL_FLAG_GENERATORS vulnhub=$INSTALL_VULNHUB (ref $FLAG_GENERATORS_REF)"
    fi
    [[ "$ASSUME_YES" -eq 1 || "$DRY_RUN" -eq 1 ]] && return
    local response expected=INSTALL
    [[ "$FUSION_NETWORK_PLAN" -eq 0 ]] || expected=INSTALL+NETWORK
    printf 'Type %s to approve this plan: ' "$expected"
    read -r response
    [[ "$response" == "$expected" ]] || die "installation cancelled"
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then main "$@"; fi
