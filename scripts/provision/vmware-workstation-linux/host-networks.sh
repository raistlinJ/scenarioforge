#!/usr/bin/env bash
# Sourced by the Workstation installer. Never invoked as a standalone cleanup.
WORKSTATION_VMNET_CLI="${SF_VMWARE_NETWORKS_CLI:-vmware-networks}"
WORKSTATION_NETWORK_PLAN=0
WORKSTATION_ORIGINAL_HITL_VMNET=""
WORKSTATION_PLANNED_HITL_VMNET=""
WORKSTATION_PLANNED_HITL_SUBNET=""
WORKSTATION_PLANNED_HITL_NETMASK=""
KEEP_HITL_NETWORK=0
WORKSTATION_NETWORK_FAILURE=""

workstation_require_network_inventory() {
    [[ -f "$VMWARE_NETWORKING_FILE" && -r "$VMWARE_NETWORKING_FILE" \
        && -r "${VMWARE_NETWORKING_FILE%/*}" && -x "${VMWARE_NETWORKING_FILE%/*}" ]] \
        || die "cannot inspect VMware host networks: cannot read $VMWARE_NETWORKING_FILE or its directory"
    grep -Eq '^VERSION=1,0[[:space:]]*$' "$VMWARE_NETWORKING_FILE" \
        || die "cannot inspect VMware host networks: invalid or unsupported configuration in $VMWARE_NETWORKING_FILE"
}

workstation_vmnet_is_bridged() {
    local number="${1#vmnet}"
    # Linux stores explicit mappings separately from VNET_N_* settings.
    [[ "$number" == 0 ]] || awk -v number="$number" '
        $1 == "add_bridge_mapping" && $3 == number { found=1 }
        $1 == "answer" && $2 == "VNL_DEFAULT_BRIDGE_VNET" && $3 == number { found=1 }
        $1 == "answer" && $2 == "VNET_" number "_INTERFACE" { found=1 }
        END { exit !found }
    ' "$VMWARE_NETWORKING_FILE"
}

workstation_network_config_value() {
    local vmnet="$1" key="$2" number
    number="${vmnet#vmnet}"
    awk -v wanted="VNET_${number}_${key}" \
        '$1 == "answer" && $2 == wanted { value=$3 } END { print value }' \
        "$VMWARE_NETWORKING_FILE" 2>/dev/null
}

workstation_hitl_network_is_safe() {
    local vmnet="$1" dhcp nat adapter subnet
    [[ "$vmnet" =~ ^vmnet[0-9]+$ && -r "$VMWARE_NETWORKING_FILE" ]] || return 1
    workstation_require_network_inventory
    workstation_vmnet_is_bridged "$vmnet" && return 1
    # Reject conflicting enabled entries even if a later duplicate says no.
    if grep -Eq "^[[:space:]]*answer[[:space:]]+VNET_${vmnet#vmnet}_(DHCP|NAT|VIRTUAL_ADAPTER)[[:space:]]+yes([[:space:]]|$)" "$VMWARE_NETWORKING_FILE"; then
        return 1
    fi
    dhcp="$(workstation_network_config_value "$vmnet" DHCP)"
    nat="$(workstation_network_config_value "$vmnet" NAT)"
    adapter="$(workstation_network_config_value "$vmnet" VIRTUAL_ADAPTER)"
    subnet="$(workstation_network_config_value "$vmnet" HOSTONLY_SUBNET)"
    [[ "$dhcp" == no && ( "$nat" == no || -z "$nat" ) && "$adapter" == no && -n "$subnet" ]]
}

workstation_vmnet_is_configured() {
    local vmnet="$1" number
    [[ "$vmnet" =~ ^vmnet[0-9]+$ ]] || return 1
    workstation_require_network_inventory
    number="${vmnet#vmnet}"
    workstation_vmnet_is_bridged "$vmnet" \
        || grep -Eq "^[[:space:]]*answer[[:space:]]+VNET_${number}_" \
            "$VMWARE_NETWORKING_FILE" 2>/dev/null \
        || [[ -e "${VMWARE_NETWORKING_FILE%/*}/$vmnet" ]]
}

workstation_running_vm_inventory() {
    local output status=0
    # Keep loader warnings on stderr: they are not inventory records.
    output="$(LC_ALL=C vmrun -T "$VMRUN_TYPE" list)" || status=$?
    if [[ "$status" -ne 0 ]]; then
        printf 'cannot inspect running VMware VMs (exit %s): %s\n' "$status" "${output:-<no stdout>}" >&2
        return 1
    fi
    printf '%s\n' "$output" | python3 -c '
import os
import re
import sys

output = sys.stdin.read()
lines = [line for line in output.splitlines() if line.strip()]
header = re.fullmatch(r"\s*Total\s+running\s+VMs\s*:\s*([0-9]+)\s*", lines[0], re.I) if lines else None
if not header or int(header[1]) != len(lines) - 1:
    sys.exit("invalid VMware running VM inventory: " + (output.strip() or "<empty>"))
for vmx in lines[1:]:
    if not os.path.isabs(vmx) or not os.path.isfile(vmx) or not os.access(vmx, os.R_OK):
        sys.exit("cannot inspect running VM: " + vmx)
print("Total running VMs: " + header[1])
for vmx in lines[1:]:
    print(vmx)
'
}

workstation_vmnet_is_used_by_running_vm() {
    local vmnet="$1" vmx running
    running="$(workstation_running_vm_inventory)" || die "cannot inspect running VMware VMs"
    while IFS= read -r vmx; do
        [[ -n "$vmx" ]] || continue
        [[ -r "$vmx" ]] || die "cannot inspect running VM: $vmx"
        grep -Eq "^[[:space:]]*ethernet[0-9]+[.]vnet[[:space:]]*=[[:space:]]*\"$vmnet\"" "$vmx" && return 0
    done < <(tail -n +2 <<<"$running")
    return 1
}

workstation_choose_unused_vmnet() {
    local requested="$1" number candidate
    if [[ "$requested" =~ ^vmnet([0-9]+)$ ]]; then
        number="${BASH_REMATCH[1]}"
        if (( number >= 2 && number <= 255 && number != 8 )) \
            && [[ "$requested" != "$MANAGEMENT_VMNET" ]] \
            && ! workstation_vmnet_is_configured "$requested" \
            && ! workstation_vmnet_is_used_by_running_vm "$requested"; then
            printf '%s\n' "$requested"
            return
        fi
    fi
    for number in $(seq 2 255); do
        [[ "$number" -ne 8 ]] || continue
        candidate="vmnet$number"
        [[ "$candidate" != "$MANAGEMENT_VMNET" ]] || continue
        workstation_vmnet_is_configured "$candidate" && continue
        workstation_vmnet_is_used_by_running_vm "$candidate" && continue
        printf '%s\n' "$candidate"
        return
    done
    return 1
}

workstation_hitl_network_values() {
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
    workstation_hitl_network_is_safe "$HITL_VMNET" && return 0
    [[ "$MANAGE_HITL_NETWORK" != 0 ]] || return 0
    command -v "$WORKSTATION_VMNET_CLI" >/dev/null 2>&1 \
        || die "vmware-networks is required to manage the HITL network"
    [[ -r "$VMWARE_NETWORKING_FILE" ]] || die "cannot inspect $VMWARE_NETWORKING_FILE"
    [[ "$MANAGEMENT_VMNET" != "$HITL_VMNET" ]] || return 0
    case "$MANAGE_HITL_NETWORK" in
        0) return ;;
        1|ask) ;;
        *) die "SF_VMWARE_MANAGE_HITL_NETWORK must be 0, 1, or unset" ;;
    esac
    local values
    # Check in the parent shell before entering command substitution below.
    # Otherwise die() inside the selector is misreported as pool exhaustion.
    workstation_require_network_inventory
    workstation_running_vm_inventory >/dev/null || die "cannot inspect running VMware VMs"
    WORKSTATION_ORIGINAL_HITL_VMNET="$HITL_VMNET"
    WORKSTATION_PLANNED_HITL_VMNET="$(workstation_choose_unused_vmnet "$HITL_VMNET")" \
        || die "no unused Workstation vmnet number is available for the isolated HITL network"
    values="$(workstation_hitl_network_values)" \
        || die "CORE and participant HITL CIDRs do not describe one shared network"
    WORKSTATION_PLANNED_HITL_SUBNET="$(sed -n '1p' <<<"$values")"
    WORKSTATION_PLANNED_HITL_NETMASK="$(sed -n '2p' <<<"$values")"
    HITL_VMNET="$WORKSTATION_PLANNED_HITL_VMNET"
    WORKSTATION_NETWORK_PLAN=1
}

validate_host_network_plan() {
    host_network_exists "$MANAGEMENT_VMNET" \
        || die "management network $MANAGEMENT_VMNET was not found in VMware Workstation"
    if [[ "$WORKSTATION_NETWORK_PLAN" -eq 1 ]]; then
        workstation_vmnet_is_configured "$HITL_VMNET" \
            && die "planned HITL network $HITL_VMNET became configured before installation"
        workstation_vmnet_is_used_by_running_vm "$HITL_VMNET" \
            && die "planned HITL network $HITL_VMNET is now referenced by a running VM"
        return 0
    fi
    validate_host_networks
}

validate_host_networks() {
    host_network_exists "$MANAGEMENT_VMNET" \
        || die "management network $MANAGEMENT_VMNET was not found in VMware Workstation"
    workstation_hitl_network_is_safe "$HITL_VMNET" \
        || die "$HITL_VMNET is not isolated; disable its DHCP, NAT, and host adapter or use --manage-hitl-network"
}

build_workstation_networking_candidate() {
    local action="$1" source="$2" destination="$3" vmnet="$4" subnet="$5" netmask="$6" force="${7:-0}"
    python3 - "$action" "$source" "$destination" "$vmnet" "$subnet" "$netmask" "$force" <<'PY'
from pathlib import Path
import re
import sys

action, source_name, destination_name, vmnet, subnet, netmask, force = sys.argv[1:]
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

begin = f"# scenarioforge-workstation managed {vmnet} begin"
end = f"# scenarioforge-workstation managed {vmnet} end"
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
    if not values and force != "1":
        destination.write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
        raise SystemExit(3)
    required = {
        "DHCP": "no",
        "HOSTONLY_NETMASK": netmask,
        "HOSTONLY_SUBNET": subnet,
        "VIRTUAL_ADAPTER": "no",
    }
    for key, expected in required.items():
        if force != "1" and values.get(key) != expected:
            raise SystemExit(f"{vmnet} {key} changed; preserving the network")
    if force != "1" and values.get("NAT", "no") != "no":
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

workstation_network_step() {
    local label="$1" status=0 command_text
    shift
    "$@" || status=$?
    if [[ "$status" -ne 0 ]]; then
        printf -v command_text '%q ' "$@"
        WORKSTATION_NETWORK_FAILURE="$label failed (exit $status): $command_text"
        warn "$WORKSTATION_NETWORK_FAILURE"
    fi
    return "$status"
}

workstation_configure_networking() {
    local candidate
    candidate="$(mktemp "$STATE_DIR/networking-migrate.XXXXXX")" || {
        WORKSTATION_NETWORK_FAILURE="could not create network migration file in $STATE_DIR"
        return 1
    }
    local status=0
    if workstation_network_step "Copy network settings for migration" cp -- "$VMWARE_NETWORKING_FILE" "$candidate"; then
        workstation_network_step "Migrate network settings" sudo "$WORKSTATION_VMNET_CLI" --migrate-network-settings "$candidate" || status=$?
    else
        status=$?
    fi
    rm -f -- "$candidate"
    return "$status"
}
workstation_reload_networking() {
    workstation_network_step "Stop VMware networking" sudo "$WORKSTATION_VMNET_CLI" --stop \
        && workstation_configure_networking \
        && workstation_network_step "Start VMware networking" sudo "$WORKSTATION_VMNET_CLI" --start
}

workstation_restore_networking() {
    local backup="$1"
    warn "Restoring the previous VMware Workstation network configuration"
    workstation_network_step "Stop VMware networking for rollback" sudo "$WORKSTATION_VMNET_CLI" --stop \
        && workstation_network_step "Restore network configuration" sudo install -o root -g root -m 0644 "$backup" "$VMWARE_NETWORKING_FILE" \
        && workstation_configure_networking \
        && workstation_network_step "Restart VMware networking after rollback" sudo "$WORKSTATION_VMNET_CLI" --start
}

apply_host_network_plan() {
    [[ "$WORKSTATION_NETWORK_PLAN" -eq 1 ]] || return 0
    local backup="$WORK_DIR/workstation-networking.before" candidate="$WORK_DIR/workstation-networking.candidate"
    cp -p -- "$VMWARE_NETWORKING_FILE" "$backup"
    build_workstation_networking_candidate add "$backup" "$candidate" "$HITL_VMNET" \
        "$WORKSTATION_PLANNED_HITL_SUBNET" "$WORKSTATION_PLANNED_HITL_NETMASK"
    cmp -s "$backup" "$VMWARE_NETWORKING_FILE" \
        || die "Workstation network configuration changed while preparing the update; rerun the installer"
    INSTALLER_CREATED_HITL_VMNET="$HITL_VMNET"
    INSTALLER_CREATED_HITL_SUBNET="$WORKSTATION_PLANNED_HITL_SUBNET"
    INSTALLER_CREATED_HITL_NETMASK="$WORKSTATION_PLANNED_HITL_NETMASK"
    write_state
    log "Creating isolated $HITL_VMNET; Linux may request an administrator password"
    WORKSTATION_NETWORK_FAILURE=""
    if ! workstation_network_step "Stop VMware networking" sudo "$WORKSTATION_VMNET_CLI" --stop \
        || ! workstation_network_step "Install network configuration" sudo install -o root -g root -m 0644 "$candidate" "$VMWARE_NETWORKING_FILE" \
        || ! workstation_configure_networking \
        || ! workstation_network_step "Start VMware networking" sudo "$WORKSTATION_VMNET_CLI" --start; then
        local failure="$WORKSTATION_NETWORK_FAILURE" rollback="Previous configuration restored and networking restarted."
        workstation_restore_networking "$backup" \
            || rollback="Rollback failed: $WORKSTATION_NETWORK_FAILURE. Backup retained at $backup."
        if ! workstation_vmnet_is_configured "$HITL_VMNET"; then INSTALLER_CREATED_HITL_VMNET=""; fi
        write_state
        die "could not apply the VMware Workstation network configuration: $failure. $rollback"
    fi
    local attempt
    for attempt in 1 2 3 4 5 6 7 8 9 10; do
        workstation_hitl_network_is_safe "$HITL_VMNET" && return
        sleep 1
    done
    local rollback="The previous configuration was restored and networking restarted."
    workstation_restore_networking "$backup" \
        || rollback="Rollback failed: $WORKSTATION_NETWORK_FAILURE. Backup retained at $backup."
    if ! workstation_vmnet_is_configured "$HITL_VMNET"; then INSTALLER_CREATED_HITL_VMNET=""; fi
    write_state
    die "Workstation did not activate $HITL_VMNET as an isolated network. $rollback"
}

describe_host_network_cleanup() {
    [[ -n "${INSTALLER_CREATED_HITL_VMNET:-}" ]] || return 0
    if [[ "$KEEP_HITL_NETWORK" -eq 1 ]]; then
        log "  Preserve Workstation network: $INSTALLER_CREATED_HITL_VMNET (--keep-hitl-network)"
        return 0
    fi
    log "  Installer-created Workstation network: $INSTALLER_CREATED_HITL_VMNET"
    log "  Workstation networking services will restart briefly during removal"
}

cleanup_host_networks() {
    local vmnet="${INSTALLER_CREATED_HITL_VMNET:-}"
    [[ -n "$vmnet" ]] || return 0
    if [[ "$KEEP_HITL_NETWORK" -eq 1 ]]; then
        log "Preserving $vmnet and releasing the old lab's network ownership (--keep-hitl-network)"
        if [[ "$DRY_RUN" -eq 0 ]]; then
            rm -f -- "$STATE_DIR/workstation-networking.cleanup-before" "$STATE_DIR/workstation-networking.cleanup-candidate"
            INSTALLER_CREATED_HITL_VMNET=""
        fi
        return 0
    fi
    [[ "$vmnet" =~ ^vmnet([0-9]+)$ ]] \
        || die "invalid installer-created vmnet in state: $vmnet"
    local number="${BASH_REMATCH[1]}"
    [[ "$number" -ge 2 && "$number" -le 255 && "$number" -ne 8 && "$vmnet" != "$MANAGEMENT_VMNET" ]] \
        || die "refusing to remove a reserved or management network: $vmnet"
    if [[ "$DRY_RUN" -eq 1 ]]; then
        log "Would remove installer-created network $vmnet and its network directory (force=$FORCE_CLEANUP)"
        return 0
    fi
    workstation_vmnet_is_used_by_running_vm "$vmnet" \
        && die "another running VM references installer-created $vmnet; stop or reconfigure it before cleanup"
    local network_dir="${VMWARE_NETWORKING_FILE%/*}/$vmnet"
    if ! workstation_vmnet_is_configured "$vmnet" && [[ ! -e "$network_dir" ]]; then
        log "Installer-created network $vmnet is already absent"
        INSTALLER_CREATED_HITL_VMNET=""
        return 0
    fi
    local backup="$STATE_DIR/workstation-networking.cleanup-before" candidate="$STATE_DIR/workstation-networking.cleanup-candidate"
    local network_backup="$STATE_DIR/workstation-$vmnet.cleanup-before"
    [[ ! -e "$network_backup" ]] || die "network backup already exists at $network_backup; restore or review it before retrying cleanup"
    cp -p -- "$VMWARE_NETWORKING_FILE" "$backup"
    if ! build_workstation_networking_candidate remove "$backup" "$candidate" "$vmnet" \
        "$INSTALLER_CREATED_HITL_SUBNET" "$INSTALLER_CREATED_HITL_NETMASK" "$FORCE_CLEANUP"; then
        die "$vmnet changed since installation; rerun cleanup --force to remove the tracked network, or --keep-hitl-network to preserve it."
    fi
    cmp -s "$backup" "$VMWARE_NETWORKING_FILE" \
        || die "Workstation network configuration changed while preparing cleanup; rerun cleanup"
    log "Removing installer-created network $vmnet and its network directory; Linux may request an administrator password"
    # Stop first: a running Workstation daemon may otherwise write the removed
    # network back. Its per-vmnet directory must also be removed before configure.
    sudo "$WORKSTATION_VMNET_CLI" --stop || die "could not stop Workstation networking; no configuration was removed"
    if [[ -e "$network_dir" ]]; then
        if ! sudo mv -- "$network_dir" "$network_backup"; then
            sudo "$WORKSTATION_VMNET_CLI" --start || true
            die "could not back up $vmnet; no configuration was removed"
        fi
    fi
    local removed=0 attempt
    if sudo install -o root -g root -m 0644 "$candidate" "$VMWARE_NETWORKING_FILE" \
        && workstation_configure_networking \
        && sudo "$WORKSTATION_VMNET_CLI" --start; then
        for attempt in 1 2 3 4 5 6 7 8 9 10; do
            if ! workstation_vmnet_is_configured "$vmnet"; then
                removed=1
                break
            fi
            sleep 1
        done
    fi
    if [[ "$removed" -ne 1 ]]; then
        sudo "$WORKSTATION_VMNET_CLI" --stop || true
        if [[ -e "$network_backup" ]]; then
            sudo rm -rf -- "$network_dir"
            sudo mv -- "$network_backup" "$network_dir" \
                || die "could not restore $vmnet; backup retained at $network_backup"
        fi
        workstation_restore_networking "$backup" || true
        die "could not remove $vmnet; rollback was attempted and installer state was preserved"
    fi
    [[ ! -e "$network_backup" ]] || sudo rm -rf -- "$network_backup"
    rm -f -- "$backup" "$candidate"
    INSTALLER_CREATED_HITL_VMNET=""

}
