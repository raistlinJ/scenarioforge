# Shared per-VM rebuild workflow. Missing images require separate download consent.
REINSTALL_COMMON_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
REINSTALL_TARGET=""

reinstall_selects() { [[ -z "$REINSTALL_TARGET" || "$REINSTALL_TARGET" == all || "$REINSTALL_TARGET" == "$1" ]]; }

remember_verified_image() {
    [[ "$DRY_RUN" != 1 ]] || return 0
    python3 "$REINSTALL_COMMON_DIR/image_cache.py" remember "$@"
}

reinstall_force_download_requested() {
    [[ -n "$REINSTALL_TARGET" && "$FORCE_CLEANUP" == 1 ]]
}

prepare_forced_reinstall_download() {
    local destination="$1" url="$2"
    [[ ! -L "$destination" && ( ! -e "$destination" || -f "$destination" ) ]] \
        || die "Refusing to replace a non-regular cache entry: $destination"
    if [[ "$DRY_RUN" == 1 ]]; then
        emit DRY-RUN "force download and verify $url -> $destination; existing cache retained until verification succeeds"
    else
        log "Force refresh: downloading and verifying $url; existing cache retained until verification succeeds"
    fi
}

confirm_reinstall_image_download() {
    local destination="$1" url="$2" response
    [[ "$DRY_RUN" != 1 ]] || die "Dry run: required cached image is missing: $destination. Run without --dry-run to choose whether to download it; no VMs were changed."
    log "Required cached image is missing: $destination"
    log "Download source: $url (the base image may be several GB)"
    read -r -p 'Download and verify this image before reinstalling? [y/N] ' response || response=""
    case "$response" in
        y|Y|yes|YES|Yes) ;;
        *) die 'Image download declined; no VMs were replaced' ;;
    esac
}

validate_reinstall_target() {
    [[ -z "$REINSTALL_TARGET" || "$COMMAND" == reinstall ]] || die '--reinstall cannot be combined with another command'
    [[ "$COMMAND" != reinstall ]] || case "$REINSTALL_TARGET" in
        core|app|participant|all) ;;
        *) die '--reinstall requires core, app, participant, or all' ;;
    esac
}

save_reinstall_settings() {
    local variable
    for variable in IMAGE_CACHE CORE_MEMORY_MB CORE_CORES CORE_DISK_GB APP_MEMORY_MB APP_CORES APP_DISK_GB \
        PARTICIPANT_MEMORY_MB PARTICIPANT_CORES PARTICIPANT_DISK_GB CORE_MINIMAL_REF CORE_REPO_REF \
        SCENARIOFORGE_REF CORE_MINIMAL_URL CORE_REPO_URL SCENARIOFORGE_URL \
        DEBIAN_IMAGE_URL DEBIAN_SUMS_URL UBUNTU_IMAGE_URL UBUNTU_SUMS_URL KALI_IMAGE_URL KALI_SUMS_URL \
        SSH_PUBLIC_KEY_FILE; do
        if declare -p "$variable" >/dev/null 2>&1; then shell_assignment "$variable" "${!variable}"; fi
    done
}

reinstall_cached_images() {
    if [[ "${VMRUN_TYPE:-}" ]]; then
        DEBIAN_IMAGE="$IMAGE_CACHE/$DEBIAN_IMAGE_CACHE_NAME"
        UBUNTU_IMAGE="$IMAGE_CACHE/$UBUNTU_IMAGE_CACHE_NAME"
    else
        DEBIAN_IMAGE="$IMAGE_CACHE/debian-12-genericcloud-amd64.qcow2"
        UBUNTU_IMAGE="$IMAGE_CACHE/noble-server-cloudimg-amd64.img"
    fi
    if reinstall_selects core || { reinstall_selects participant && [[ "$PARTICIPANT_OS" == debian ]]; }; then
        download_verified_image "$DEBIAN_IMAGE_URL" "$DEBIAN_SUMS_URL" sha512 "$DEBIAN_IMAGE"
    fi
    if reinstall_selects app; then
        download_verified_image "$UBUNTU_IMAGE_URL" "$UBUNTU_SUMS_URL" sha256 "$UBUNTU_IMAGE"
    fi
    PARTICIPANT_IMAGE="$DEBIAN_IMAGE"
    if reinstall_selects participant && [[ "$PARTICIPANT_OS" == kali ]]; then
        prepare_participant_image
    fi
}

reinstall_wait_for_guest() {
    local role="$1" prefix target user password phase deadline started percent activity last_activity=''
    started="$(date +%s)"
    prefix="$(printf '%s' "$role" | tr '[:lower:]' '[:upper:]')"
    deadline=$(( started + WAIT_MINUTES * 60 ))
    if [[ "${VMRUN_TYPE:-}" ]]; then
        target="${prefix}_VMX"; target="${!target}"
        password="${prefix}_PASSWORD"; password="${!password}"
        case "$role" in core) user=corevm ;; app) user=scenarioforge ;; participant) user=participant ;; esac
    else
        target="${prefix}_VMID"; target="${!target}"
    fi
    while :; do
        if [[ "${VMRUN_TYPE:-}" ]]; then
            if guest_file_exists "$target" "$user" "$password" "/var/lib/scenarioforge/$role-ready"; then
                log "$role reinstall: ready after $(format_elapsed "$started")"
                return
            fi
            phase="$(guest_phase "$target" "$user" "$password")"
            percent="$(guest_file_text "$target" "$user" "$password" /var/lib/scenarioforge/bootstrap-percent || true)"
        else
            if guest_marker_exists "$target" "/var/lib/scenarioforge/$role-ready"; then
                log "$role reinstall: ready after $(format_elapsed "$started")"
                return
            fi
            phase="$(guest_bootstrap_failure_text "$target")"
            [[ -z "$phase" ]] || die "$role reinstall failed: $phase; VM retained for diagnosis"
            phase="$(guest_command_output "$target" cat /var/lib/scenarioforge/bootstrap-status)"
            percent="$(guest_command_output "$target" cat /var/lib/scenarioforge/bootstrap-percent)"
        fi
        [[ "$phase" != failed* ]] || die "$role reinstall failed: $phase; VM retained for diagnosis"
        if [[ "$percent" =~ ^[0-9]{1,3}$ ]] && (( 10#$percent <= 100 )); then
            percent="[$((10#$percent))%] "
        else
            percent=''
        fi
        log "$role reinstall: ${percent}${phase:-waiting for guest agent / Cloud-Init} (elapsed $(format_elapsed "$started"))"
        if [[ "${VMRUN_TYPE:-}" ]]; then
            report_vmware_guest_activity "$role" "$target" "$user" "$password"
        else
            activity="$(guest_last_log_line "$target" "/var/log/scenarioforge-$role-bootstrap.log")"
            [[ -n "$activity" ]] || activity="$(guest_last_log_line "$target" /var/log/cloud-init-output.log)"
            if [[ -n "$activity" && "$activity" != "$last_activity" ]]; then
                log "$role guest: $activity"
                last_activity="$activity"
            fi
        fi
        (( $(date +%s) < deadline )) || die "$role reinstall timed out; VM and any temporary participant NAT were retained for diagnosis"
        sleep 15
    done
}

reinstall_vmware_running() {
    local target="$1" output header
    output="$(timeout 30 "${FUSION_VMRUN:-vmrun}" -T "$VMRUN_TYPE" list)" \
        || die 'Could not read VMware power status; reinstall aborted before disk replacement'
    header="${output%%$'\n'*}"
    [[ "$header" =~ ^Total\ running\ VMs:[[:space:]]*[0-9]+$ ]] \
        || die 'Invalid VMware power status; reinstall aborted before disk replacement'
    tail -n +2 <<<"$output" | grep -Fxq -- "$target"
}

perform_reinstall() {
    local role prefix target directory name variable response settings old_complete deadline
    local -a selected_roles=()
    if [[ "${VMRUN_TYPE:-}" ]]; then
        load_state
        require_linux_workstation
    else
        [[ -f "$STATE_FILE" ]] || die 'Reinstall requires saved installer state'
        load_cleanup_scope
        [[ -f "$CREDENTIALS_FILE" && ! -L "$CREDENTIALS_FILE" && -O "$CREDENTIALS_FILE" ]] || die 'Missing safe saved credentials'
        [[ "$(python3 -c 'import os,sys; print(os.stat(sys.argv[1]).st_mode & 0o077)' "$CREDENTIALS_FILE")" == 0 ]] || die 'Credentials must have mode 0600'
        source "$CREDENTIALS_FILE"
        CORE_PASSWORD="$CORE_VM_PASSWORD"; APP_PASSWORD="$APP_VM_PASSWORD"; PARTICIPANT_PASSWORD="$PARTICIPANT_VM_PASSWORD"
        settings="$(storage_config "$SNIPPET_STORAGE")"
        SNIPPET_DIR="$(storage_field "$settings" path)/snippets"
        [[ "$SNIPPET_DIR" != /snippets && -d "$SNIPPET_DIR" ]] || die 'Saved snippet storage is unavailable'
    fi
    for variable in CORE_PASSWORD APP_PASSWORD PARTICIPANT_PASSWORD SCENARIOFORGE_ADMIN_PASSWORD; do
        [[ -n "${!variable}" ]] || die "Reinstall requires saved credentials: $variable"
    done
    old_complete="${INSTALL_COMPLETE:-0}"
    WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/scenarioforge-reinstall.XXXXXX")"
    trap 'rm -rf -- "$WORK_DIR"' EXIT
    for prefix in CORE APP PARTICIPANT; do
        for variable in NET0_MAC NET1_MAC NET2_MAC; do
            # Unselected Cloud-Init documents are generated but never installed.
            name="${prefix}_$variable"
            if ! declare -p "$name" >/dev/null 2>&1 || [[ -z "${!name}" ]]; then
                printf -v "$name" '%s' '02:00:00:00:00:01'
            fi
        done
    done
    for role in core app participant; do
        reinstall_selects "$role" || continue
        selected_roles+=("$role")
        prefix="$(printf '%s' "$role" | tr '[:lower:]' '[:upper:]')"
        name="${prefix}_NAME"; name="${!name}"
        if [[ "${VMRUN_TYPE:-}" ]]; then
            target="${prefix}_VMX"; target="${!target}"
            directory="${target%/*}"
            safe_vm_dir "$directory" "$name$VM_BUNDLE_SUFFIX" && vmx_owned "$target" \
                || die "Refusing reinstall of unowned VM: $target"
            # Refuse links anywhere in a selected directory before recursive removal.
            python3 - "$directory" <<'PY'
import os, sys
for root, dirs, files in os.walk(sys.argv[1], followlinks=False):
    if any(os.path.islink(os.path.join(root, name)) for name in dirs + files):
        raise SystemExit('Refusing reinstall of VM directory containing symbolic links')
PY
            settings="$(python3 "$REINSTALL_COMMON_DIR/reinstall_inventory.py" vmware "$role" "$target")" || die "Cannot read hardware for $role"
        else
            target="${prefix}_VMID"; target="${!target}"
            vm_owned_by_installer "$target" "$name" "scenarioforge-$role-user.yaml" || die "Refusing reinstall of unowned VMID $target"
            qm config "$target" > "$WORK_DIR/$role.config"
            settings="$(python3 "$REINSTALL_COMMON_DIR/reinstall_inventory.py" proxmox "$role" "$WORK_DIR/$role.config")" || die "Cannot read hardware for $role"
        fi
        eval "$settings" # Helper emits only fixed variable names and quoted scalar values.
        variable="${prefix}_DISK_GB"
        name="REINSTALL_$variable"
        if declare -p "$name" >/dev/null 2>&1; then
            printf -v "$variable" '%s' "${!name}"
        else
            name="SF_$variable"
            if declare -p "$name" >/dev/null 2>&1; then
                printf -v "$variable" '%s' "${!name}"
            fi
        fi
        validate_integer "$role disk size" "${!variable}" 8
        if [[ "$role" == participant && "$PARTICIPANT_OS" == kali ]]; then
            validate_integer 'Kali participant disk size' "${!variable}" 25
        fi
        log "Reinstall scope: $role ($target); its guest disk and data will be replaced"
        log "Reinstall $role disk size: ${!variable} GB"
    done
    validate_integer 'wait minutes' "$WAIT_MINUTES" 1
    reinstall_cached_images
    if [[ "$DRY_RUN" == 1 ]]; then
        log 'Reinstall preview complete; no VMs or networks changed'
        return
    fi
    if [[ "$ASSUME_YES" != 1 ]]; then
        read -r -p 'Type REINSTALL to erase and recreate the selected VMs: ' response
        [[ "$response" == REINSTALL ]] || die 'Reinstall canceled'
    fi
    if reinstall_selects app; then prepare_optional_content; fi
    if [[ "${VMRUN_TYPE:-}" ]]; then
        write_vmware_cloud_init_files
    else
        write_guest_bootstraps
        if [[ "$CYBER_AGENT_FLOW" == 1 ]]; then caf_generate inject "$WORK_DIR/participant-bootstrap.sh"; fi
        write_cloud_init_files
        if [[ "$CYBER_AGENT_FLOW" == 1 ]]; then caf_generate network "$PARTICIPANT_NET2_MAC" >> "$WORK_DIR/participant-network.yaml"; fi
    fi
    # All selected VMs, credentials, cached images and provisioning inputs have
    # passed preflight before the first guest is stopped or removed.
    for role in "${selected_roles[@]}"; do
        prefix="$(printf '%s' "$role" | tr '[:lower:]' '[:upper:]')"
        if [[ "${VMRUN_TYPE:-}" ]]; then
            target="${prefix}_VMX"; target="${!target}"
            if reinstall_vmware_running "$target"; then
                log "Requesting a graceful shutdown of $role (timeout: 120 seconds)"
                deadline=$(( $(date +%s) + 120 ))
                if timeout 120 "${FUSION_VMRUN:-vmrun}" -T "$VMRUN_TYPE" stop "$target" soft; then
                    while reinstall_vmware_running "$target"; do
                        (( $(date +%s) < deadline )) || break
                        sleep 2
                    done
                else
                    warn "$role did not shut down gracefully"
                fi
                if reinstall_vmware_running "$target"; then
                    vmx_owned "$target" || die "VM ownership changed: $target"
                    warn "Forcing $role to stop for the confirmed reinstall"
                    timeout 120 "${FUSION_VMRUN:-vmrun}" -T "$VMRUN_TYPE" stop "$target" hard \
                        || die "Could not stop VM: $target; reinstall aborted before disk replacement"
                fi
                if reinstall_vmware_running "$target"; then
                    die "VM is still running: $target; reinstall aborted before disk replacement"
                fi
            fi
        else
            target="${prefix}_VMID"; target="${!target}"
            if qm status "$target" | grep -q 'status: running'; then
                log "Requesting a graceful shutdown of $role VMID $target (timeout: 120 seconds)"
                if ! qm shutdown "$target" --timeout 120; then
                    warn "$role VMID $target did not shut down gracefully"
                fi
                if qm status "$target" | grep -q 'status: running'; then
                    # REINSTALL already authorizes replacing this guest's disk.
                    # Recheck ownership before forcibly stopping a stuck guest.
                    name="${prefix}_NAME"; name="${!name}"
                    vm_owned_by_installer "$target" "$name" "scenarioforge-$role-user.yaml" \
                        || die "VM ownership changed: $target"
                    warn "Forcing $role VMID $target to stop for the confirmed reinstall"
                    qm stop "$target" || die "Could not stop VMID $target; reinstall aborted before disk replacement"
                fi
            fi
            qm status "$target" | grep -q 'status: stopped' || die "VMID $target is not stopped"
        fi
    done
    INSTALL_COMPLETE=0
    INSTALL_STARTED_EPOCH="$(date +%s)"
    INSTALL_PERCENT=40
    INSTALL_PHASE="Reinstalling $REINSTALL_TARGET"
    if reinstall_selects participant; then PARTICIPANT_BOOTSTRAP_UPLINK_ATTACHED=1; fi
    write_state
    for role in "${selected_roles[@]}"; do
        prefix="$(printf '%s' "$role" | tr '[:lower:]' '[:upper:]')"
        if [[ "${VMRUN_TYPE:-}" ]]; then
            target="${prefix}_VMX"; target="${!target}"
            vmx_owned "$target" || die "VM ownership changed: $target"
            rm -rf -- "${target%/*}"
        else
            target="${prefix}_VMID"; target="${!target}"
            name="${prefix}_NAME"; name="${!name}"
            vm_owned_by_installer "$target" "$name" "scenarioforge-$role-user.yaml" || die "VM ownership changed: $target"
            qm destroy "$target" --purge 1
        fi
    done
    if [[ -z "${VMRUN_TYPE:-}" ]]; then install_snippets; fi
    create_vms
    for role in "${selected_roles[@]}"; do
        prefix="$(printf '%s' "$role" | tr '[:lower:]' '[:upper:]')"
        if [[ "${VMRUN_TYPE:-}" ]]; then
            target="${prefix}_VMX"; start_vm "${!target}"
        else
            target="${prefix}_VMID"; qm start "${!target}"
        fi
    done
    if reinstall_selects app; then transfer_optional_content_to_app; fi
    for role in "${selected_roles[@]}"; do
        reinstall_wait_for_guest "$role"
        if [[ "$role" == participant ]]; then
            if [[ "${VMRUN_TYPE:-}" ]]; then detach_participant_uplink; else detach_participant_bootstrap_uplink; fi
        fi
    done
    INSTALL_COMPLETE="$old_complete"
    [[ "$REINSTALL_TARGET" != all ]] || INSTALL_COMPLETE=1
    INSTALL_PERCENT=100
    INSTALL_PHASE="Reinstall complete: $REINSTALL_TARGET"
    write_state
    log "Reinstall complete: $REINSTALL_TARGET; saved credentials and host networks retained"
}
