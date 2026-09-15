#!/usr/bin/env bash
# Linux-only module preflight and explicitly approved Secure Boot setup.
WORKSTATION_SECURE_BOOT_HELPER="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)/secure-boot.sh"

workstation_module_loaded() { [[ -d "/sys/module/$1" ]]; }

workstation_approve_module_signing() {
    local answer
    [[ -t 0 && -t 1 ]] || return 1
    printf 'Sign VMware modules and request certificate enrollment if needed? [y/N] '
    read -r answer || return 1
    [[ "$answer" == y || "$answer" == Y || "$answer" == yes || "$answer" == YES ]]
}

workstation_enrollment_instructions() {
    log "Reboot when ready. At the machine's console select Enroll MOK → Continue → Yes."
    log "Enter the temporary password you supplied to mokutil, then reboot again."
    log "Rerun the same installer command as your desktop user after enrollment."
}

workstation_secure_boot_enabled() {
    local output
    [[ -d /sys/firmware/efi ]] || return 1
    command -v mokutil >/dev/null 2>&1 || die "mokutil is required to inspect Secure Boot; install the mokutil package and rerun"
    output="$(LC_ALL=C mokutil --sb-state 2>&1)" || die "cannot inspect Secure Boot: $output"
    case "$output" in
        *"SecureBoot enabled"*) return 0 ;;
        *"SecureBoot disabled"*) return 1 ;;
        *) die "unexpected Secure Boot status: $output" ;;
    esac
}

ensure_vmware_kernel_modules() {
    local module output secure_boot=0 needs_signing=0 status=0
    workstation_module_loaded vmmon && workstation_module_loaded vmnet && return 0
    for module in vmmon vmnet; do
        modinfo -n "$module" >/dev/null 2>&1 \
            || die "VMware module $module is missing for $(uname -r). Build VMware's modules with vmware-modconfig --console --install-all, then rerun."
    done
    if workstation_secure_boot_enabled; then secure_boot=1; fi
    if [[ "$DRY_RUN" == 1 ]]; then
        log "DRY-RUN: VMware modules need loading; Secure Boot signing/enrollment may require explicit approval."
        die "dry run stopped before module loading; rerun without --dry-run to prepare VMware"
    fi
    for module in vmmon vmnet; do
        workstation_module_loaded "$module" && continue
        if [[ "$secure_boot" == 1 && -z "$(modinfo -F signer "$module")" ]]; then
            needs_signing=1
            continue
        fi
        if output="$(sudo modprobe "$module" 2>&1)"; then
            continue
        fi
        if [[ "$secure_boot" == 1 && "$output" =~ (Key\ was\ rejected|Required\ key\ not\ available) ]]; then
            needs_signing=1
        else
            die "cannot load VMware module $module: $output"
        fi
    done
    [[ "$needs_signing" == 1 ]] || return 0
    log "Secure Boot is enabled and VMware's modules need a trusted signature."
    log "With your approval, the installer will install matching kernel headers if needed,"
    log "create or reuse a root-protected key in /var/lib/scenarioforge-vmware-secure-boot,"
    log "back up and sign vmmon/vmnet, and request enrollment of that certificate if needed."
    log "Enrolling this certificate trusts modules signed with its private key."
    log "mokutil will ask for a temporary enrollment password. Console access and a reboot may be required."
    log "The installer will not reboot the host. --yes does not approve this step."
    workstation_approve_module_signing \
        || die "Secure Boot setup was not approved; no signing or enrollment was performed. Rerun interactively to approve it."
    sudo bash "$WORKSTATION_SECURE_BOOT_HELPER" --sign-approved || status=$?
    if [[ "$status" == 20 ]]; then
        workstation_enrollment_instructions
        die "Secure Boot enrollment pending; no lab networks or VMs have been provisioned"
    fi
    [[ "$status" == 0 ]] || die "VMware module signing/enrollment failed (exit $status); resolve the error above and rerun"
    for module in vmmon vmnet; do
        sudo modprobe "$module" || die "signed module $module could not load; inspect the kernel log before retrying"
    done
}

workstation_sign_modules_as_root() {
    # Called only by the root entry point after the desktop user's approval.
    # This directory is separate from lab state and is retained by lab cleanup.
    local key_dir=/var/lib/scenarioforge-vmware-secure-boot
    local kernel sign_tool module path fingerprint pending enrolled key_public cert_public
    local -a module_paths=()
    umask 077
    kernel="$(uname -r)"
    sign_tool="/lib/modules/$kernel/build/scripts/sign-file"
    if [[ ! -x "$sign_tool" ]]; then
        if command -v apt-get >/dev/null 2>&1; then
            apt-get install -y "linux-headers-$kernel" || return 1
        elif command -v dnf >/dev/null 2>&1; then
            dnf install -y "kernel-devel-$kernel" || return 1
        elif command -v yum >/dev/null 2>&1; then
            yum install -y "kernel-devel-$kernel" || return 1
        fi
        [[ -x "$sign_tool" ]] || { echo "Kernel signing tool missing: $sign_tool" >&2; return 1; }
    fi
    for module in vmmon vmnet; do
        path="$(modinfo -n "$module")" || return 1
        [[ "$path" == /*.ko && -f "$path" && ! -L "$path" ]] \
            || { echo "Expected an uncompressed VMware .ko module, got: $path" >&2; return 1; }
        module_paths+=("$path")
    done
    [[ ! -L "$key_dir" ]] || { echo "Refusing symlink at $key_dir" >&2; return 1; }
    if [[ ! -e "$key_dir" ]]; then
        install -d -o root -g root -m 0700 "$key_dir" || return 1
    fi
    [[ -d "$key_dir" && "$(stat -c %u:%a "$key_dir")" == 0:700 ]] \
        || { echo "Signing directory must be owned by root with mode 0700: $key_dir" >&2; return 1; }
    for path in "$key_dir/MOK.priv" "$key_dir/MOK.der"; do
        [[ ! -L "$path" ]] || { echo "Refusing symlink at $path" >&2; return 1; }
    done
    if [[ ! -e "$key_dir/MOK.priv" && ! -e "$key_dir/MOK.der" ]]; then
        openssl req -new -x509 -newkey rsa:3072 -nodes -days 3650 \
            -keyout "$key_dir/MOK.priv" -outform DER -out "$key_dir/MOK.der" \
            -subj '/CN=ScenarioForge VMware modules/' || return 1
    fi
    [[ -f "$key_dir/MOK.priv" && -f "$key_dir/MOK.der" ]] \
        || { echo "Incomplete signing key pair in $key_dir; preserve and repair it before retrying" >&2; return 1; }
    key_public="$(openssl pkey -in "$key_dir/MOK.priv" -pubout)" || return 1
    cert_public="$(openssl x509 -inform DER -in "$key_dir/MOK.der" -pubkey -noout)" || return 1
    [[ "$key_public" == "$cert_public" ]] || { echo "Signing key does not match certificate" >&2; return 1; }
    openssl x509 -inform DER -in "$key_dir/MOK.der" -checkend 0 -noout || return 1
    for path in "${module_paths[@]}"; do
        # Retain the original module from each kernel before signing.
        [[ -e "$key_dir/$kernel-${path##*/}.before-signing" ]] \
            || cp -p -- "$path" "$key_dir/$kernel-${path##*/}.before-signing" || return 1
        "$sign_tool" sha256 "$key_dir/MOK.priv" "$key_dir/MOK.der" "$path" || return 1
    done
    # --test-key exit codes differ across mokutil releases. Check the actual
    # enrolled certificate inventory, never infer trust from exit status alone.
    fingerprint="$(openssl x509 -inform DER -in "$key_dir/MOK.der" -fingerprint -sha1 -noout)" || return 1
    fingerprint="${fingerprint#*=}"
    [[ "$fingerprint" =~ ^([[:xdigit:]]{2}:){19}[[:xdigit:]]{2}$ ]] \
        || { echo "Could not read signing certificate fingerprint" >&2; return 1; }
    enrolled="$(LC_ALL=C mokutil --list-enrolled)" || return 1
    if grep -Fiq -- "$fingerprint" <<<"$enrolled"; then return 0; fi
    # Avoid asking for another password when this exact certificate is pending.
    pending="$(LC_ALL=C mokutil --list-new)" || return 1
    if ! grep -Fiq -- "$fingerprint" <<<"$pending"; then
        echo "Choose a temporary password for approval at the MOK Manager console."
        mokutil --import "$key_dir/MOK.der" || return 1
        pending="$(LC_ALL=C mokutil --list-new)" || return 1
        grep -Fiq -- "$fingerprint" <<<"$pending" \
            || { echo "Certificate enrollment request was not found after import; inspect mokutil --list-new" >&2; return 1; }
    fi
    return 20
}

if [[ "${BASH_SOURCE[0]}" == "$0" ]]; then
    set -Eeuo pipefail
    [[ "$EUID" == 0 && "${1:-}" == --sign-approved && "$#" == 1 ]] \
        || { echo "Run Secure Boot setup through the Linux installer approval prompt." >&2; exit 1; }
    export PATH=/usr/sbin:/usr/bin:/sbin:/bin
    workstation_sign_modules_as_root
fi
