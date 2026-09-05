#!/usr/bin/env python3
"""Installed host launcher for the VMware lab; no guest credentials are needed."""
import argparse
import hashlib
import ipaddress
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import time


class LaunchError(Exception):
    pass


def command(args, timeout=30):
    try:
        return subprocess.run(args, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise LaunchError(f"Could not run {args[0]}: {exc}") from exc


def dialog(message, platform, question=False):
    """Only an explicit affirmative response permits starting VMs."""
    print(message, flush=True)
    try:
        if platform == "fusion":
            buttons = '{"Cancel", "Start VMs"} default button "Start VMs" cancel button "Cancel"' if question else '{"OK"} default button "OK"'
            script = ('on run argv\nactivate\ndisplay dialog (item 1 of argv) with title "ScenarioForge" '
                      f'buttons {buttons}\nend run')
            # Pass text as data, never as AppleScript source.
            result = command(["osascript", "-e", script, message], timeout=None)
            if result.returncode == 0:
                return True
            if "(-128)" in result.stderr:  # User canceled the native dialog.
                return False
        elif shutil.which("zenity"):
            args = ["zenity", "--question" if question else "--error", "--no-markup", "--title=ScenarioForge", f"--text={message}"]
            if question:
                args += ["--ok-label=Start VMs", "--cancel-label=Cancel"]
            result = command(args, timeout=None)
            if result.returncode in (0, 1):
                return result.returncode == 0
    except LaunchError as exc:
        print(str(exc), file=sys.stderr)
    # Both desktop formats open a terminal, so minimal Linux desktops can still
    # ask for confirmation without adding a GUI package dependency.
    if sys.stdin.isatty():
        try:
            if question:
                return input("Start these VMs? [y/N] ").strip().lower() in ("y", "yes")
            input("Press Enter to close. ")
        except (EOFError, KeyboardInterrupt):
            pass
    return False


def running_vms(options):
    result = command([options.vmrun, "-T", options.platform, "list"])
    lines = result.stdout.splitlines()
    if result.returncode or not lines or not lines[0].startswith("Total running VMs:"):
        raise LaunchError("Could not check VMware power status. Open VMware and try again.\n" + result.stderr.strip())
    return {os.path.realpath(line.strip()) for line in lines[1:] if line.strip()}


def start_vm(options, label, path, timeout=120):
    """Power state is authoritative even if the vmrun client does not exit."""
    print(f"Starting {label}…", flush=True)
    deadline = time.monotonic() + timeout
    # A child VMware process can outlive vmrun. A file avoids waiting for that
    # child's inherited stdout/stderr pipe to close before we can make progress.
    with tempfile.TemporaryFile(mode="w+b") as output:
        try:
            process = subprocess.Popen(
                [options.vmrun, "-T", options.platform, "start", path, "gui"],
                stdout=output, stderr=subprocess.STDOUT,
            )
        except OSError as exc:
            raise LaunchError(f"Could not start {label}: {exc}") from exc
        last_status_error = ""
        try:
            while True:
                returncode = process.poll()
                try:
                    if os.path.realpath(path) in running_vms(options):
                        print(f"{label} is running.", flush=True)
                        return
                    last_status_error = ""
                except LaunchError as exc:
                    last_status_error = str(exc)
                if returncode not in (None, 0):
                    output.seek(0)
                    detail = output.read().decode(errors="replace").strip()
                    raise LaunchError(f"Could not start {label}.\n{detail}\nVMs already started have been left running.")
                if time.monotonic() >= deadline:
                    product = "VMware Fusion" if options.platform == "fusion" else "VMware Workstation"
                    message = (f"Could not confirm that {label} started within {timeout} seconds. "
                               f"Open {product} and check the VM window for a pending question or startup error, "
                               "then try the shortcut again. VMs already started have been left running.")
                    if last_status_error:
                        message += "\n" + last_status_error
                    raise LaunchError(message)
                time.sleep(2)
        finally:
            # Reap only this vmrun client, never the VM or its process group.
            # A hung automation client must not block other approved VM starts.
            if process.poll() is None:
                process.terminate()
                try:
                    process.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=5)


def ensure_running(options):
    required = [("CORE VM", options.core)]
    required.append(("APP VM", options.app) if options.mode == "browser" else ("Participant VM", options.participant))
    for label, path in required:
        if not Path(path).is_file():
            raise LaunchError(f"{label} was not found at {path}. Run the installer status command to refresh the shortcuts.")
    running = running_vms(options)
    stopped = [(label, path) for label, path in required if os.path.realpath(path) not in running]
    if stopped:
        message = "The following VMs are not running:\n\n" + "\n".join(f"• {label} ({Path(path).stem})" for label, path in stopped)
        message += "\n\nStart them and continue?"
        if not dialog(message, options.platform, question=True):
            return False
        for label, path in stopped:
            if os.path.realpath(path) in running_vms(options):
                continue
            start_vm(options, label, path)
        deadline = time.monotonic() + 60
        while True:
            running = running_vms(options)
            if all(os.path.realpath(path) in running for _, path in required):
                break
            if time.monotonic() >= deadline:
                raise LaunchError("VMware did not confirm that all required VMs started. Check their power state in VMware and try again.")
            time.sleep(2)
    if options.platform == "fusion":
        # Attach VMs that were previously started headlessly too. Otherwise
        # Fusion can show stale power state and vmrun can miss running Tools.
        result = command(["open", "-g", "-a", options.fusion_app, *[path for _, path in required]])
        if result.returncode:
            raise LaunchError("Could not connect the running VMs to VMware Fusion.\n" + result.stderr.strip())
    return True


def app_url(options):
    print("Waiting for the APP VM's network address…", flush=True)
    deadline = time.monotonic() + 120
    while True:
        result = command([options.vmrun, "-T", options.platform, "getGuestIPAddress", options.app], timeout=20)
        if result.returncode == 0:
            try:
                address = ipaddress.ip_address(result.stdout.strip())
                if not (address.is_unspecified or address.is_loopback):
                    host = f"[{address}]" if address.version == 6 else str(address)
                    return f"https://{host}/"
            except ValueError:
                pass
        if time.monotonic() >= deadline:
            raise LaunchError("The APP VM is running, but its network address is not ready. Wait for it to finish booting, then click the shortcut again.")
        time.sleep(3)


def launch(options):
    try:
        if not ensure_running(options):
            return 0
        if options.mode == "browser":
            url = app_url(options)
            result = command(["open" if options.platform == "fusion" else "xdg-open", url])
        elif options.platform == "fusion":
            result = command(["open", "-a", options.fusion_app, options.participant])
        else:
            try:
                subprocess.Popen([options.vmware, options.participant], start_new_session=True,
                                 stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            except OSError as exc:
                raise LaunchError(f"Could not open VMware Workstation: {exc}") from exc
            return 0
        if result.returncode:
            raise LaunchError("Could not open the requested application.\n" + (result.stderr.strip() or result.stdout.strip()))
        return 0
    except LaunchError as exc:
        dialog(str(exc), options.platform)
        return 1


def write_shortcut(options):
    args = [sys.executable, options.launcher, "--mode", options.mode, "--platform", options.platform,
            "--vmrun", options.vmrun, "--vmware", options.vmware, "--fusion-app", options.fusion_app,
            "--core", options.core, "--app", options.app, "--participant", options.participant]
    if options.platform == "fusion":
        content = "#!/bin/sh\n# Check the lab VMs before opening ScenarioForge.\nexec " + " ".join(shlex.quote(arg) for arg in args) + "\n"
    else:
        def desktop_quote(value):
            # https://specifications.freedesktop.org/desktop-entry/latest/exec-variables.html
            value = ''.join('\\' + ch if ch in '\\"`$' else ch for ch in value)
            value = value.replace('\\', '\\\\').replace('%', '%%')
            value = value.replace('\n', '\\n').replace('\r', '\\r').replace('\t', '\\t')
            return f'"{value}"'
        title = "ScenarioForge" if options.mode == "browser" else "ScenarioForge Participant VM"
        content = (f"[Desktop Entry]\nType=Application\nName={title}\n"
                   "Comment=Check required lab VMs and open ScenarioForge\n"
                   "Exec=" + " ".join(desktop_quote(arg) for arg in args) + "\n"
                   "Icon=computer\nTerminal=true\n")
    path = Path(options.write_shortcut)
    path.parent.mkdir(parents=True, exist_ok=True)
    encoded = content.encode()
    if not path.exists() or path.read_bytes() != encoded:
        path.write_bytes(encoded)
    path.chmod(0o755)
    print(hashlib.sha256(encoded).hexdigest())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("browser", "participant"), required=True)
    parser.add_argument("--platform", choices=("ws", "fusion"), required=True)
    parser.add_argument("--vmrun", default="vmrun")
    parser.add_argument("--vmware", default="vmware")
    parser.add_argument("--fusion-app", default="/Applications/VMware Fusion.app")
    for name in ("core", "app", "participant"):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--write-shortcut")
    parser.add_argument("--launcher")
    options = parser.parse_args()
    if options.write_shortcut:
        if not options.launcher:
            parser.error("--write-shortcut requires --launcher")
        write_shortcut(options)
        return 0
    return launch(options)


if __name__ == "__main__":
    sys.exit(main())
