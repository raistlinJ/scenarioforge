import threading

from core.services.base import CoreService, ShadowDir, ServiceMode


_CORETG_MAKO_TEMPLATE_LOCK = threading.RLock()


def _install_threadsafe_mako_template_lookup() -> None:
    """Serialize Mako template compilation on affected Python 3.11 runtimes.

    CORE boots nodes concurrently. Older Python 3.11 patch releases can raise a
    spurious AST recursion-depth SystemError when Mako compiles templates in
    parallel. Custom service modules load when core-daemon starts, before node
    services render templates, making this a process-wide compatibility hook.
    """
    try:
        from mako.lookup import TemplateLookup
    except Exception:
        return

    if getattr(TemplateLookup, "_coretg_threadsafe_get_template", False):
        return

    original_get_template = TemplateLookup.get_template

    def _locked_get_template(self, uri):
        with _CORETG_MAKO_TEMPLATE_LOCK:
            return original_get_template(self, uri)

    TemplateLookup.get_template = _locked_get_template
    TemplateLookup._coretg_threadsafe_get_template = True


_install_threadsafe_mako_template_lookup()


class CoreTGPrereqsService(CoreService):
    """Best-effort dependency installer for ScenarioForge services.

    Ensures common tools exist inside the node namespace/container so that other
    custom services (Segmentation, Traffic) can run their generated scripts.

    Notes:
    - This is best-effort and logs to prereqs_output.txt.
    - Package installation requires root inside the node.
    - For Docker-based nodes, iptables availability/capabilities may depend on
      how the container is launched (e.g., CAP_NET_ADMIN/privileged).
    """

    name: str = "CoreTGPrereqs"
    group: str = "Simple"
    files: list[str] = ["/runprereqs.sh"]
    executables: list[str] = []
    dependencies: list[str] = []
    # Resolve on both node kinds: a Docker node gets the file at the container
    # root, while a namespaced vnode only has it in its `.conf` directory (the
    # startup working directory). Traffic and Segmentation both depend on this
    # service, so an absolute-only path meant their prerequisite never ran on
    # vnodes. See TrafficService for the full explanation.
    startup: list[str] = [
        "/bin/sh -c 'f=runprereqs.sh; [ -f \"$f\" ] || f=/runprereqs.sh; exec sh \"$f\"'"
    ]
    validate: list[str] = []
    shutdown: list[str] = []
    validation_mode: ServiceMode = ServiceMode.NON_BLOCKING

    shadow_directories: list[ShadowDir] = []

    def get_text_template(self, name: str) -> str:  # type: ignore[override]
        # Only the node constants below are templated by Mako; the script body
        # lives in a <%text> block so it is plain shell. Without that, ordinary
        # syntax breaks: `${VAR:-default}` raises, a line starting with `%` is a
        # Mako control line, and a line starting with `##` is silently dropped.
        return r"""#!/bin/sh
NODE_ID='${node.id}'
NODE_NAME='${node.name}'
<%text>
set -eu

LOG="/tmp/coretg_prereqs_output.txt"

log() {
  echo "[CoreTGPrereqs] $*" >> "$LOG"
}

have() {
  command -v "$1" >/dev/null 2>&1
}

as_root() {
  # Best-effort check: many CORE nodes run as root.
  if have id; then
    [ "$(id -u)" = "0" ]
    return
  fi
  # If id is missing, assume non-root.
  return 1
}

install_pkgs_apt() {
  # shellcheck disable=SC2039
  pkgs="$*"
  log "apt-get installing: $pkgs"
  DEBIAN_FRONTEND=noninteractive apt-get update >>"$LOG" 2>&1 || true
  DEBIAN_FRONTEND=noninteractive apt-get install -y $pkgs >>"$LOG" 2>&1 || true
}

install_pkgs_apk() {
  pkgs="$*"
  log "apk installing: $pkgs"
  apk add --no-cache $pkgs >>"$LOG" 2>&1 || true
}

install_pkgs_yum() {
  pkgs="$*"
  log "yum installing: $pkgs"
  yum install -y $pkgs >>"$LOG" 2>&1 || true
}

maybe_install() {
  if ! as_root; then
    log "not root; cannot install packages"
    return 0
  fi

  if have apt-get; then
    install_pkgs_apt "$@"
    return 0
  fi
  if have apk; then
    install_pkgs_apk "$@"
    return 0
  fi
  if have yum; then
    install_pkgs_yum "$@"
    return 0
  fi

  log "no supported package manager found (apt-get/apk/yum)"
  return 0
}

log "node id($NODE_ID) name($NODE_NAME) starting prereq check"

# Ensure /bin/bash exists because other ScenarioForge CORE services use it.
if [ ! -x /bin/bash ]; then
  log "/bin/bash missing; attempting to install bash"
  maybe_install bash
fi

# Ensure python3 for generated Traffic and Segmentation scripts.
if ! have python3; then
  log "python3 missing; attempting to install python3"
  maybe_install python3
fi

# Ensure iptables + iproute tooling for segmentation scripts.
if ! have iptables; then
  log "iptables missing; attempting to install iptables"
  maybe_install iptables
fi

if ! have ip; then
  log "ip (iproute2) missing; attempting to install iproute2/iproute"
  # distro package names differ
  maybe_install iproute2 iproute
fi

# Some images ship nftables instead of iptables; log it for debugging.
if have nft; then
  log "nft present"
fi

log "done"
</%text>
"""
