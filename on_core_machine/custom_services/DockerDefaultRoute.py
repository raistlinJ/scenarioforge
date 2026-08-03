from core.services.base import CoreService, ShadowDir, ServiceMode


class DockerDefaultRouteService(CoreService):
    """Docker-safe default route service using absolute script paths.

    This avoids CORE built-in DefaultRoute relative-path behavior (defaultroute.sh)
    that can fail when Docker container working directories vary.
    """

    name: str = "DockerDefaultRoute"
    group: str = "Simple"
    files: list[str] = ["/defaultroute.sh"]
    executables: list[str] = []
    dependencies: list[str] = ["CoreTGPrereqs"]
    # Docker-oriented, but kept consistent with the other services so the same
    # startup works if it is ever applied to a namespaced vnode, whose service
    # files live in the node's `.conf` directory rather than at the root.
    startup: list[str] = [
        "/bin/sh -c 'f=defaultroute.sh; [ -f \"$f\" ] || f=/defaultroute.sh; exec sh \"$f\"'"
    ]
    # Route setup is best-effort. CORE starts node services concurrently, so the
    # attached interface or peer route may not be ready during service validation.
    validate: list[str] = []
    shutdown: list[str] = []
    validation_mode: ServiceMode = ServiceMode.NON_BLOCKING
    shadow_directories: list[ShadowDir] = []

    def get_text_template(self, name: str) -> str:  # type: ignore[override]
        # CORE renders service files through Mako, which would otherwise eat
        # ordinary shell syntax: `${VAR:-default}` raises, a line starting with
        # `%` is a control line, and a line starting with `##` is silently
        # deleted. The `<%text>` block makes the body verbatim, so this is plain
        # shell with no templating rules to remember.
        return r"""<%text>
#!/bin/sh

LOG=/tmp/coretg_docker_defaultroute.log

log() {
  echo "[DockerDefaultRoute] $*" >> "$LOG"
}

# Resolve an `ip` implementation. Wrapper images ship a BusyBox at a fixed path,
# and the host-side preflight repair drops one at /busybox, so `ip` can exist
# even in images with no iproute2 and no working package manager.
IPCMD=""
if command -v ip >/dev/null 2>&1; then
  IPCMD="ip"
elif [ -x /usr/local/coretg/bin/busybox ] && /usr/local/coretg/bin/busybox ip link show >/dev/null 2>&1; then
  IPCMD="/usr/local/coretg/bin/busybox ip"
elif [ -x /busybox ] && /busybox ip link show >/dev/null 2>&1; then
  IPCMD="/busybox ip"
fi

if [ -z "$IPCMD" ]; then
  log "no usable ip command; cannot set default route"
  exit 0
fi

# CORE starts node services concurrently with interface configuration, so the
# address is frequently not assigned yet on the first pass. Exiting here (the
# old behavior) left the node with a connected route but no default gateway,
# permanently, because nothing ever re-ran this script.
wait_s="${CORETG_DEFAULT_ROUTE_WAIT_S:-45}"
case "$wait_s" in
  ''|*[!0-9]*) wait_s=45 ;;
esac

iface=""
cidr=""

# Parse `ip -4 -o addr show scope global` without awk/cut/head: minimal images
# that needed the busybox repair may not have coreutils either.
find_addr() {
  iface=""
  cidr=""
  addrs="$($IPCMD -4 -o addr show scope global 2>/dev/null)"
  [ -n "$addrs" ] || return 1

  # Two passes: prefer a non-eth0 device (eth0 is often a leftover docker
  # bridge), then accept anything, since a CORE-attached iface can be eth0.
  for pass in 1 2; do
    oldifs="$IFS"
    IFS='
'
    for line in $addrs; do
      IFS="$oldifs"
      set -- $line
      dev="$2"
      fam="$3"
      addr="$4"
      case "$dev" in
        *@*)
          di="$IFS"; IFS='@'; set -- $dev; dev="$1"; IFS="$di" ;;
      esac
      if [ "$fam" = "inet" ] && [ -n "$addr" ]; then
        if [ "$pass" = "1" ] && [ "$dev" = "eth0" ]; then
          :
        elif [ "$dev" != "lo" ]; then
          iface="$dev"
          cidr="$addr"
          IFS="$oldifs"
          return 0
        fi
      fi
      IFS='
'
    done
    IFS="$oldifs"
  done
  return 1
}

waited=0
while : ; do
  if find_addr; then
    break
  fi
  if [ "$waited" -ge "$wait_s" ]; then
    log "no global IPv4 interface after ${waited}s; giving up"
    exit 0
  fi
  waited=$((waited + 1))
  sleep 1
done

if [ "$waited" -gt 0 ]; then
  log "waited ${waited}s for a global IPv4 address"
fi

ipaddr=""
prefix=""
oi="$IFS"; IFS='/'; set -- $cidr; ipaddr="$1"; prefix="$2"; IFS="$oi"

case "$prefix" in
  ''|*[!0-9]*) prefix=24 ;;
esac

a=""; b=""; c=""; d=""
oi="$IFS"; IFS='.'; set -- $ipaddr; a="$1"; b="$2"; c="$3"; d="$4"; IFS="$oi"
for octet in "$a" "$b" "$c" "$d"; do
  case "$octet" in
    ''|*[!0-9]*) log "invalid IPv4 address parsed: $ipaddr"; exit 0 ;;
  esac
done

# An explicit override wins, for topologies whose gateway is not the first host.
gw="${CORETG_DEFAULT_GW:-}"
if [ -z "$gw" ]; then
  if [ "$prefix" -gt 30 ]; then
    log "prefix /$prefix too narrow to derive a gateway (addr=$ipaddr); skipping"
    exit 0
  fi
  # Derive the gateway from the actual subnet rather than assuming a /24:
  # network base + 1, or + 2 when that address is our own.
  ipnum=$(( (a * 16777216) + (b * 65536) + (c * 256) + d ))
  mask=$(( 4294967295 ^ ((1 << (32 - prefix)) - 1) ))
  net=$(( ipnum & mask ))
  gwnum=$(( net + 1 ))
  if [ "$gwnum" -eq "$ipnum" ]; then
    gwnum=$(( net + 2 ))
  fi
  g1=$(( (gwnum >> 24) & 255 ))
  g2=$(( (gwnum >> 16) & 255 ))
  g3=$(( (gwnum >> 8) & 255 ))
  g4=$(( gwnum & 255 ))
  gw="$g1.$g2.$g3.$g4"
fi

has_default() {
  routes="$($IPCMD route show 2>/dev/null)"
  case "$routes" in
    default*|*"
default"*) return 0 ;;
  esac
  return 1
}

if has_default; then
  log "default route already present (addr=$ipaddr/$prefix dev=$iface); nothing to do"
  exit 0
fi

# Try a few times: the peer/router side may still be coming up, which makes the
# gateway briefly unreachable ("RTNETLINK answers: Network unreachable").
attempt=0
while [ "$attempt" -lt 10 ]; do
  attempt=$((attempt + 1))
  err="$($IPCMD route replace default via "$gw" dev "$iface" 2>&1)"
  if [ $? -eq 0 ] && has_default; then
    log "set default route via $gw dev $iface (addr=$ipaddr/$prefix, attempt=$attempt)"
    exit 0
  fi
  err2="$($IPCMD route add default via "$gw" dev "$iface" 2>&1)"
  if [ $? -eq 0 ] && has_default; then
    log "added default route via $gw dev $iface (addr=$ipaddr/$prefix, attempt=$attempt)"
    exit 0
  fi
  if [ "$attempt" -eq 1 ]; then
    log "default route attempt failed (gw=$gw dev=$iface): replace=[$err] add=[$err2]"
  fi
  sleep 2
done

log "failed to set default route via $gw dev $iface after $attempt attempts (addr=$ipaddr/$prefix)"
log "routes: $($IPCMD route show 2>&1)"
log "addrs: $($IPCMD -4 -o addr show 2>&1)"
exit 0
</%text>"""
