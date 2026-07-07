#!/bin/sh
set -eu

log() { printf '[nginx-init] %s\n' "$*"; }

OUT_DIR="/etc/nginx/generated"
OUT_FILE="$OUT_DIR/timeouts.conf"
DEFAULT_TIMEOUT_S=3700

raw="${CORETG_NGINX_PROXY_READ_TIMEOUT_S:-}"
timeout_s="$raw"
case "$timeout_s" in
  '' | *[!0-9]*)
    if [ -n "$raw" ]; then
      log "CORETG_NGINX_PROXY_READ_TIMEOUT_S='$raw' is not a positive integer; using default ${DEFAULT_TIMEOUT_S}s"
    fi
    timeout_s="$DEFAULT_TIMEOUT_S"
    ;;
esac

mkdir -p "$OUT_DIR"
printf 'proxy_read_timeout %ss;\n' "$timeout_s" > "$OUT_FILE"
log "wrote $OUT_FILE (proxy_read_timeout ${timeout_s}s)"

# Do not start nginx here; this script runs under /docker-entrypoint.d
return 0 2>/dev/null || true
