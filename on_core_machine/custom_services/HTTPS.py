from core.services.base import CoreService, ShadowDir, ServiceMode


class HTTPSService(CoreService):
    """Small, executable TLS web endpoint for ScenarioForge HTTPS intent."""

    name: str = "HTTPS"
    group: str = "Web"
    files: list[str] = ["/runhttps.sh"]
    executables: list[str] = []
    dependencies: list[str] = ["CoreTGPrereqs"]
    startup: list[str] = [
        "/bin/sh -c 'f=runhttps.sh; [ -f \"$f\" ] || f=/runhttps.sh; exec sh \"$f\"'"
    ]
    validate: list[str] = []
    shutdown: list[str] = [
        "/bin/sh -c 'p=/tmp/coretg_https.pid; [ ! -s \"$p\" ] || kill \"$(cat \"$p\")\" 2>/dev/null || true'"
    ]
    validation_mode: ServiceMode = ServiceMode.NON_BLOCKING
    shadow_directories: list[ShadowDir] = []

    def get_text_template(self, name: str) -> str:  # type: ignore[override]
        return r"""<%text>
#!/bin/sh
set -eu

runtime=/tmp/coretg_https
log="$runtime/https.log"
pidfile=/tmp/coretg_https.pid
mkdir -p "$runtime"

if ! command -v openssl >/dev/null 2>&1; then
  echo "HTTPS service requires openssl" > "$log"
  exit 1
fi

if [ ! -s "$runtime/cert.pem" ] || [ ! -s "$runtime/key.pem" ]; then
  openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
    -subj "/CN=core-node" \
    -keyout "$runtime/key.pem" -out "$runtime/cert.pem" >>"$log" 2>&1
fi

if [ -s "$pidfile" ] && kill -0 "$(cat "$pidfile")" 2>/dev/null; then
  exit 0
fi

cd "$runtime"
openssl s_server -quiet -accept 443 -cert cert.pem -key key.pem -www >>"$log" 2>&1 &
echo "$!" > "$pidfile"
</%text>
"""
