#!/bin/bash
set -u
url=http://localhost:5055
ready() { curl --noproxy '*' --silent --fail --max-time 2 "$url" >/dev/null 2>&1; }
if ready; then
    exec xdg-open "$url"
fi
/usr/local/bin/cyber-agent-flow &
server_pid=$!
for attempt in $(seq 1 120); do
    if ! kill -0 "$server_pid" 2>/dev/null; then
        wait "$server_pid"
        result=$?
        echo 'CyberAgentFlow exited before its web page was ready.' >&2
        (( result != 0 )) || result=1
        exit "$result"
    fi
    if ready; then
        xdg-open "$url" || echo "Could not open the browser; visit $url" >&2
        wait "$server_pid"
        exit $?
    fi
    sleep 1
done
echo "CyberAgentFlow is still starting. Open $url when ready; server output follows." >&2
wait "$server_pid"
