from core.config import ConfigString, ConfigBool, Configuration
from core.services.base import CoreService, ShadowDir, ServiceMode

# class that subclasses CoreService
class TrafficService(CoreService):
    # unique name for your service within CORE
    name: str = "Traffic"
    # the group your service is associated with, used for display in GUI
    group: str = "Simple"
    # directories that the service should shadow mount, hiding the system directory
    #directories: list[str] = ["/usr/local/core"]
    # files that this service should generate, defaults to nodes home directory
    # or can provide an absolute path to a mounted directory
    files: list[str] = ["/runtraffic.sh"]
    # executables that should exist on path, that this service depends on
    executables: list[str] = []
    # other services that this service depends on, defines service start order
    dependencies: list[str] = ["CoreTGPrereqs"]
    # commands to run to start this service
    #
    # The script has to be found on both node kinds. CORE writes a Docker node's
    # service files into the container, so they land at `/runtraffic.sh`; for a
    # namespaced vnode (PC/router) the node shares the host filesystem and the
    # file only exists in the node's `.conf` directory, which is the working
    # directory the startup command runs from. An absolute-only path therefore
    # fails silently on vnodes, which is how traffic could be configured and
    # deployed yet never actually start. CORE's own services use the relative
    # form; try that first and fall back to the absolute Docker location.
    startup: list[str] = [
        "/bin/bash -c 'f=runtraffic.sh; [ -f \"$f\" ] || f=/runtraffic.sh; exec bash \"$f\"' &"
    ]
    # commands to run to validate this service
    validate: list[str] = []
    # commands to run to stop this service
    shutdown: list[str] = []
    # validation mode BLOCKING, NON_BLOCKING, and TIMER
    validation_mode: ServiceMode = ServiceMode.NON_BLOCKING

    # defines directories that this service can help shadow within a node
    shadow_directories: list[ShadowDir] = []

    def get_text_template(self, name: str) -> str:
        """
        This function is used to return a string template that will be rendered
        by the templating engine. Available variables will be node and any other
        key/value pairs returned by the "data()" function.

        :param name: name of file to get template for
        :return: string template
        """
        # Only the node constants below are templated by Mako; the script body
        # lives in a <%text> block so it is plain shell. Without that, ordinary
        # syntax breaks: `${VAR:-default}` raises, a line starting with `%` is a
        # Mako control line, and a line starting with `##` is silently dropped.
        return """
        #!/bin/bash
        NODE_ID='${node.id}'
        NODE_NAME='${node.name}'
        <%text>
        # Traffic starter.
        #
        # Runs the static Go agent rather than per-flow Python scripts. Most
        # vulnerability images ship no python3, so the old approach silently
        # generated no traffic on Docker nodes; a static binary has no
        # interpreter or package-manager dependency. The agent takes one config
        # per node and runs every flow for that node in a single process.
        runtime_dir=/tmp/coretg_traffic
        mkdir -p "$runtime_dir"
        log="$runtime_dir/output.txt"
        config=/tmp/traffic/traffic_"$NODE_ID".json

        if [ ! -f "$config" ]; then
            echo "no traffic config at $config; nothing to run" >> "$log"
            exit 0
        fi

        # The node decides its own architecture: a Docker node may be an
        # emulated amd64 image on an arm64 host, so the host's arch is not
        # authoritative.
        case "$(uname -m)" in
            x86_64|amd64) arch=amd64 ;;
            aarch64|arm64) arch=arm64 ;;
            *) arch="$(uname -m)" ;;
        esac

        agent=""
        for candidate in \\
            "/tmp/traffic/traffic-agent-linux-$arch" \\
            "/usr/local/coretg/bin/traffic-agent" \\
            "$(command -v traffic-agent 2>/dev/null)"; do
            if [ -n "$candidate" ] && [ -x "$candidate" ]; then
                agent="$candidate"
                break
            fi
        done

        if [ -z "$agent" ]; then
            echo "no traffic-agent binary for arch $arch (looked in /tmp/traffic and /usr/local/coretg/bin)" >> "$log"
            exit 0
        fi

        # Copy locally so a running flow does not depend on the shared
        # directory surviving the rest of the run.
        cp "$agent" "$runtime_dir/traffic-agent" 2>/dev/null || true
        chmod +x "$runtime_dir/traffic-agent" 2>/dev/null || true
        [ -x "$runtime_dir/traffic-agent" ] || runtime_dir_agent="$agent"
        run_agent="${runtime_dir_agent:-$runtime_dir/traffic-agent}"

        echo "running: $run_agent -config $config" >> "$log"
        "$run_agent" -config "$config" \\
            -stats "$runtime_dir/stats.json" >> "$log" 2>&1 &
        </%text>
        """

