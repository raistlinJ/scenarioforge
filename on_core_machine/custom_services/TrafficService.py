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
    #
    # The launcher is `sh`, not `bash`. A Docker node's container IS the
    # vulnerability image, so this command runs inside whatever the scenario
    # author chose, and plenty of those images ship no bash. When it is missing
    # the exec fails before the script's first line, so nothing runs and not
    # even the script's own log is written -- the failure is invisible outside
    # the core-daemon journal. Nothing here needs bash: the body below is POSIX
    # shell and the agent is a static binary. Keep it that way.
    startup: list[str] = [
        "/bin/sh -c 'f=runtraffic.sh; [ -f \"$f\" ] || f=/runtraffic.sh; exec sh \"$f\"' &"
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
        #!/bin/sh
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
        # Every path here is per-node. CORE vnodes share the host's /tmp (they
        # get a network namespace, not a mount namespace), so a fixed filename
        # means each vnode's agent overwrites the last one's stats and log --
        # leaving one file that describes whichever node happened to write last.
        # Docker nodes have their own /tmp and are unaffected either way.
        log="$runtime_dir/output_$NODE_ID.txt"
        stats="$runtime_dir/stats_$NODE_ID.json"
        # The artifacts are bind-mounted at both paths. /tmp is not always
        # ours: a Docker-in-Docker image runs Docker's `dind` wrapper, which
        # does `mountpoint -q /tmp || mount -t tmpfs none /tmp` and so hides
        # every bind underneath it. Binding the same directory outside /tmp as
        # well gives those nodes a view the tmpfs cannot cover.
        # Measured on `docker/unauthorized-rce`, the only such image in the
        # catalog: its agent reported "no traffic config" for the whole run
        # while every other node on the same scenario had its traffic.
        traffic_dir=""

        # Wait for the config rather than checking once. Services start as the
        # session comes up, and the traffic artifacts are staged into the shared
        # /tmp/traffic around the same moment; a node that looked once, found
        # nothing and exited stayed silent for the entire run even though its
        # config appeared a second later.
        #
        # ~60s, as thirty two-second ticks. The tick list is a literal because
        # this runs in whatever image the scenario author chose, and neither
        # `seq` nor `expr` is guaranteed to be in it.
        for _tick in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
            if [ -f /coretg/traffic/traffic_"$NODE_ID".json ]; then
                traffic_dir=/coretg/traffic
            elif [ -f /tmp/traffic/traffic_"$NODE_ID".json ]; then
                traffic_dir=/tmp/traffic
            fi
            [ -n "$traffic_dir" ] && break
            sleep 2
        done

        if [ -z "$traffic_dir" ]; then
            echo "no traffic config at /coretg/traffic or /tmp/traffic for node $NODE_ID after ~60s; nothing to run" >> "$log"
            exit 0
        fi
        config="$traffic_dir"/traffic_"$NODE_ID".json

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
            "$traffic_dir/traffic-agent-linux-$arch" \\
            "/tmp/traffic/traffic-agent-linux-$arch" \\
            "/usr/local/coretg/bin/traffic-agent" \\
            "$(command -v traffic-agent 2>/dev/null)"; do
            if [ -n "$candidate" ] && [ -x "$candidate" ]; then
                agent="$candidate"
                break
            fi
        done

        if [ -z "$agent" ]; then
            echo "no traffic-agent binary for arch $arch (looked in $traffic_dir, /tmp/traffic and /usr/local/coretg/bin)" >> "$log"
            exit 0
        fi

        # Copy locally so a running flow does not depend on the shared
        # directory surviving the rest of the run.
        cp "$agent" "$runtime_dir/traffic-agent-$NODE_ID" 2>/dev/null || true
        chmod +x "$runtime_dir/traffic-agent-$NODE_ID" 2>/dev/null || true
        [ -x "$runtime_dir/traffic-agent-$NODE_ID" ] || runtime_dir_agent="$agent"
        run_agent="${runtime_dir_agent:-$runtime_dir/traffic-agent-$NODE_ID}"

        echo "running: $run_agent -config $config" >> "$log"
        # Supervise the agent instead of launching it once. The agent itself
        # retries every dial and every listen for the life of the run, so a
        # flow survives a network that has not converged yet; this loop covers
        # the one case it cannot -- the process going away entirely -- so a
        # node cannot end up permanently silent while the scenario runs.
        #
        # A signalled exit (128+N) is session teardown, not a fault: restarting
        # there would fight CORE's own cleanup and leave orphan processes.
        (
            while :; do
                "$run_agent" -config "$config" -stats "$stats" >> "$log" 2>&1
                rc=$?
                if [ "$rc" -ge 128 ] || [ ! -f "$config" ]; then
                    echo "agent exited rc=$rc; not restarting" >> "$log"
                    break
                fi
                echo "agent exited rc=$rc; restarting in 5s" >> "$log"
                sleep 5
            done
        ) &
        </%text>
        """

