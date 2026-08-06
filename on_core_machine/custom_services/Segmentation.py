from core.config import ConfigString, ConfigBool, Configuration
from core.services.base import CoreService, ShadowDir, ServiceMode

# class that subclasses CoreService
class SegmentationService(CoreService):
    # unique name for your service within CORE
    name: str = "Segmentation"
    # the group your service is associated with, used for display in GUI
    group: str = "Simple"
    # directories that the service should shadow mount, hiding the system directory
    #directories: list[str] = ["/usr/local/core"]
    # files that this service should generate, defaults to nodes home directory
    # or can provide an absolute path to a mounted directory
    files: list[str] = ["/runsegmentation.sh"]
    # executables that should exist on path, that this service depends on
    executables: list[str] = []
    # other services that this service depends on, defines service start order
    dependencies: list[str] = ["CoreTGPrereqs"]
    # commands to run to start this service
    # Resolve on both node kinds: a Docker node gets the file at the container
    # root, while a namespaced vnode only has it in its `.conf` directory (the
    # startup working directory). See TrafficService for the full explanation.
    # The launcher is `sh` for the same reason it is in TrafficService: on a
    # Docker node this runs inside the scenario's own image, which may not ship
    # bash, and the body needs nothing bash provides.
    startup: list[str] = [
        "/bin/sh -c 'f=runsegmentation.sh; [ -f \"$f\" ] || f=/runsegmentation.sh; exec sh \"$f\"' &"
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
        # Apply base policy/NAT scripts first and explicit permits last. Running
        # every script in the background allowed default-deny and ACCEPT rules
        # to race, so live iptables order could disagree with the summary.
        # The old substring glob was not an exact node-id match: node 2 also
        # matched seg_subnet_block_12_1.py.  Parse the two
        # numeric suffix fields instead so a router never executes another
        # node's policy script (which can, for example, block OSPF).
        for source in /tmp/segmentation/seg_*.py; do
           [ -f "$source" ] || continue
           file=${source##*/}
           stem=${file%.py}
           without_count=${stem%_*}
           file_node_id=${without_count##*_}
           [ "$file_node_id" = "$NODE_ID" ] || continue
           cp "$source" .
        done
        for file in seg_*.py; do
           [ -f "$file" ] || continue
           stem=${file%.py}
           without_count=${stem%_*}
           file_node_id=${without_count##*_}
           [ "$file_node_id" = "$NODE_ID" ] || continue
           case "$file" in
             seg_allow_*|seg_compose_allow_*) continue ;;
           esac
           echo "running: python3 $file" >> output.txt
           python3 "$file"
        done
        for file in seg_*.py; do
           [ -f "$file" ] || continue
           stem=${file%.py}
           without_count=${stem%_*}
           file_node_id=${without_count##*_}
           [ "$file_node_id" = "$NODE_ID" ] || continue
           case "$file" in
             seg_allow_*|seg_compose_allow_*) ;;
             *) continue ;;
           esac
           echo "running last: python3 $file" >> output.txt
           python3 "$file"
        done
        </%text>
        """
