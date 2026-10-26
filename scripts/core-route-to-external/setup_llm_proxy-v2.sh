#!/usr/bin/env bash
# Dr. Jaime C. Acosta
# Copy of core-router-uplink-sce-web.sh with a selectable, restricted uplink.
# Run BEFORE starting CORE. Requires Python 3 on the CORE VM. For an uploaded
# script, enable Render template variables in SCE-web and invoke it with:
#   bash /home/corevm/setup_llm_proxy-v2.sh \
#     --instance-index "{{instance_index}}" \
#     --scenario-xml /root/myscenario.xml \
#     --router-node n3 \
#     --external-interface eth1 \
#     --internal-ip 13.0.0.101 \
#     --uplink-gateway 11.0.0.254 \
#     --external-addresses \
#       100.100.100.100:8080:129.108.156.63:11434-11436 \
#       100.100.100.101:443:129.108.4.46:443-443
# Replace n3 with the router's exact name or numeric node ID, eth1 with
# its external interface, and the example addresses with permitted servers.
#
# Options override the corresponding environment variables. External addresses
# can be passed with --external-addresses, or as positional arguments as before:
#   EXTERNAL_ADDRESSES='100.100.100.100:8080:129.108.156.63:11434-11436 100.100.100.101:443:129.108.4.46:443-443'
# See --help for --scenario-xml and --uplink-gateway, too.
# Format: TRANSLATED_IP:TRANSLATED_PORT:REAL_IP:REAL_PORT_RANGE (TCP).
# Real port = START + ((instance_index - 1) % (END - START + 1)).
# Instance 68: 100.100.100.100:8080 -> 129.108.156.63:11435;
#              100.100.100.101:443 -> 129.108.4.46:443.
# Each entry has its own translated IP/port; no implicit aliases or direct
# backend access are added for this format. Students use the translated endpoint.
# A single real port also works in the final field. No global port flags needed.
# Older IP[:PORT_OR_RANGE] and IP:CLIENT_PORT:BACKEND_RANGE forms still work;
# their legacy LLM alias uses VIRTUAL_LLM/LLM_ADDRESS. Bare IPs allow all ports.
# Do not combine global DEST_PORT/CONVERSION_BASE_PORT settings with port entries.
# Include your LM address in the list. URLs, CIDRs, and IPv6 are not accepted.
# Hostnames resolve on the VM at configuration time; rerun to refresh their IPs.
# Website redirects/CDNs need their own listed addresses. The internal host does
# not receive general DNS access; use an allowed resolver or local hosts entries.
#
# Updates only the selected router interface's IP/MAC and saves a .bak backup.
# Adds the firewall/routes/NAT to the uplink router's IPForward template, so they
# execute INSIDE that router rather than on the CORE VM. Existing IPForward
# service settings and template content are preserved. Only replies to
# internal-initiated connections are allowed back; other forwarding through the
# uplink (including IPv6) drops.
# Other scenario services must not subsequently override these firewall rules.
# Specify --router-node when changing the assigned instance_index on a rerun.
set -eu

instance_index="{{instance_index}}"
instance_index="${INSTANCE_INDEX:-$instance_index}"
scenario_xml="${SCENARIO_XML:-/root/myscenario.xml}"
internal_ip="${INTERNAL_IP:-13.0.0.101}"
external_addresses="${EXTERNAL_ADDRESSES:-}" # Example: '192.0.2.10 example.org'
uplink_gateway="${UPLINK_GATEWAY:-11.0.0.254}"

python3 - "$instance_index" "$scenario_xml" "$internal_ip" \
  "$uplink_gateway" "$external_addresses" "$@" <<'PY'
import argparse
import ipaddress
import os
from pathlib import Path
import re
import shutil
import socket
import sys
import tempfile
import xml.etree.ElementTree as ET


def fail(message):
    raise SystemExit(message)


def ipv4(value):
    try:
        return str(ipaddress.IPv4Address(value))
    except ipaddress.AddressValueError:
        fail(f"Expected a single IPv4 address: {value!r}")


def port(value, option):
    if not re.fullmatch(r"[0-9]+", str(value)) or not 1 <= int(value) <= 65535:
        fail(f"Expected {option} to be an integer from 1 through 65535: {value!r}")
    return int(value)


def port_range(value):
    parts = value.split("-")
    if len(parts) not in (1, 2):
        fail(f"Expected a port or inclusive START-END range: {value!r}")
    start, end = port(parts[0], "port range"), port(parts[-1], "port range")
    if start > end:
        fail(f"Port range must be ascending: {value!r}")
    return start, end


def port_match(start, end):
    return str(start) if start == end else f"{start}:{end}"


default_index, default_filename, default_internal, default_gateway, default_addresses, *arguments = sys.argv[1:]
parser = argparse.ArgumentParser(
    prog="setup_llm_proxy-v2.sh",
    description="Configure the CORE router uplink allowlist in the scenario XML before starting CORE.",
    epilog="Options override environment variables. Positional destinations append to the configured allowlist. "
           "Use single IPv4 addresses or resolvable hostnames, not URLs, CIDRs or IPv6.")
parser.add_argument("--instance-index", default=default_index, metavar="N",
                    help="SCE-web instance index, 1..253; overrides INSTANCE_INDEX")
parser.add_argument("--scenario-xml", default=default_filename, metavar="PATH",
                    help="scenario XML path; overrides SCENARIO_XML (default: /root/myscenario.xml)")
parser.add_argument("--router-node", default=os.environ.get("ROUTER_NODE", ""), metavar="ID_OR_NAME",
                    help="router node ID or exact name; overrides ROUTER_NODE (default: auto-detect)")
parser.add_argument("--external-interface", default=os.environ.get("EXTERNAL_INTERFACE", "eth1"), metavar="NAME",
                    help="external interface on that router; overrides EXTERNAL_INTERFACE (default: eth1)")
parser.add_argument("--internal-ip", default=default_internal, metavar="IP",
                    help="permitted internal host; overrides INTERNAL_IP (default: 13.0.0.101)")
parser.add_argument("--dest-port", "--virtual-port", default=os.environ.get("DEST_PORT", os.environ.get("VIRTUAL_PORT")), metavar="PORT",
                    help="legacy global client TCP port for bare-IP entries; overrides DEST_PORT (proxy default: 8080)")
parser.add_argument("--conversion-base-port", "--llm-base-port", default=os.environ.get("CONVERSION_BASE_PORT", os.environ.get("LLM_BASE_PORT")), metavar="PORT",
                    help="legacy global backend TCP base for bare-IP entries; overrides CONVERSION_BASE_PORT (proxy default: 11434)")
parser.add_argument("--backend-port-count", default=os.environ.get("BACKEND_PORT_COUNT", "3"), metavar="N",
                    help="legacy global backend port count; overrides BACKEND_PORT_COUNT (default: 3)")
parser.add_argument("--virtual-llm", default=os.environ.get("VIRTUAL_LLM", "100.100.100.100"), metavar="IP",
                    help="legacy model alias; unused by four-field entries; overrides VIRTUAL_LLM (default: 100.100.100.100)")
parser.add_argument("--llm-address", default=os.environ.get("LLM_ADDRESS", "129.108.156.63"), metavar="IP",
                    help="legacy model alias backend; unused by four-field entries; overrides LLM_ADDRESS (default: 129.108.156.63)")
parser.add_argument("--uplink-gateway", "--gateway", default=default_gateway, metavar="IP",
                    help="uplink gateway; overrides UPLINK_GATEWAY (default: 11.0.0.254)")
parser.add_argument("--external-addresses", nargs="+", action="append", metavar="ENDPOINT",
                    help="TRANSLATED_IP:TRANSLATED_PORT:REAL_IP:REAL_PORT_RANGE; replaces EXTERNAL_ADDRESSES; legacy formats also work")
parser.add_argument("addresses", nargs="*", metavar="IP_OR_HOST",
                    help="additional allowed destinations (legacy positional form)")
args = parser.parse_args(arguments)
external_interface = args.external_interface
# This value is embedded in shell commands; disallow shell syntax and iptables
# interface wildcards, and respect Linux's 15-byte interface-name limit.
if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.:-]{0,14}", external_interface):
    fail("Expected --external-interface to be a single interface name of 1..15 safe characters.")
index, filename, internal, gateway = args.instance_index, args.scenario_xml, args.internal_ip, args.uplink_gateway
if not re.fullmatch(r"[0-9]+", index) or not 1 <= int(index) <= 253:
    fail("Set --instance-index or INSTANCE_INDEX to 1..253. In SCE-web, enable Render template variables.")
index = int(index)
router_ip = f"11.0.0.{index}"
router_mac = f"00:00:00:aa:00:{index:02x}"
virtual_llm = None
legacy_proxy_enabled = args.dest_port is not None or args.conversion_base_port is not None
if legacy_proxy_enabled:
    dest_port = port(args.dest_port if args.dest_port is not None else "8080", "--dest-port")
    conversion_base_port = port(args.conversion_base_port if args.conversion_base_port is not None else "11434", "--conversion-base-port")
    backend_port_count = port(args.backend_port_count, "--backend-port-count")
    if conversion_base_port + backend_port_count - 1 > 65535:
        fail("Backend port range exceeds 65535; lower --conversion-base-port or --backend-port-count.")
    backend_port = conversion_base_port + (index - 1) % backend_port_count
    virtual_llm, llm_address = ipv4(args.virtual_llm), ipv4(args.llm_address)
internal, gateway = ipv4(internal), ipv4(gateway)
addresses = ([address for group in args.external_addresses for value in group for address in value.split()]
             if args.external_addresses is not None else default_addresses.split())
addresses += args.addresses
if not addresses:
    fail("Set --external-addresses, EXTERNAL_ADDRESSES, or positional IPv4 addresses/hostnames; include the LM address.")

# Resolve everything before touching the XML. A typo/unresolvable name must not
# leave a partially rewritten scenario or silently expand to a network prefix.
allowed = set()
policies = set()
explicit_mappings = set()
endpoint_ports = any(":" in value for value in addresses)
if endpoint_ports and legacy_proxy_enabled:
    fail("Use per-address port settings or the legacy global port options/environment variables, not both. "
         "Unset DEST_PORT, VIRTUAL_PORT, CONVERSION_BASE_PORT and LLM_BASE_PORT for per-address settings.")
for endpoint in addresses:
    parts = endpoint.split(":")
    if len(parts) not in (1, 2, 3, 4):
        fail(f"Expected TRANSLATED_IP:TRANSLATED_PORT:REAL_IP:REAL_PORT_RANGE "
             f"or a legacy IP[:PORT_OR_RANGE] entry: {endpoint!r}")
    address = parts[0]
    kind, start, end, selected_backend = "all", 0, 0, 0
    if len(parts) == 2:
        kind = "direct"
        start, end = port_range(parts[1])
    elif len(parts) == 3:
        kind = "mapped"
        start = end = port(parts[1], "client port")
        low, high = port_range(parts[2])
        selected_backend = low + (index - 1) % (high - low + 1)
    elif len(parts) == 4:
        kind = "explicit"
        translated_ip = ipv4(parts[0])
        start = end = port(parts[1], "translated port")
        address = parts[2]
        low, high = port_range(parts[3])
        selected_backend = low + (index - 1) % (high - low + 1)
        translated = ipaddress.IPv4Address(translated_ip)
        if (translated.is_unspecified or translated.is_multicast or translated.is_loopback
                or translated_ip == "255.255.255.255" or translated_ip in (internal, router_ip, gateway)):
            fail(f"Translated IP must be a separate unicast address, distinct from the internal host/uplink/gateway: {translated_ip}")
    if re.fullmatch(r"[0-9.]+", address):
        resolved = {ipv4(address)}
    else:
        if len(address) > 253 or not all(
            re.fullmatch(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?", label)
            for label in address.rstrip(".").split(".")
        ):
            fail(f"Expected an IPv4 address or hostname, not a URL/CIDR: {address!r}")
        try:
            results = socket.getaddrinfo(address, None, socket.AF_INET, socket.SOCK_STREAM)
        except socket.gaierror as error:
            fail(f"Cannot resolve {address!r}: {error}")
        if not results:
            fail(f"No IPv4 addresses for {address!r}")
        resolved = {ipv4(result[4][0]) for result in results}
    allowed.update(resolved)
    if kind == "explicit":
        if len(resolved) != 1:
            fail(f"Real destination for {translated_ip}:{start} resolves to multiple IPs; use one real IPv4 address.")
        explicit_mappings.update((translated_ip, start, ip, selected_backend) for ip in resolved)
    else:
        policies.update((ip, kind, start, end, selected_backend) for ip in resolved)
allowed = sorted(allowed, key=ipaddress.IPv4Address)
policies = sorted(policies)
for address in allowed:
    parsed = ipaddress.IPv4Address(address)
    if parsed.is_unspecified or parsed.is_multicast or parsed.is_loopback or address == "255.255.255.255":
        fail(f"Not a unicast external destination: {address}")
    if address in (internal, router_ip):
        fail(f"External destination conflicts with the internal/uplink address: {address}")
for address in allowed:
    entries = [entry for entry in policies if entry[0] == address]
    if any(entry[1] == "all" for entry in entries) and len(entries) > 1:
        fail(f"Do not mix unrestricted and port-specific entries for {address}.")
    for _, kind, start, end, backend in entries:
        if kind == "mapped" and any(other[1] != "all" and other != (address, kind, start, end, backend)
                                    and other[2] <= start <= other[3] for other in entries):
            fail(f"Conflicting client port policies for {address}:{start}.")
mappings = []
if legacy_proxy_enabled:
    if llm_address not in allowed:
        fail("The --llm-address must also be included in --external-addresses / EXTERNAL_ADDRESSES.")
    mappings.append((virtual_llm, dest_port, llm_address, backend_port))
elif any(entry[1] == "mapped" for entry in policies):
    virtual_llm, llm_address = ipv4(args.virtual_llm), ipv4(args.llm_address)
    for address, kind, start, end, backend in policies:
        if kind == "mapped":
            mappings.append((address, start, address, backend))
            # Preserve the earlier virtual model endpoint for the selected LLM.
            # All other converted servers use their real IP and client port.
            if address == llm_address:
                mappings.append((virtual_llm, start, address, backend))
proxy_enabled = bool(mappings)
if proxy_enabled and any(original == virtual_llm for original, _, _, _ in mappings):
    virtual = ipaddress.IPv4Address(virtual_llm)
    if (virtual.is_unspecified or virtual.is_multicast or virtual.is_loopback or virtual_llm == "255.255.255.255"
            or virtual_llm in allowed or virtual_llm in (internal, router_ip, gateway)):
        fail("The --virtual-llm must be a separate unicast IPv4 address, distinct from internal/uplink/gateway/allowed IPs.")
# Explicit entries define their own virtual endpoint; no automatic LLM alias or
# direct access to the real backend is added for these entries.
mappings = sorted(set(mappings) | explicit_mappings)
client_endpoints = {}
for original_ip, client_port, address, backend in mappings:
    key, destination = (original_ip, client_port), (address, backend)
    if key in client_endpoints and client_endpoints[key] != destination:
        fail(f"Conflicting translations for {original_ip}:{client_port}.")
    client_endpoints[key] = destination
    if any(ip == original_ip and (kind == "all" or kind == "direct" and low <= client_port <= high)
           for ip, kind, low, high, _ in policies) and not legacy_proxy_enabled:
        fail(f"Translation overlaps direct access for {original_ip}:{client_port}.")
proxy_enabled = bool(mappings)

path = Path(filename)
original = path.read_text()
root = ET.fromstring(original, parser=ET.XMLParser(target=ET.TreeBuilder(insert_comments=True)))
if root.tag != "scenario":
    fail("Expected a CORE <scenario> XML file.")
devices = root.findall("./devices/device")
node_inventory = "; ".join(
    f"ID={device.get('id')!r}, name={device.get('name')!r}, type={device.get('type')!r}"
    for device in devices
) or "(no devices found)"
if args.router_node:
    matches = [device for device in devices
               if args.router_node in (device.get("id"), device.get("name"))]
    if len(matches) != 1:
        fail(f"Expected exactly one node with ID or name {args.router_node!r}; found {len(matches)}.\n"
             f"Scenario XML: {path}\nAvailable nodes: {node_inventory}")
    device = matches[0]
    if device.get("type") != "router":
        fail(f"Selected node {args.router_node!r} must be a CORE router device; "
             f"its XML type is {device.get('type')!r}.\nScenario XML: {path}")
    node_id = device.get("id")
else:
    node_id = None
interfaces = []
available_interfaces = []
named_interfaces = []
for link in root.findall("./links/link"):
    for side in ("1", "2"):
        iface = link.find(f"iface{side}")
        owner = link.get(f"node{side}")
        if iface is not None and args.router_node and owner == node_id:
            available_interfaces.append(iface.get("name", "(unnamed)"))
        if iface is None or iface.get("name") != external_interface:
            continue
        named_interfaces.append((owner, iface))
        if args.router_node:
            if owner == node_id:
                interfaces.append((owner, iface))
        elif iface.get("ip4") in ("11.0.0.2", router_ip) or iface.get("mac", "").lower() in (
            "00:00:00:aa:00:00", router_mac
        ):
            if any(device.get("id") == owner and device.get("type") == "router" for device in devices):
                interfaces.append((owner, iface))
if not args.router_node:
    # Include every representation of each candidate interface, so a conflicting
    # copy cannot be hidden merely because its address did not match detection.
    candidate_nodes = {owner for owner, iface in interfaces}
    interfaces = [(owner, iface) for owner, iface in named_interfaces if owner in candidate_nodes]
# Some CORE XML exports repeat an interface in both directional link records.
# Treat copies with identical owner and attributes as one logical interface,
# and update every copy. Different IDs/addresses/masks remain an error.
identities = {(owner, tuple(sorted(iface.attrib.items()))) for owner, iface in interfaces}
if len(identities) != 1:
    if args.router_node:
        details = "; ".join(str(iface.attrib) for owner, iface in interfaces) or "(none)"
        fail(f"Expected exactly one distinct {external_interface!r} interface on router {args.router_node!r}; "
             f"found {len(identities)} distinct definitions in {len(interfaces)} XML entries.\n"
             f"Scenario XML: {path}\nAvailable interfaces: {', '.join(available_interfaces) or '(none)'}\n"
             f"Matching definitions: {details}")
    fail(f"Expected exactly one CORE router uplink with the original/current IP/MAC on {external_interface}; specify --router-node.")
node_id, interface = interfaces[0]
device = next(device for device in devices if device.get("id") == node_id)
for owner, interface in interfaces:
    interface.set("ip4", router_ip)
    interface.set("mac", router_mac)

services = device.find("services")
if services is None:
    services = ET.SubElement(device, "services")
if not any(service.get("name") == "IPForward" for service in services):
    ET.SubElement(services, "service", name="IPForward")
configs = root.find("service_configurations")
if configs is None:
    configs = ET.SubElement(root, "service_configurations")
matches = [service for service in configs if service.get("node") == node_id and service.get("name") == "IPForward"]
if len(matches) > 1:
    fail("Multiple IPForward configurations for the uplink router; resolve these first.")
service = matches[0] if matches else ET.SubElement(configs, "service", name="IPForward", node=node_id)
# CORE exports startup/files/executables and other service settings alongside
# templates. Keep those settings intact; they do not make this a legacy format.
supported_settings = {"startup", "shutdown", "validate", "directories", "files",
                      "executables", "dependencies", "templates"}
unknown_settings = [child.tag for child in service if isinstance(child.tag, str) and child.tag not in supported_settings]
if unknown_settings:
    fail(f"Unrecognized IPForward XML settings: {', '.join(unknown_settings)}; scenario left unchanged.")
templates = service.find("templates")
if templates is None:
    templates = ET.SubElement(service, "templates")
matches = [template for template in templates if template.get("name") == "ipforward.sh"]
if len(matches) > 1:
    fail("Multiple ipforward.sh templates for the uplink router.")
template = matches[0] if matches else ET.SubElement(templates, "template", name="ipforward.sh")
block_begin, block_end = "# BEGIN SCE UPLINK ALLOWLIST", "# END SCE UPLINK ALLOWLIST"
body = template.text or ""
if block_begin in body or block_end in body:
    if body.count(block_begin) != 1 or body.count(block_end) != 1:
        fail("Malformed existing SCE uplink allowlist block.")
    body, removed = re.subn(re.escape(block_begin) + r".*?" + re.escape(block_end) + r"\n?", "", body, flags=re.S)
    if removed != 1:
        fail("Malformed existing SCE uplink allowlist block.")
if not body.strip():
    # Retain CORE's default forwarding setup. IPv6 on the uplink is deliberately
    # blocked below, while other interfaces retain their normal routing.
    body = """#!/bin/sh
<%text>
sysctl -w net.ipv4.conf.all.forwarding=1
sysctl -w net.ipv4.conf.default.forwarding=1
sysctl -w net.ipv6.conf.all.forwarding=1
sysctl -w net.ipv6.conf.default.forwarding=1
for dir in /proc/sys/net/ipv4/conf/*; do
    echo 1 > "$dir/forwarding"
    echo 0 > "$dir/send_redirects"
    echo 0 > "$dir/rp_filter"
done
for dir in /proc/sys/net/ipv6/conf/*; do
    echo 1 > "$dir/forwarding"
done
</%text>
"""

# Dedicated chains run before legacy broad ACCEPT/ESTABLISHED rules. A DROP at
# the end of each chain prevents falling through to those older permissions.
rules = [
    "set -eu",
    "command -v iptables >/dev/null",
    "command -v ip6tables >/dev/null",
    f"ip link show dev {external_interface} >/dev/null",
    "iptables -w -N SCE_UPLINK_OUT 2>/dev/null || iptables -w -S SCE_UPLINK_OUT >/dev/null",
    "iptables -w -N SCE_UPLINK_IN 2>/dev/null || iptables -w -S SCE_UPLINK_IN >/dev/null",
    "iptables -w -t nat -N SCE_UPLINK_NAT 2>/dev/null || iptables -w -t nat -S SCE_UPLINK_NAT >/dev/null",
    "iptables -w -t nat -N SCE_UPLINK_DNAT 2>/dev/null || iptables -w -t nat -S SCE_UPLINK_DNAT >/dev/null",
    # Block first, including during reapplication; only remove these guards
    # after the complete replacement allowlist has been installed.
    f"iptables -w -I FORWARD 1 -i {external_interface} -m comment --comment sce-uplink-update -j DROP",
    f"iptables -w -I FORWARD 1 -o {external_interface} -m comment --comment sce-uplink-update -j DROP",
    f"ip6tables -w -I FORWARD 1 -i {external_interface} -j DROP",
    f"ip6tables -w -I FORWARD 1 -o {external_interface} -j DROP",
    "iptables -w -F SCE_UPLINK_OUT",
    "iptables -w -F SCE_UPLINK_IN",
    "iptables -w -t nat -F SCE_UPLINK_NAT",
    "iptables -w -t nat -F SCE_UPLINK_DNAT",
    f"iptables -w -A SCE_UPLINK_OUT -i {external_interface} -j DROP",
]
for address in allowed:
    # A host route avoids granting a default route to arbitrary destinations.
    if address != gateway:
        rules.append(f"ip route replace {address}/32 via {gateway} dev {external_interface}")
for address, kind, start, end, backend in policies:
    if kind == "mapped":
        continue  # Only translated connections are allowed for mapped entries.
    outgoing_port = f" -p tcp --dport {port_match(start, end)}" if kind == "direct" else ""
    incoming_port = f" -p tcp --sport {port_match(start, end)}" if kind == "direct" else ""
    rules.extend([
        f"iptables -w -A SCE_UPLINK_OUT -s {internal}/32 -d {address}/32{outgoing_port} -m conntrack --ctstate NEW,ESTABLISHED --ctdir ORIGINAL -j ACCEPT",
        f"iptables -w -A SCE_UPLINK_IN -s {address}/32 -d {internal}/32{incoming_port} -m conntrack --ctstate ESTABLISHED --ctdir REPLY --ctorigsrc {internal} --ctorigdst {address} -j ACCEPT",
        f"iptables -w -t nat -A SCE_UPLINK_NAT -s {internal}/32 -d {address}/32{outgoing_port} -j SNAT --to-source {router_ip}",
    ])
for original_ip, client_port, address, backend in mappings:
    original_tuple = f"--ctorigsrc {internal} --ctorigdst {original_ip} --ctorigdstport {client_port}"
    rules.extend([
        f"iptables -w -t nat -A SCE_UPLINK_DNAT ! -i {external_interface} -s {internal}/32 -d {original_ip}/32 -p tcp --dport {client_port} -j DNAT --to-destination {address}:{backend}",
        f"iptables -w -A SCE_UPLINK_OUT -s {internal}/32 -d {address}/32 -p tcp --dport {backend} -m conntrack --ctstate NEW,ESTABLISHED --ctdir ORIGINAL {original_tuple} -j ACCEPT",
        f"iptables -w -A SCE_UPLINK_IN -s {address}/32 -d {internal}/32 -p tcp --sport {backend} -m conntrack --ctstate ESTABLISHED --ctdir REPLY {original_tuple} -j ACCEPT",
        f"iptables -w -t nat -A SCE_UPLINK_NAT -s {internal}/32 -d {address}/32 -p tcp --dport {backend} -m conntrack --ctdir ORIGINAL {original_tuple} -j SNAT --to-source {router_ip}",
    ])
rules.extend([
    "iptables -w -A SCE_UPLINK_OUT -j DROP",
    "iptables -w -A SCE_UPLINK_IN -j DROP",
    f"while iptables -w -C FORWARD -o {external_interface} -j SCE_UPLINK_OUT 2>/dev/null; do iptables -w -D FORWARD -o {external_interface} -j SCE_UPLINK_OUT; done",
    f"while iptables -w -C FORWARD -i {external_interface} -j SCE_UPLINK_IN 2>/dev/null; do iptables -w -D FORWARD -i {external_interface} -j SCE_UPLINK_IN; done",
    f"iptables -w -I FORWARD 1 -o {external_interface} -j SCE_UPLINK_OUT",
    f"iptables -w -I FORWARD 1 -i {external_interface} -j SCE_UPLINK_IN",
    f"while iptables -w -t nat -C POSTROUTING -o {external_interface} -j SCE_UPLINK_NAT 2>/dev/null; do iptables -w -t nat -D POSTROUTING -o {external_interface} -j SCE_UPLINK_NAT; done",
    f"iptables -w -t nat -I POSTROUTING 1 -o {external_interface} -j SCE_UPLINK_NAT",
    "while iptables -w -t nat -C PREROUTING -j SCE_UPLINK_DNAT 2>/dev/null; do iptables -w -t nat -D PREROUTING -j SCE_UPLINK_DNAT; done",
])
if proxy_enabled:
    rules.append("iptables -w -t nat -I PREROUTING 1 -j SCE_UPLINK_DNAT")
rules.extend([
    f"while iptables -w -C FORWARD -o {external_interface} -m comment --comment sce-uplink-update -j DROP 2>/dev/null; do iptables -w -D FORWARD -o {external_interface} -m comment --comment sce-uplink-update -j DROP; done",
    f"while iptables -w -C FORWARD -i {external_interface} -m comment --comment sce-uplink-update -j DROP 2>/dev/null; do iptables -w -D FORWARD -i {external_interface} -m comment --comment sce-uplink-update -j DROP; done",
])
# Mako must treat the generated shell literally, as with other CORE services.
template.text = body.rstrip() + "\n" + block_begin + "\n<%text>\n" + "\n".join(rules) + "\n</%text>\n" + block_end + "\n"

updated = ET.tostring(root, encoding="unicode")
# Validate/serialize completely before replacing the source. Preserve its mode
# and retain the same overwritten-on-each-run .bak contract as the original.
ET.fromstring(updated)
shutil.copy2(path, str(path) + ".bak")
temp_name = None
try:
    with tempfile.NamedTemporaryFile(mode="w", dir=path.parent, delete=False) as output:
        temp_name = output.name
        output.write(updated + "\n")
    shutil.copymode(path, temp_name)
    os.replace(temp_name, path)
finally:
    if temp_name and os.path.exists(temp_name):
        os.unlink(temp_name)
print(f"Router uplink: {router_ip}, MAC {router_mac}, CORE node {node_id} ({device.get('name', '')}), interface {external_interface}")
print(f"Allowed via {external_interface}: {internal} -> {', '.join(allowed)}; established replies only")
for address, kind, start, end, backend in policies:
    if kind == "direct":
        print(f"TCP allowed without translation: {internal} -> {address}:{start}-{end}")
if proxy_enabled:
    for original_ip, client_port, address, backend in mappings:
        if original_ip == virtual_llm:
            print(f"Student API: http://{original_ip}:{client_port}/v1 (client {internal})")
        print(f"TCP conversion: {original_ip}:{client_port} -> {address}:{backend}")
else:
    print("Port conversion disabled; use TRANSLATED_IP:TRANSLATED_PORT:REAL_IP:REAL_PORT_RANGE in --external-addresses / EXTERNAL_ADDRESSES to enable.")
PY
