# Dr. Jaime C. Acosta
"""Configuration checks for the SCE-web script; no host firewall mutations."""

import os
from pathlib import Path
import socket
import subprocess
import sys
import xml.etree.ElementTree as ET

from mako.template import Template
import pytest


SNIPPET = Path(__file__).resolve().parents[1] / "scenarioforge/utils/core-route-to-external/setup_llm_proxy-v2.sh"
BASE_XML = """<scenario>
  <!-- Keep scenario comments. -->
  <devices>
    <device id="1" name="router-1" type="router">
      <services><service name="IPForward"/><service name="RIP"/></services>
    </device>
    <device id="2" name="router-2" type="router"/>
  </devices>
  <links><link node1="1" node2="9">
    <iface1 name="eth1" ip4="11.0.0.2" ip4_mask="24" mac="00:00:00:aa:00:00"/>
  </link></links>
</scenario>
"""


def run_snippet(path, *addresses, **overrides):
    env = dict(os.environ)
    for key in ("DEST_PORT", "VIRTUAL_PORT", "CONVERSION_BASE_PORT", "LLM_BASE_PORT",
                "BACKEND_PORT_COUNT", "VIRTUAL_LLM", "LLM_ADDRESS"):
        env.pop(key, None)
    env.update(INSTANCE_INDEX="60", SCENARIO_XML=str(path),
               INTERNAL_IP="13.0.0.101", UPLINK_GATEWAY="11.0.0.254",
               EXTERNAL_ADDRESSES="", ROUTER_NODE="", EXTERNAL_INTERFACE="eth1")
    env.update(overrides)
    return subprocess.run(["bash", str(SNIPPET), *addresses], env=env,
                          capture_output=True, text=True)


def rendered_script(path, node="1"):
    root = ET.parse(path).getroot()
    template = root.find(f"./service_configurations/service[@node='{node}']/templates/template[@name='ipforward.sh']")
    return Template(template.text).render(devnames=["eth0", "eth1"])


def test_multiple_addresses_render_and_preserve_original(tmp_path):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    result = run_snippet(path, "192.0.2.10", "192.0.2.20", "192.0.2.10")
    assert result.returncode == 0, result.stderr
    assert Path(str(path) + ".bak").read_text() == BASE_XML
    assert "Keep scenario comments." in path.read_text()
    root = ET.parse(path).getroot()
    iface = root.find("./links/link/iface1")
    assert iface.get("ip4") == "11.0.0.60"
    assert iface.get("mac") == "00:00:00:aa:00:3c"
    assert root.find("./devices/device[@id='2']/services") is None
    script = rendered_script(path)
    assert subprocess.run(["sh", "-n"], input=script, text=True).returncode == 0
    for address in ("192.0.2.10", "192.0.2.20"):
        assert f"ip route replace {address}/32 via 11.0.0.254 dev eth1" in script
        accepts = [line for line in script.splitlines() if f"-s {address}/32" in line and "-j ACCEPT" in line]
        assert len(accepts) == 1
        assert "-d 13.0.0.101/32" in accepts[0]
        assert "--ctstate ESTABLISHED --ctdir REPLY" in accepts[0]
        assert "--ctorigsrc 13.0.0.101" in accepts[0]
    assert script.count("--to-source 11.0.0.60") == 2
    assert "iptables -w -A SCE_UPLINK_OUT -j DROP" in script
    assert "iptables -w -A SCE_UPLINK_IN -j DROP" in script
    assert "ip6tables -w -I FORWARD 1 -i eth1 -j DROP" in script
    assert "ip6tables -w -I FORWARD 1 -o eth1 -j DROP" in script


def test_reconfigure_replaces_allowlist_and_internal_host(tmp_path):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    assert run_snippet(path, "192.0.2.10").returncode == 0
    result = run_snippet(path, "192.0.2.20", INTERNAL_IP="13.0.0.102")
    assert result.returncode == 0, result.stderr
    script = rendered_script(path)
    assert script.count("# BEGIN SCE UPLINK ALLOWLIST") == 1
    assert "192.0.2.10" not in script
    assert "13.0.0.101" not in script
    assert "-s 13.0.0.102/32 -d 192.0.2.20/32" in script


def test_instance_68_port_conversion_and_reply_tuple(tmp_path):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    result = run_snippet(path, "--instance-index", "68", "--dest-port", "8080",
                         "--conversion-base-port", "11434", "--external-addresses",
                         "129.108.156.63", "129.108.4.46")
    assert result.returncode == 0, result.stderr
    script = rendered_script(path)
    assert "http://100.100.100.100:8080/v1" in result.stdout
    assert "100.100.100.100:8080 -> 129.108.156.63:11435" in result.stdout
    dnat = next(line for line in script.splitlines() if "-A SCE_UPLINK_DNAT" in line)
    assert "! -i eth1 -s 13.0.0.101/32 -d 100.100.100.100/32 -p tcp --dport 8080" in dnat
    assert "-j DNAT --to-destination 129.108.156.63:11435" in dnat
    reply = next(line for line in script.splitlines() if "-A SCE_UPLINK_IN" in line and "--ctorigdstport 8080" in line)
    assert "-s 129.108.156.63/32 -d 13.0.0.101/32 -p tcp --sport 11435" in reply
    assert "--ctstate ESTABLISHED --ctdir REPLY --ctorigsrc 13.0.0.101 --ctorigdst 100.100.100.100" in reply
    assert script.index("--ctorigdstport 8080") < script.index("iptables -w -A SCE_UPLINK_IN -j DROP")
    assert "-s 13.0.0.101/32 -d 129.108.4.46/32" in script
    assert "--to-source 11.0.0.68" in script
    assert subprocess.run(["sh", "-n"], input=script, text=True).returncode == 0


@pytest.mark.parametrize("index,base,count,expected", [
    (1, 11434, 3, 11434), (2, 11434, 3, 11435), (3, 11434, 3, 11436),
    (4, 11434, 3, 11434), (68, 12000, 5, 12002), (253, 65535, 1, 65535),
])
def test_port_conversion_environment_and_backend_assignment(tmp_path, index, base, count, expected):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    result = run_snippet(path, "--external-addresses", "192.0.2.10",
                         INSTANCE_INDEX=str(index), DEST_PORT="9000", CONVERSION_BASE_PORT=str(base),
                         BACKEND_PORT_COUNT=str(count), VIRTUAL_LLM="100.64.0.1", LLM_ADDRESS="192.0.2.10")
    assert result.returncode == 0, result.stderr
    assert f"100.64.0.1:9000 -> 192.0.2.10:{expected}" in result.stdout
    assert f"--to-destination 192.0.2.10:{expected}" in rendered_script(path)


def test_port_cli_overrides_environment_and_reapplication_can_disable_proxy(tmp_path):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    result = run_snippet(path, "--dest-port", "9001", "--conversion-base-port", "12000",
                         "--backend-port-count", "1", "--virtual-llm", "100.64.0.2",
                         "--llm-address", "192.0.2.20", "--external-addresses", "192.0.2.20",
                         DEST_PORT="invalid", CONVERSION_BASE_PORT="invalid", BACKEND_PORT_COUNT="invalid",
                         VIRTUAL_LLM="invalid", LLM_ADDRESS="invalid")
    assert result.returncode == 0, result.stderr
    assert "100.64.0.2:9001 -> 192.0.2.20:12000" in result.stdout
    result = run_snippet(path, "--external-addresses", "192.0.2.20",
                         VIRTUAL_PORT="8080", LLM_BASE_PORT="11434", LLM_ADDRESS="192.0.2.20")
    assert result.returncode == 0, result.stderr
    script = rendered_script(path)
    assert "--dport 9001" not in script and ":12000" not in script
    assert "--dport 8080 -j DNAT --to-destination 192.0.2.20:11436" in script
    assert script.count("# BEGIN SCE UPLINK ALLOWLIST") == 1
    result = run_snippet(path, "192.0.2.20")
    assert result.returncode == 0, result.stderr
    script = rendered_script(path)
    assert "Port conversion disabled" in result.stdout
    assert "-A SCE_UPLINK_DNAT" not in script
    assert "-I PREROUTING" not in script
    assert "-t nat -F SCE_UPLINK_DNAT" in script
    assert "-t nat -D PREROUTING -j SCE_UPLINK_DNAT" in script


@pytest.mark.parametrize("options", [
    ["--dest-port", "8080"], ["--conversion-base-port", "11434"],
])
def test_either_port_option_enables_mapping_with_other_default(tmp_path, options):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    result = run_snippet(path, *options, "--external-addresses", "129.108.156.63")
    assert result.returncode == 0, result.stderr
    assert "100.100.100.100:8080 -> 129.108.156.63:11436" in result.stdout


@pytest.mark.parametrize("options", [
    ["--dest-port", "0"], ["--dest-port", "65536"], ["--dest-port", ""],
    ["--dest-port", "8080;id"], ["--conversion-base-port", "-1"],
    ["--conversion-base-port", "65535", "--backend-port-count", "2"],
    ["--dest-port", "8080", "--backend-port-count", "0"],
    ["--dest-port", "8080", "--backend-port-count", "three"],
    ["--dest-port", "8080", "--virtual-llm", "127.0.0.1"],
    ["--dest-port", "8080", "--virtual-llm", "13.0.0.101"],
    ["--dest-port", "8080", "--virtual-llm", "129.108.156.63"],
    ["--dest-port", "8080", "--llm-address", "192.0.2.99"],
])
def test_invalid_port_mapping_leaves_xml_and_backup_untouched(tmp_path, options):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    backup = Path(str(path) + ".bak")
    backup.write_text("prior backup")
    result = run_snippet(path, *options, "--external-addresses", "129.108.156.63")
    assert result.returncode != 0
    assert path.read_text() == BASE_XML
    assert backup.read_text() == "prior backup"


@pytest.mark.parametrize("environment", [False, True])
def test_per_address_translated_and_direct_tcp_ports(tmp_path, environment):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    endpoints = "129.108.156.63:8080:11434-11436 129.108.4.46:443-443"
    options = [] if environment else ["--external-addresses", *endpoints.split()]
    overrides = {"EXTERNAL_ADDRESSES": endpoints} if environment else {"EXTERNAL_ADDRESSES": "192.0.2.99"}
    result = run_snippet(path, "--instance-index", "68", *options, **overrides)
    assert result.returncode == 0, result.stderr
    script = rendered_script(path)
    assert "129.108.156.63:8080 -> 129.108.156.63:11435" in result.stdout
    assert "100.100.100.100:8080 -> 129.108.156.63:11435" in result.stdout
    assert "TCP allowed without translation: 13.0.0.101 -> 129.108.4.46:443-443" in result.stdout
    assert "192.0.2.99" not in script
    dnat = [line for line in script.splitlines() if "-A SCE_UPLINK_DNAT" in line]
    assert len(dnat) == 2
    assert all("--dport 8080 -j DNAT --to-destination 129.108.156.63:11435" in line for line in dnat)
    outgoing = [line for line in script.splitlines() if "-A SCE_UPLINK_OUT" in line and "-j ACCEPT" in line]
    assert len(outgoing) == 3
    model = [line for line in outgoing if "-d 129.108.156.63/32" in line]
    assert len(model) == 2
    assert all("-p tcp --dport 11435" in line and "--ctorigdstport 8080" in line for line in model)
    assert all("--ctdir ORIGINAL" in line and "-s 13.0.0.101/32" in line for line in outgoing)
    https = [line for line in outgoing if "-d 129.108.4.46/32" in line]
    assert len(https) == 1 and "-p tcp --dport 443 " in https[0]
    replies = [line for line in script.splitlines() if "-A SCE_UPLINK_IN" in line and "-j ACCEPT" in line]
    assert len(replies) == 3
    assert all("--ctstate ESTABLISHED --ctdir REPLY" in line for line in replies)
    assert all("-p tcp --sport 11435" in line and "--ctorigdstport 8080" in line
               for line in replies if "-s 129.108.156.63/32" in line)
    assert subprocess.run(["sh", "-n"], input=script, text=True).returncode == 0


@pytest.mark.parametrize("index,expected", [(1,11434), (2,11435), (3,11436), (4,11434), (68,11435)])
def test_per_address_backend_range_rotation_and_direct_ranges(tmp_path, index, expected):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    result = run_snippet(path, "--external-addresses", "192.0.2.10:8080:11434-11436",
                         "192.0.2.20:8000-8010", "192.0.2.20:443", INSTANCE_INDEX=str(index))
    assert result.returncode == 0, result.stderr
    script = rendered_script(path)
    assert f"192.0.2.10:8080 -> 192.0.2.10:{expected}" in result.stdout
    assert script.count("-A SCE_UPLINK_DNAT") == 1
    assert "-d 192.0.2.20/32 -p tcp --dport 8000:8010" in script
    assert "-s 192.0.2.20/32 -d 13.0.0.101/32 -p tcp --sport 8000:8010" in script
    assert "-d 192.0.2.20/32 -p tcp --dport 443" in script


def test_per_address_multiple_translations_reconfigure_and_deduplicate(tmp_path):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    result = run_snippet(path, "--external-addresses", "192.0.2.10:8080:11434-11436",
                         "192.0.2.10:8080:11434-11436", "192.0.2.10:9000:65535-65535")
    assert result.returncode == 0, result.stderr
    script = rendered_script(path)
    assert script.count("-A SCE_UPLINK_DNAT") == 2
    assert "--dport 9000 -j DNAT --to-destination 192.0.2.10:65535" in script
    result = run_snippet(path, "--external-addresses", "192.0.2.10:443-443")
    assert result.returncode == 0, result.stderr
    script = rendered_script(path)
    assert ":65535" not in script and "--dport 8080" not in script
    assert "-A SCE_UPLINK_DNAT" not in script
    assert script.count("# BEGIN SCE UPLINK ALLOWLIST") == 1


@pytest.mark.parametrize("endpoints,options,overrides", [
    (["192.0.2.10:0"], [], {}), (["192.0.2.10:65536"], [], {}),
    (["192.0.2.10:443-442"], [], {}), (["192.0.2.10:443-443-443"], [], {}),
    (["192.0.2.10:"], [], {}), (["192.0.2.10:443;id"], [], {}),
    (["192.0.2.10:8080:11436-11434"], [], {}),
    (["192.0.2.10:8080:11434-65536"], [], {}),
    (["192.0.2.10:8000-8010:11434-11436"], [], {}),
    (["192.0.2.10:8080:11434-11436:1"], [], {}),
    (["192.0.2.10", "192.0.2.10:443"], [], {}),
    (["192.0.2.10:8080:11434", "192.0.2.10:8080:12000"], [], {}),
    (["192.0.2.10:8080:11434", "192.0.2.10:8000-9000"], [], {}),
    (["192.0.2.10:443"], ["--dest-port", "8080"], {}),
    (["192.0.2.10:443"], [], {"CONVERSION_BASE_PORT": "11434"}),
    (["129.108.156.63:8080:11434-11436"], ["--virtual-llm", "13.0.0.101"], {}),
])
def test_invalid_per_address_ports_do_not_change_files(tmp_path, endpoints, options, overrides):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    backup = Path(str(path) + ".bak")
    backup.write_text("prior backup")
    result = run_snippet(path, *options, "--external-addresses", *endpoints, **overrides)
    assert result.returncode != 0
    assert path.read_text() == BASE_XML
    assert backup.read_text() == "prior backup"


@pytest.mark.parametrize("environment", [False, True])
def test_independent_virtual_endpoints_for_model_and_https(tmp_path, environment):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    entries = ["100.100.100.100:8080:129.108.156.63:11434-11436",
               "100.100.100.101:443:129.108.4.46:443-443"]
    options = [] if environment else ["--external-addresses", *entries]
    overrides = {"EXTERNAL_ADDRESSES": " ".join(entries)} if environment else {}
    result = run_snippet(path, "--instance-index", "68", *options,
                         VIRTUAL_LLM="unused-invalid-legacy-value", LLM_ADDRESS="unused-invalid-legacy-value", **overrides)
    assert result.returncode == 0, result.stderr
    assert "100.100.100.100:8080 -> 129.108.156.63:11435" in result.stdout
    assert "100.100.100.101:443 -> 129.108.4.46:443" in result.stdout
    script = rendered_script(path)
    dnat = [line for line in script.splitlines() if "-A SCE_UPLINK_DNAT" in line]
    outbound = [line for line in script.splitlines() if "-A SCE_UPLINK_OUT" in line and "-j ACCEPT" in line]
    inbound = [line for line in script.splitlines() if "-A SCE_UPLINK_IN" in line and "-j ACCEPT" in line]
    snat = [line for line in script.splitlines() if "-A SCE_UPLINK_NAT" in line]
    assert len(dnat) == len(outbound) == len(inbound) == len(snat) == 2
    for virtual, client, real, backend in [("100.100.100.100", 8080, "129.108.156.63", 11435),
                                           ("100.100.100.101", 443, "129.108.4.46", 443)]:
        nat = next(line for line in dnat if f"-d {virtual}/32" in line)
        assert f"! -i eth1 -s 13.0.0.101/32 -d {virtual}/32 -p tcp --dport {client}" in nat
        assert f"--to-destination {real}:{backend}" in nat
        for lines in (outbound, inbound, snat):
            matched = [line for line in lines if f"--ctorigdst {virtual} --ctorigdstport {client}" in line]
            assert len(matched) == 1
            assert "--ctorigsrc 13.0.0.101" in matched[0]
        assert f"ip route replace {real}/32 via 11.0.0.254 dev eth1" in script
        assert f"ip route replace {virtual}/32" not in script
    assert all("--ctdir REPLY" in line for line in inbound)
    assert all("--ctdir ORIGINAL" in line for line in outbound)
    assert all("--to-source 11.0.0.68" in line for line in snat)
    assert subprocess.run(["sh", "-n"], input=script, text=True).returncode == 0


def test_explicit_entries_can_share_virtual_ip_on_distinct_ports_and_replace_old_mapping(tmp_path):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    entry = "100.100.100.100:8080:192.0.2.10:11434-11436"
    result = run_snippet(path, "--external-addresses", entry, entry,
                         "100.100.100.100:443:192.0.2.20:443")
    assert result.returncode == 0, result.stderr
    assert rendered_script(path).count("-A SCE_UPLINK_DNAT") == 2
    result = run_snippet(path, "--external-addresses", "100.100.100.102:9443:192.0.2.30:65535-65535")
    assert result.returncode == 0, result.stderr
    script = rendered_script(path)
    assert "--to-destination 192.0.2.30:65535" in script
    assert "100.100.100.100" not in script and "192.0.2.10" not in script and "192.0.2.20" not in script
    assert script.count("# BEGIN SCE UPLINK ALLOWLIST") == 1


@pytest.mark.parametrize("entries", [
    ["not-an-ip:8080:192.0.2.10:11434-11436"],
    ["0.0.0.0:8080:192.0.2.10:11434-11436"],
    ["127.0.0.1:8080:192.0.2.10:11434-11436"],
    ["13.0.0.101:8080:192.0.2.10:11434-11436"],
    ["11.0.0.60:8080:192.0.2.10:11434-11436"],
    ["100.100.100.100:0:192.0.2.10:11434-11436"],
    ["100.100.100.100:8080:192.0.2.10:65536"],
    ["100.100.100.100:8080:192.0.2.10:11436-11434"],
    ["100.100.100.100:8080:127.0.0.1:11434-11436"],
    ["100.100.100.100:8080:192.0.2.10:11434-11436", "100.100.100.100:8080:192.0.2.20:11434-11436"],
    ["100.100.100.100:8080:192.0.2.10:11434-11436", "100.100.100.100:8080:192.0.2.10:12000"],
    ["100.100.100.100:8080:192.0.2.10:11434-11436", "100.100.100.100:8080"],
    ["100.100.100.100:8080:192.0.2.10:11434-11436", "100.100.100.100"],
])
def test_invalid_or_conflicting_explicit_entries_preserve_files(tmp_path, entries):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    backup = Path(str(path) + ".bak")
    backup.write_text("prior backup")
    result = run_snippet(path, "--external-addresses", *entries)
    assert result.returncode != 0
    assert path.read_text() == BASE_XML
    assert backup.read_text() == "prior backup"


@pytest.mark.parametrize("ips", [["192.0.2.10"], ["192.0.2.10", "192.0.2.20"]])
def test_explicit_real_hostname_requires_one_backend_ip(tmp_path, monkeypatch, ips):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    monkeypatch.setattr(socket, "getaddrinfo", lambda *args: [
        (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0)) for address in ips])
    monkeypatch.setattr(sys, "argv", ["-", "68", str(path), "13.0.0.101", "11.0.0.254",
                                      "100.100.100.101:443:site.example:443-443"])
    program = SNIPPET.read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    if len(ips) == 1:
        exec(compile(program, str(SNIPPET), "exec"), {})
        assert "--to-destination 192.0.2.10:443" in rendered_script(path)
    else:
        with pytest.raises(SystemExit, match="resolves to multiple IPs"):
            exec(compile(program, str(SNIPPET), "exec"), {})
        assert path.read_text() == BASE_XML
        assert not Path(str(path) + ".bak").exists()


def test_preserves_existing_ipforward_template(tmp_path):
    root = ET.fromstring(BASE_XML)
    configs = ET.SubElement(root, "service_configurations")
    service = ET.SubElement(configs, "service", name="IPForward", node="1")
    templates = ET.SubElement(service, "templates")
    ET.SubElement(templates, "template", name="ipforward.sh").text = (
        "#!/bin/sh\n<%text>\necho 'existing startup command'\n</%text>\n"
    )
    path = tmp_path / "scenario.xml"
    ET.ElementTree(root).write(path)
    result = run_snippet(path, EXTERNAL_ADDRESSES="192.0.2.10 192.0.2.20")
    assert result.returncode == 0, result.stderr
    script = rendered_script(path)
    assert "echo 'existing startup command'" in script
    assert "192.0.2.10" in script and "192.0.2.20" in script


@pytest.mark.parametrize("existing_template", [False, True])
def test_exported_ipforward_metadata_is_preserved(tmp_path, existing_template):
    root = ET.fromstring(BASE_XML)
    configs = ET.SubElement(root, "service_configurations")
    service = ET.SubElement(configs, "service", name="IPForward", node="1")
    metadata = ET.fromstring("""<metadata>
      <startup><command>bash ipforward.sh</command></startup>
      <files><file>ipforward.sh</file></files>
      <executables><executable>sysctl</executable></executables>
      <shutdown><command>echo stop</command></shutdown>
      <validate><command>sysctl net.ipv4.ip_forward</command></validate>
      <directories><directory>/run/router</directory></directories>
      <dependencies><dependency>zebra</dependency></dependencies>
    </metadata>""")
    service.extend(metadata)
    preserved = [ET.tostring(child) for child in service]
    if existing_template:
        templates = ET.SubElement(service, "templates")
        ET.SubElement(templates, "template", name="ipforward.sh").text = (
            "#!/bin/sh\n<%text>\necho 'custom forwarding'\n</%text>\n")
    other = ET.SubElement(configs, "service", name="IPForward", node="2")
    ET.SubElement(other, "startup").text = "unrelated service"
    other_original = ET.tostring(other)
    path = tmp_path / "scenario.xml"
    ET.ElementTree(root).write(path)
    original = path.read_text()
    for attempt in range(2):
        result = run_snippet(path, "--router-node", "router-1", "--external-addresses", "192.0.2.10")
        assert result.returncode == 0, result.stderr
        if attempt == 0:
            assert Path(str(path) + ".bak").read_text() == original
        updated = ET.parse(path).getroot()
        service = updated.find("./service_configurations/service[@node='1']")
        assert [ET.tostring(child) for child in service if child.tag != "templates"] == preserved
        assert ET.tostring(updated.find("./service_configurations/service[@node='2']")) == other_original
        script = rendered_script(path)
        assert script.count("# BEGIN SCE UPLINK ALLOWLIST") == 1
        assert "ip route replace 192.0.2.10/32 via 11.0.0.254 dev eth1" in script
        assert "echo 'custom forwarding'" in script if existing_template else "sysctl -w net.ipv4.conf.all.forwarding=1" in script
        assert subprocess.run(["sh", "-n"], input=script, text=True).returncode == 0


def test_unsupported_ipforward_metadata_is_reported_without_changes(tmp_path):
    root = ET.fromstring(BASE_XML)
    configs = ET.SubElement(root, "service_configurations")
    service = ET.SubElement(configs, "service", name="IPForward", node="1")
    ET.SubElement(service, "legacy-settings")
    path = tmp_path / "scenario.xml"
    ET.ElementTree(root).write(path)
    original = path.read_text()
    result = run_snippet(path, "192.0.2.10")
    assert result.returncode != 0
    assert "Unrecognized IPForward XML settings: legacy-settings" in result.stderr
    assert path.read_text() == original
    assert not Path(str(path) + ".bak").exists()


def test_cli_options_override_environment_without_expanding_allowlist(tmp_path):
    path = tmp_path / "scenario with spaces.xml"
    path.write_text(BASE_XML)
    other = tmp_path / "unchanged.xml"
    other.write_text(BASE_XML)
    result = run_snippet(
        other, "--instance-index", "7", "--scenario-xml", str(path),
        "--internal-ip", "13.0.0.102", "--uplink-gateway", "11.0.0.253",
        "--external-addresses", "192.0.2.20", "192.0.2.30",
        INSTANCE_INDEX="{{instance_index}}", INTERNAL_IP="invalid", UPLINK_GATEWAY="invalid",
        EXTERNAL_ADDRESSES="192.0.2.99")
    assert result.returncode == 0, result.stderr
    assert other.read_text() == BASE_XML
    assert not Path(str(other) + ".bak").exists()
    assert Path(str(path) + ".bak").read_text() == BASE_XML
    script = rendered_script(path)
    assert "-s 13.0.0.102/32 -d 192.0.2.20/32" in script
    assert "ip route replace 192.0.2.30/32 via 11.0.0.253 dev eth1" in script
    assert "--to-source 11.0.0.7" in script
    assert "192.0.2.99" not in script
    assert ET.parse(path).find("./links/link/iface1").get("mac") == "00:00:00:aa:00:07"


@pytest.mark.parametrize("options", [
    ["--external-addresses", "192.0.2.10 192.0.2.20"],
    ["--external-addresses", "192.0.2.10", "--external-addresses", "192.0.2.20"],
    ["192.0.2.10", "--external-addresses", "192.0.2.20"],
])
def test_cli_address_lists_and_legacy_positionals(tmp_path, options):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    result = run_snippet(path, *options)
    assert result.returncode == 0, result.stderr
    script = rendered_script(path)
    assert "-d 192.0.2.10/32" in script and "-d 192.0.2.20/32" in script
    assert script.count("--to-source 11.0.0.60") == 2


def test_help_needs_no_environment_or_scenario():
    env = {key: value for key, value in os.environ.items()
           if key not in {"INSTANCE_INDEX", "SCENARIO_XML", "INTERNAL_IP", "UPLINK_GATEWAY", "EXTERNAL_ADDRESSES"}}
    result = subprocess.run(["bash", str(SNIPPET), "--help"], env=env, capture_output=True, text=True)
    assert result.returncode == 0, result.stderr
    assert "--instance-index" in result.stdout and "--external-addresses" in result.stdout
    assert "--router-node" in result.stdout and "--external-interface" in result.stdout


@pytest.mark.parametrize("selector", ["2", "router-2"])
def test_select_router_and_external_interface_without_global_substitution(tmp_path, selector):
    root = ET.fromstring(BASE_XML)
    links = root.find("links")
    link = ET.SubElement(links, "link", node1="9", node2="2")
    ET.SubElement(link, "iface2", name="eth3", ip4="172.16.0.8", ip4_mask="24", mac="02:00:00:00:00:08")
    other = ET.SubElement(links, "link", node1="2", node2="10")
    ET.SubElement(other, "iface1", name="eth0", ip4="11.0.0.2", ip4_mask="24", mac="00:00:00:aa:00:00")
    configs = ET.SubElement(root, "service_configurations")
    service = ET.SubElement(configs, "service", name="IPForward", node="1")
    templates = ET.SubElement(service, "templates")
    ET.SubElement(templates, "template", name="ipforward.sh").text = "echo 11.0.0.2 00:00:00:aa:00:00\n"
    untouched = [ET.tostring(root.find("./links/link/iface1")), ET.tostring(other), ET.tostring(service)]
    path = tmp_path / "scenario.xml"
    ET.ElementTree(root).write(path)
    result = run_snippet(path, "--router-node", selector, "--external-interface", "eth3",
                         "--external-addresses", "192.0.2.10",
                         ROUTER_NODE="nonexistent", EXTERNAL_INTERFACE="invalid;name")
    assert result.returncode == 0, result.stderr
    updated = ET.parse(path).getroot()
    selected = updated.find("./links/link/iface2")
    assert selected.attrib == dict(name="eth3", ip4="11.0.0.60", ip4_mask="24", mac="00:00:00:aa:00:3c")
    assert ET.tostring(updated.find("./links/link/iface1")) == untouched[0]
    assert ET.tostring(updated.find("./links/link[@node2='10']")) == untouched[1]
    assert ET.tostring(updated.find("./service_configurations/service[@node='1']")) == untouched[2]
    script = rendered_script(path, "2")
    assert "eth1" not in script
    assert "ip route replace 192.0.2.10/32 via 11.0.0.254 dev eth3" in script
    assert "ip6tables -w -I FORWARD 1 -i eth3 -j DROP" in script
    assert "-o eth3 -j SCE_UPLINK_NAT" in script
    assert subprocess.run(["sh", "-n"], input=script, text=True).returncode == 0


def test_router_environment_and_explicit_index_reassignment(tmp_path):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML.replace('name="eth1"', 'name="eth2"'))
    for index in ("60", "7"):
        result = run_snippet(path, "192.0.2.10", ROUTER_NODE="router-1",
                             EXTERNAL_INTERFACE="eth2", INSTANCE_INDEX=index)
        assert result.returncode == 0, result.stderr
        assert ET.parse(path).find("./links/link/iface1").get("ip4") == f"11.0.0.{index}"
    assert rendered_script(path).count("# BEGIN SCE UPLINK ALLOWLIST") == 1


@pytest.mark.parametrize("selector", ["n3", "3"])
def test_core_n3_router_label_and_numeric_id(tmp_path, selector):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML.replace('id="1" name="router-1"', 'id="3" name="n3"')
                    .replace('node1="1"', 'node1="3"'))
    result = run_snippet(path, "--router-node", selector, "--external-addresses", "192.0.2.10")
    assert result.returncode == 0, result.stderr
    assert "CORE node 3 (n3), interface eth1" in result.stdout
    assert "--to-source 11.0.0.60" in rendered_script(path, "3")


def test_selection_errors_identify_actual_xml_nodes_and_interfaces(tmp_path):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    result = run_snippet(path, "--router-node", "n3", "--external-addresses", "192.0.2.10")
    assert result.returncode != 0
    assert str(path) in result.stderr
    assert "ID='1', name='router-1', type='router'" in result.stderr
    result = run_snippet(path, "--router-node", "router-1", "--external-interface", "eth9",
                         "--external-addresses", "192.0.2.10")
    assert result.returncode != 0
    assert "Available interfaces: eth1" in result.stderr
    assert path.read_text() == BASE_XML
    assert not Path(str(path) + ".bak").exists()


@pytest.mark.parametrize("explicit", [True, False])
def test_duplicate_directional_links_update_every_interface_copy(tmp_path, explicit):
    root = ET.fromstring(BASE_XML)
    router = root.find("./devices/device[@id='1']")
    router.set("name", "n3")
    first = root.find("./links/link/iface1")
    first.set("id", "1")
    reverse = ET.SubElement(root.find("links"), "link", node1="9", node2="1")
    ET.SubElement(reverse, "iface2", **first.attrib)
    path = tmp_path / "scenario.xml"
    ET.ElementTree(root).write(path)
    original = path.read_text()
    options = ["--router-node", "n3"] if explicit else []
    for attempt in range(2):
        result = run_snippet(path, *options, "--external-addresses", "192.0.2.10")
        assert result.returncode == 0, result.stderr
        if attempt == 0:
            assert Path(str(path) + ".bak").read_text() == original
        updated = ET.parse(path).getroot()
        copies = [updated.find("./links/link/iface1"), updated.find("./links/link/iface2")]
        assert all(iface.attrib == dict(id="1", name="eth1", ip4="11.0.0.60", ip4_mask="24",
                                       mac="00:00:00:aa:00:3c") for iface in copies)
        assert rendered_script(path).count("# BEGIN SCE UPLINK ALLOWLIST") == 1


@pytest.mark.parametrize("field,value", [("id", "2"), ("ip4", "11.0.0.99"),
                                         ("mac", "02:00:00:00:00:99"), ("ip4_mask", "16")])
@pytest.mark.parametrize("explicit", [True, False])
def test_conflicting_interface_copies_are_rejected(tmp_path, field, value, explicit):
    root = ET.fromstring(BASE_XML)
    first = root.find("./links/link/iface1")
    first.set("id", "1")
    reverse = ET.SubElement(root.find("links"), "link", node1="9", node2="1")
    copy = ET.SubElement(reverse, "iface2", **first.attrib)
    copy.set(field, value)
    path = tmp_path / "scenario.xml"
    ET.ElementTree(root).write(path)
    original = path.read_text()
    backup = Path(str(path) + ".bak")
    backup.write_text("prior backup")
    options = ["--router-node", "router-1"] if explicit else []
    result = run_snippet(path, *options, "--external-addresses", "192.0.2.10")
    assert result.returncode != 0
    if explicit:
        assert "2 distinct definitions in 2 XML entries" in result.stderr
    assert path.read_text() == original
    assert backup.read_text() == "prior backup"


@pytest.mark.parametrize("options,xml", [
    (["--router-node", "missing"], BASE_XML),
    (["--router-node", "router-1", "--external-interface", "eth9"], BASE_XML),
    (["--router-node", "router-1"], BASE_XML.replace('type="router"', 'type="host"', 1)),
    (["--router-node", "router-1"], BASE_XML.replace('name="router-2"', 'name="router-1"')),
    (["--router-node", "1"], BASE_XML.replace('name="router-2"', 'name="1"')),
    (["--external-interface", "eth1;id"], BASE_XML),
    (["--external-interface", "eth+"], BASE_XML),
    (["--external-interface", "a" * 16], BASE_XML),
    (["--external-interface", ""], BASE_XML),
    ([], BASE_XML.replace('</links>', '<link node1="2" node2="9"><iface1 name="eth1" ip4="11.0.0.2"/></link></links>')),
    (["--router-node", "1"], BASE_XML.replace('</links>', '<link node1="1" node2="10"><iface1 name="eth1"/></link></links>')),
])
def test_invalid_or_ambiguous_router_selection_preserves_files(tmp_path, options, xml):
    path = tmp_path / "scenario.xml"
    path.write_text(xml)
    backup = Path(str(path) + ".bak")
    backup.write_text("previous backup")
    result = run_snippet(path, *options, "--external-addresses", "192.0.2.10")
    assert result.returncode != 0
    assert path.read_text() == xml
    assert backup.read_text() == "previous backup"


@pytest.mark.parametrize("options", [
    ["--instance-index"],
    ["--external-addresses"],
    ["--unknown-option", "192.0.2.10"],
    ["--instance-index", "254", "--external-addresses", "192.0.2.10"],
    ["--internal-ip", "13.0.0.0/24", "--external-addresses", "192.0.2.10"],
    ["--external-addresses", "https://example.org"],
])
def test_invalid_cli_options_leave_xml_and_backup_untouched(tmp_path, options):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    backup = Path(str(path) + ".bak")
    backup.write_text("previous backup")
    result = run_snippet(path, *options)
    assert result.returncode != 0
    assert path.read_text() == BASE_XML
    assert backup.read_text() == "previous backup"


@pytest.mark.parametrize("addresses,overrides", [
    ([], {}),
    (["0.0.0.0/0"], {}),
    (["https://example.org"], {}),
    (["192.0.2.999"], {}),
    (["127.0.0.1"], {}),
    (["::1"], {}),
    (["192.0.2.10"], {"INTERNAL_IP": "13.0.0.0/24"}),
    (["192.0.2.10"], {"INSTANCE_INDEX": "254"}),
    (["192.0.2.10"], {"INSTANCE_INDEX": "{{instance_index}}"}),
])
def test_invalid_config_does_not_touch_xml_or_backup(tmp_path, addresses, overrides):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)
    backup = Path(str(path) + ".bak")
    backup.write_text("previous backup")
    result = run_snippet(path, *addresses, **overrides)
    assert result.returncode != 0
    assert path.read_text() == BASE_XML
    assert backup.read_text() == "previous backup"


def test_missing_uplink_does_not_modify_scenario(tmp_path):
    path = tmp_path / "scenario.xml"
    original = BASE_XML.replace('name="eth1"', 'name="eth2"')
    path.write_text(original)
    assert run_snippet(path, "192.0.2.10").returncode != 0
    assert path.read_text() == original


@pytest.mark.parametrize("resolves", [True, False])
@pytest.mark.parametrize("endpoint", ["allowed.example", "allowed.example:443-443", "allowed.example:8080:11434-11436"])
def test_hostname_resolution_is_a_snapshot_and_fails_before_xml_changes(tmp_path, monkeypatch, resolves, endpoint):
    path = tmp_path / "scenario.xml"
    path.write_text(BASE_XML)

    def resolve(host, port, family, kind):
        assert (host, port, family, kind) == ("allowed.example", None, socket.AF_INET, socket.SOCK_STREAM)
        if not resolves:
            raise socket.gaierror("test lookup failure")
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 0))
                for address in ("192.0.2.10", "192.0.2.20")]

    monkeypatch.setattr(socket, "getaddrinfo", resolve)
    monkeypatch.setattr(sys, "argv", ["-", "60", str(path), "13.0.0.101", "11.0.0.254", endpoint])
    # Execute the embedded Python with a deterministic DNS resolver.
    program = SNIPPET.read_text().split("<<'PY'\n", 1)[1].rsplit("\nPY", 1)[0]
    if resolves:
        exec(compile(program, str(SNIPPET), "exec"), {})
        script = rendered_script(path)
        assert "192.0.2.10/32" in script and "192.0.2.20/32" in script
        assert "allowed.example" not in script
        if endpoint.endswith("11434-11436"):
            assert "--to-destination 192.0.2.10:11436" in script
            assert "--to-destination 192.0.2.20:11436" in script
    else:
        with pytest.raises(SystemExit, match="Cannot resolve"):
            exec(compile(program, str(SNIPPET), "exec"), {})
        assert path.read_text() == BASE_XML
        assert not Path(str(path) + ".bak").exists()
