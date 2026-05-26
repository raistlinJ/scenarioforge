from __future__ import annotations
from pathlib import Path

from scenarioforge.parsers.hitl import parse_hitl_info


def test_parse_hitl_info_handles_interfaces(tmp_path: Path) -> None:
    xml_content = """
    <Scenarios>
      <Scenario name="Demo">
        <ScenarioEditor>
          <HardwareInLoop enabled="true">
            <Interface name="en0" alias="ethernet" mac="aa:bb:cc:dd:ee:ff" ipv4="10.0.0.1/24, 10.0.0.2/24" ipv6="fe80::1" />
            <Interface name=" usb 0 " />
            <Interface name="hitl-router-ens19-hitl0" />
          </HardwareInLoop>
        </ScenarioEditor>
      </Scenario>
    </Scenarios>
    """
    xml_path = tmp_path / "scenario.xml"
    xml_path.write_text(xml_content, encoding="utf-8")

    info = parse_hitl_info(str(xml_path), "Demo")

    assert info["enabled"] is True
    assert len(info["interfaces"]) == 3
    first = info["interfaces"][0]
    assert first["name"] == "en0"
    assert first["alias"] == "ethernet"
    assert first["mac"] == "aa:bb:cc:dd:ee:ff"
    assert first["ipv4"] == ["10.0.0.1/24", "10.0.0.2/24"]
    assert first["ipv6"] == ["fe80::1"]
    assert first["attachment"] == "existing_router"

    second = info["interfaces"][1]
    assert second["attachment"] == "existing_router"

    third = info["interfaces"][2]
    assert third["name"] == "ens19"
    assert third["attachment"] == "existing_router"


def test_parse_hitl_info_preserves_vm_metadata(tmp_path: Path) -> None:
    xml_content = """
    <Scenarios>
      <Scenario name="Demo">
        <ScenarioEditor>
          <HardwareInLoop enabled="true">
            <Interface
              name="net0"
              core_bridge="vmbr-core"
              pve_node="pve1"
              pve_vmid="101"
              pve_interface_id="net0"
              pve_macaddr="aa:bb:cc:dd:ee:ff"
              pve_bridge="vmbr-core"
              ext_vm_key="pve2::202"
              ext_vmid="202"
              ext_interface_id="net1"
            />
          </HardwareInLoop>
        </ScenarioEditor>
      </Scenario>
    </Scenarios>
    """
    xml_path = tmp_path / "scenario.xml"
    xml_path.write_text(xml_content, encoding="utf-8")

    info = parse_hitl_info(str(xml_path), "Demo")

    iface = info["interfaces"][0]
    assert iface["name"] == "net0"
    assert iface["core_bridge"] == "vmbr-core"
    assert iface["proxmox_target"]["interface_id"] == "net0"
    assert iface["proxmox_target"]["bridge"] == "vmbr-core"
    assert iface["external_vm"]["vm_key"] == "pve2::202"
    assert iface["external_vm"]["interface_id"] == "net1"
