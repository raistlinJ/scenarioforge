# CORE router uplink for SCE-web

Dr. Jaime C. Acosta

Push `setup_llm_proxy-v2.sh` to the CORE VM and run it as root **before starting
the CORE scenario**. It edits the scenario XML and the selected router's
IPForward startup service. Routing, NAT and firewall rules run inside that
router when CORE starts the scenario.

For a script uploaded to `/home/corevm/setup_llm_proxy-v2.sh`, use this SCE-web
startup, stored or custom command with **Render template variables** enabled:

```bash
bash /home/corevm/setup_llm_proxy-v2.sh \
  --instance-index "{{instance_index}}" \
  --scenario-xml /root/myscenario.xml \
  --router-node n3 \
  --external-interface eth1 \
  --internal-ip 13.0.0.101 \
  --uplink-gateway 11.0.0.254 \
  --external-addresses \
    100.100.100.100:8080:129.108.156.63:11434-11436 \
    100.100.100.101:443:129.108.4.46:443-443
```

Replace the router name, interface, internal host, gateway and external endpoints
as needed. A numeric router node ID also works. SCE-web renders the command text;
pass the index explicitly when invoking an uploaded file. In a terminal without
SCE-web, replace `{{instance_index}}` with the actual instance number.

Each external endpoint specifies all four fields, separated by colons:

```text
TRANSLATED_IP:TRANSLATED_PORT:REAL_EXTERNAL_IP:REAL_PORT_RANGE
```

The translated IP and port are the address students use. The real IP and selected
real port are the destination after TCP destination NAT. Each entry has its own
translated endpoint; multiple virtual IPs and multiple ports on one virtual IP
are supported. Identical entries are deduplicated. Two different destinations
for the same translated IP and port are rejected before writing.

For instance **68**, the example produces:

| Student endpoint | Real destination |
| --- | --- |
| `100.100.100.100:8080` | `129.108.156.63:11435` |
| `100.100.100.101:443` | `129.108.4.46:443` |

Students use `http://100.100.100.100:8080/v1` for the model API and
`https://100.100.100.101/` for the other server. A range is inclusive and must be
ascending within 1–65535. Port selection is
`START + ((instance_index - 1) % (END - START + 1))`.
For 11434–11436, instances 1, 2, 3 and 4 select 11434, 11435, 11436 and 11434.
Use `443-443` or just `443` for a fixed real port. The translated port is always
one port, rather than a range. The translated IP must be a unicast IPv4 literal;
the real destination can also be a hostname resolving to exactly one IPv4 address.

This format adds only the specified translated endpoints, without an automatic
LLM alias or direct backend access. Requests to real IPs and other ports are
blocked unless separately permitted. Only TCP connections from the authorized
internal host and their established replies are allowed through the external
interface. Source NAT uses the router uplink IP, `11.0.0.68` for instance 68;
connection tracking reverses both translations for replies.

Traffic for each translated IP must reach this router from the student VM,
including through intermediate lab routers. This script adds real-server host
routes on the proxy router; it does not install routes on the student VM or
advertise virtual prefixes through the lab routing protocol. It translates
outgoing student requests, rather than inbound connections to a student listener.

The same endpoint list works in the environment:

```bash
EXTERNAL_ADDRESSES='100.100.100.100:8080:129.108.156.63:11434-11436 100.100.100.101:443:129.108.4.46:443-443' \
bash /home/corevm/setup_llm_proxy-v2.sh \
  --instance-index "{{instance_index}}" \
  --scenario-xml /root/myscenario.xml \
  --router-node n3 \
  --external-interface eth1 \
  --internal-ip 13.0.0.101 \
  --uplink-gateway 11.0.0.254
```

| Option | Meaning | Environment fallback / default |
| --- | --- | --- |
| `--instance-index N` | Index 1–253; derives uplink IP, MAC and backend port selection | `INSTANCE_INDEX`, then inline SCE-web placeholder |
| `--scenario-xml PATH` | Scenario XML to update | `SCENARIO_XML`, then `/root/myscenario.xml` |
| `--router-node ID_OR_NAME` | Router whose interface and IPForward service are updated | `ROUTER_NODE`, then auto-detect |
| `--external-interface NAME` | External interface on that router | `EXTERNAL_INTERFACE`, then `eth1` |
| `--internal-ip IP` | Internal host permitted through the uplink | `INTERNAL_IP`, then `13.0.0.101` |
| `--uplink-gateway IP` or `--gateway IP` | Uplink next hop | `UPLINK_GATEWAY`, then `11.0.0.254` |
| `--external-addresses ENDPOINT ...` | Allowed endpoints and TCP port rules; may be repeated | `EXTERNAL_ADDRESSES` |
| `--virtual-llm IP` | Legacy model alias; unused by four-field entries | `VIRTUAL_LLM`, then `100.100.100.100` |
| `--llm-address IP` | Legacy alias backend; unused by four-field entries | `LLM_ADDRESS`, then `129.108.156.63` |
| `--help` | Show usage without reading or editing XML | |

Options override environment values. `--external-addresses` replaces
`EXTERNAL_ADDRESSES`; quoted whitespace-separated lists and repeated flags work.
Legacy positional endpoints append to the list. Reapply and reload the scenario
after changing entries so students get the new mapping.

Older formats remain available for compatibility:

| Older format | Behavior |
| --- | --- |
| `IP:CLIENT_PORT:START-END` | Translate the port on that same real IP; the selected legacy LLM also gets its configured virtual alias |
| `IP:START-END` or `IP:PORT` | Direct TCP access to the range or single port |
| `IP` | Direct access to all ports/protocols on that destination |

For older three-field entries, `--llm-address` / `LLM_ADDRESS` chooses the backend
for the automatic alias and `--virtual-llm` / `VIRTUAL_LLM` sets that alias's IP.
Those options do not add aliases to four-field entries. Hostnames in older forms
can resolve to multiple IPv4 addresses. Conflicting or shadowed frontend rules,
and mixing bare-IP access with older port-specific forms for the same IP, are
rejected before writing. Explicit direct permissions can separately permit a
real backend when required.

The older global `--dest-port` / `DEST_PORT`, `--conversion-base-port` /
`CONVERSION_BASE_PORT` and `--backend-port-count` / `BACKEND_PORT_COUNT` options
remain supported only with bare-IP entries. Their aliases are `--virtual-port` /
`VIRTUAL_PORT` and `--llm-base-port` / `LLM_BASE_PORT`. Setting either global port
enables the old virtual-only mapping, with defaults 8080, 11434 and count 3;
bare-IP direct access stays unrestricted in that mode. Do not combine global
port settings with per-entry port settings. Unset stale global port environment
variables when using the four-field format.

Destinations must be individual IPv4 addresses or hostnames, without URLs, CIDRs
or IPv6. Hostnames resolve on the CORE VM at configuration time; rerun to refresh
their addresses. Other forwarding through the selected external interface is
blocked, including IPv6. DNS, redirects and additional CDN destinations need
their own permitted endpoints. The script installs only external host routes;
other lab routing remains governed by the existing routing configuration.

Only the selected interface's IPv4 and MAC are replaced with
`11.0.0.<instance-index>` and `00:00:00:aa:00:<index-in-hex>`. Its subnet mask,
other interfaces, and other nodes' addresses/services are preserved. Identical
copies in directional link records are all updated; conflicting interface
copies are rejected with their attributes. Without `--router-node`, detection
requires exactly one router interface with the selected name and the original
IP/MAC (`11.0.0.2` / `00:00:00:aa:00:00`) or current instance values.

The script validates before writing, preserves existing IPForward service
settings (including exported startup commands, files and executables) and
template content, and saves the prior XML as `<scenario-xml>.bak`. That backup is
overwritten on each successful run. Specify `--router-node` when changing the
instance index on a rerun. Existing generated rules are replaced. If CORE is
running, stop it and reload the updated XML to apply the new startup configuration.
Other scenario services must not subsequently override these firewall rules.

`core-router-uplink-sce-web.sh` is the original IP/MAC substitution snippet;
these options and firewall settings belong to `setup_llm_proxy-v2.sh`.
