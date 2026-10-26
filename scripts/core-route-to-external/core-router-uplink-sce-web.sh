#!/usr/bin/env bash
# Dr. Jaime C. Acosta
# Paste this snippet into an SCE-web startup or stored command for the CORE VM.
# Enable "Render template variables" and run before starting the CORE scenario.
# SCE-web supplies only instance_index; this snippet calculates the addresses.
# IP uses the decimal index; the MAC's final byte uses its hexadecimal value.
# Example: instance 60 -> 11.0.0.60 and 00:00:00:aa:00:3c.
# Replaces every matching occurrence of the original uplink IP/MAC in the XML.
# Saves the previous XML as /root/myscenario.xml.bak (overwritten on each run).
# To change an assignment later, first restore a copy of the original scenario.
set -eu

instance_index="{{instance_index}}"
case "$instance_index" in
  ''|*[!0-9]*) echo 'Enable Render template variables in SCE-web.' >&2; exit 1 ;;
esac
# Reserve .254 for the gateway; exclude the network and broadcast addresses.
if [ "$instance_index" -lt 1 ] || [ "$instance_index" -gt 253 ]; then
  echo 'This address scheme requires an instance index between 1 and 253.' >&2
  exit 1
fi

router_ip="11.0.0.${instance_index}"
router_mac="$(printf '00:00:00:aa:00:%02x' "$instance_index")"

sed -E -i.bak \
  -e "s#(^|[^0-9.])11[.]0[.]0[.]2([^0-9.]|$)#\1${router_ip}\2#g" \
  -e "s/00:00:00:aa:00:00/${router_mac}/g" \
  /root/myscenario.xml

printf 'Router uplink: %s, MAC %s\n' "$router_ip" "$router_mac"
