"""Resolve the participant next-hop independently of the CORE HITL interface IP."""
import ipaddress
import sys


def resolve(core_cidr, participant_cidr, requested=''):
    core = ipaddress.IPv4Interface(core_cidr)
    participant = ipaddress.IPv4Interface(participant_cidr)
    if core.network != participant.network:
        raise ValueError('CORE HITL and participant addresses must share a subnet')
    # Match the existing-router address allocated by ScenarioForge HITL: the
    # first usable host other than the configured RJ45/interface address.
    gateway = ipaddress.IPv4Address(requested) if requested else next(
        (host for host in core.network.hosts() if host != core.ip), None)
    if (gateway is None or gateway not in participant.network or
            gateway in (participant.ip, core.ip, participant.network.network_address,
                        participant.network.broadcast_address) or
            gateway.is_unspecified or gateway.is_multicast or gateway.is_loopback):
        raise ValueError('Participant gateway must be a distinct usable IPv4 router address in the HITL subnet')
    return str(gateway)


if __name__ == '__main__':
    try:
        print(resolve(*sys.argv[1:]))
    except (ValueError, TypeError) as error:
        raise SystemExit(str(error))
