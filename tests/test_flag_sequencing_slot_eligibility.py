"""Flag-sequencing eligibility must recognize challenge slots.

Challenge slots are Docker-backed hosts under their own role name. Counting only
the literal 'Docker' role made a slot-only topology look like it had no container
capacity at all, producing "Topology must include Docker or vulnerability nodes."
"""

from __future__ import annotations

from scenarioforge.planning.node_plan import challenge_slot_kind, is_docker_backed_role


def _counts(hosts):
    """Mirror the eligibility counting the routes perform."""
    docker_count = 0
    nodegen_targets = 0
    for host in hosts:
        role = str(host.get('role') or '').strip()
        vulns = host.get('vulnerabilities') or []
        if is_docker_backed_role(role):
            docker_count += 1
            if not vulns and challenge_slot_kind(role) != 'vulnerability':
                nodegen_targets += 1
    return docker_count, nodegen_targets


def test_flag_gen_slot_only_topology_is_eligible() -> None:
    """The reported failure: a topology of FlagGenSlot hosts and nothing else."""
    docker_count, nodegen_targets = _counts([
        {'role': 'FlagGenSlot'}, {'role': 'FlagGenSlot'}, {'role': 'PC'},
    ])
    assert docker_count == 2
    assert nodegen_targets == 2


def test_vulnerability_slot_counts_as_capacity_but_not_as_a_nodegen_target() -> None:
    """It is Docker-backed, yet only ever takes a vulnerability."""
    docker_count, nodegen_targets = _counts([{'role': 'VulnerabilitySlot'}])
    assert docker_count == 1
    assert nodegen_targets == 0


def test_plain_docker_still_counts_for_both() -> None:
    docker_count, nodegen_targets = _counts([{'role': 'Docker'}])
    assert docker_count == 1
    assert nodegen_targets == 1


def test_a_vuln_bearing_host_is_not_a_nodegen_target() -> None:
    docker_count, nodegen_targets = _counts([{'role': 'Docker', 'vulnerabilities': ['CVE-1']}])
    assert docker_count == 1
    assert nodegen_targets == 0


def test_non_container_roles_never_count() -> None:
    docker_count, nodegen_targets = _counts([{'role': 'PC'}, {'role': 'Server'}, {'role': 'Workstation'}])
    assert docker_count == 0
    assert nodegen_targets == 0


def test_role_counts_summing_includes_slots() -> None:
    """role_counts is used when the host list is empty."""
    role_counts = {'Docker': 1, 'FlagGenSlot': 2, 'VulnerabilitySlot': 3, 'PC': 4}
    total = sum(
        max(0, int(count or 0))
        for role_name, count in role_counts.items()
        if is_docker_backed_role(role_name)
    )
    assert total == 6
