"""The Flag Sequencing summary splits challenge capacity into five buckets.

Two come from the section cards ("Specified ..."), three are free capacity
declared in Node Information ("... slots"). They must partition the
Docker-backed hosts, because the summary presents their sum as "Max challenges"
and the chain-length spinner uses the same total as its maximum.

The distinction that used to be missing: a FlagGenSlot or VulnerabilitySlot host
was reported under "Docker slots", which is only meant to describe a plain
Docker node -- the one kind of host that can take either challenge type.
"""

from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[1]
FLOW_TEMPLATE_PATH = REPO_ROOT / 'webapp' / 'templates' / 'flow.html'

BUCKET_KEYS = (
    'specified_flag_node_generator_total',
    'specified_vulnerability_total',
    'flag_gen_slot_total',
    'vulnerability_slot_total',
    'docker_slot_total',
)


def _stats(nodes):
    from webapp import app_backend as backend

    return backend._flow_compose_docker_stats(nodes)


def _docker_node(name, *, role=None, slot_kind=None, generator_id='', vulns=None):
    node = {'id': name, 'name': name, 'type': 'docker'}
    if role:
        node['role'] = role
    if slot_kind:
        node['challenge_slot_kind'] = slot_kind
    if generator_id:
        node['flag_node_generator_id'] = generator_id
    if vulns:
        node['vulnerabilities'] = list(vulns)
    return node


def test_declared_slots_are_not_reported_as_docker_slots() -> None:
    """A slot is reserved for one challenge kind; a Docker node takes either."""
    nodes = [
        _docker_node('flaggenslot-1', role='FlagGenSlot', slot_kind='flag-node-generator'),
        _docker_node('vulnslot-1', role='VulnerabilitySlot', slot_kind='vulnerability'),
        _docker_node('docker-1'),
    ]
    stats = _stats(nodes)

    assert stats['flag_gen_slot_total'] == 1
    assert stats['vulnerability_slot_total'] == 1
    assert stats['docker_slot_total'] == 1, (
        'only a plain Docker node belongs in the Docker slots bucket'
    )


def test_card_placed_hosts_are_reported_as_specified() -> None:
    nodes = [
        _docker_node('docker-1', generator_id='alpha'),
        _docker_node('docker-2', vulns=['cve/one']),
        _docker_node('docker-3'),
    ]
    stats = _stats(nodes)

    assert stats['specified_flag_node_generator_total'] == 1
    assert stats['specified_vulnerability_total'] == 1
    assert stats['docker_slot_total'] == 1


def test_a_generator_host_carrying_a_vulnerability_is_counted_once() -> None:
    """The buckets must stay disjoint or the sum overshoots Max challenges."""
    nodes = [_docker_node('docker-1', generator_id='alpha', vulns=['cve/one'])]
    stats = _stats(nodes)

    assert stats['specified_flag_node_generator_total'] == 1
    assert stats['specified_vulnerability_total'] == 0
    assert sum(stats[key] for key in BUCKET_KEYS) == 1


def test_a_filled_slot_stays_in_its_slot_bucket() -> None:
    """Classification follows where a host came from, not what now sits on it.

    Otherwise a slot would migrate between buckets as the plan resolves.
    """
    nodes = [
        _docker_node('vulnslot-1', role='VulnerabilitySlot',
                     slot_kind='vulnerability', vulns=['cve/one']),
        _docker_node('flaggenslot-1', role='FlagGenSlot',
                     slot_kind='flag-node-generator', generator_id='alpha'),
    ]
    stats = _stats(nodes)

    assert stats['vulnerability_slot_total'] == 1
    assert stats['flag_gen_slot_total'] == 1
    assert stats['specified_vulnerability_total'] == 0
    assert stats['specified_flag_node_generator_total'] == 0


def test_buckets_partition_every_docker_backed_host() -> None:
    nodes = [
        _docker_node('flaggenslot-1', role='FlagGenSlot', slot_kind='flag-node-generator'),
        _docker_node('flaggenslot-2', role='FlagGenSlot', slot_kind='flag-node-generator'),
        _docker_node('vulnslot-1', role='VulnerabilitySlot', slot_kind='vulnerability'),
        _docker_node('docker-1', generator_id='alpha'),
        _docker_node('docker-2', vulns=['cve/one']),
        _docker_node('docker-3'),
        {'id': 'router-1', 'name': 'router-1', 'type': 'router'},
    ]
    stats = _stats(nodes)

    assert sum(stats[key] for key in BUCKET_KEYS) == stats['docker_total'] == 6


def test_flow_summary_ui_reports_all_five_buckets() -> None:
    text = FLOW_TEMPLATE_PATH.read_text(encoding='utf-8', errors='ignore')

    for label in (
        'Specified Flag-node-generators:',
        'Specified vulnerabilities:',
        'Flag-node-generator slots:',
        'Vulnerability slots:',
        'Docker slots:',
    ):
        assert label in text, f'Flow summary is missing the {label!r} row'

    for key in BUCKET_KEYS:
        assert key in text, f'Flow summary does not read {key}'

    # Max challenges must be the sum of the buckets, not a stale subset.
    assert 'const maxChallenges = specifiedFlagNodeGenerators + specifiedVulnerabilities' in text
