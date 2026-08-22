from scenarioforge.planning.ai_topology_intent import apply_compiled_sections_to_scenario
from scenarioforge.planning.ai_topology_intent import compile_ai_topology_intent
from scenarioforge.planning.ai_topology_intent import extract_vulnerability_target_count


def _scenario_payload(name='IntentScenario'):
    return {
        'name': name,
        'sections': {
            'Node Information': {'density': 0, 'total_nodes': 0, 'items': []},
            'Routing': {'density': 0.0, 'items': []},
            'Services': {'density': 0.0, 'items': []},
            'Traffic': {'density': 0.0, 'items': []},
            'Vulnerabilities': {'density': 0.0, 'items': [], 'flag_type': 'text'},
            'Segmentation': {'density': 0.0, 'items': []},
        },
        'notes': '',
    }


def test_compile_ai_topology_intent_seeds_router_and_host_counts():
    compiled = compile_ai_topology_intent(
        'Create a topology with 30 nodes, 8 routers with low router-to-router link ratio, and 4 servers.'
    )

    assert compiled.locked_sections == ('Routing', 'Node Information')
    assert compiled.applied_actions == ['Routing routers=8', 'Node Server=4', 'Node PC=18']

    routing = compiled.section_payloads['Routing']
    assert routing['items'][0]['selected'] == 'OSPFv2'
    assert routing['items'][0]['v_count'] == 8
    assert routing['items'][0]['r2r_mode'] == 'Min'

    node_info = compiled.section_payloads['Node Information']
    assert node_info['total_nodes'] == 22
    assert node_info['items'][0]['selected'] == 'Server'
    assert node_info['items'][0]['v_count'] == 4
    assert node_info['items'][1]['selected'] == 'PC'
    assert node_info['items'][1]['v_count'] == 18


def test_apply_compiled_sections_to_scenario_overrides_llm_node_and_routing_rows():
    compiled = compile_ai_topology_intent('Create a network with 12 nodes and 3 routers.')
    scenario = _scenario_payload()
    scenario['sections']['Node Information']['items'] = [
        {'selected': 'Server', 'v_metric': 'Count', 'v_count': 99, 'factor': 1.0},
    ]
    scenario['sections']['Routing']['items'] = [
        {'selected': 'BGP', 'v_metric': 'Count', 'v_count': 99, 'factor': 1.0},
    ]

    merged = apply_compiled_sections_to_scenario(scenario, compiled)

    node_items = merged['sections']['Node Information']['items']
    routing_items = merged['sections']['Routing']['items']
    assert node_items == [
        {'selected': 'PC', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 9},
    ]
    assert routing_items == [
        {'selected': 'OSPFv2', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 3},
    ]


def test_compile_ai_topology_intent_also_compiles_services_and_traffic_rows():
    compiled = compile_ai_topology_intent(
        'create a network with 10 nodes, 2 routers, two ssh and one web service, plus two tcp and one udp flows, and two periodic and one burst flows'
    )

    assert compiled.locked_sections == ('Routing', 'Node Information', 'Services', 'Traffic')
    assert compiled.section_payloads['Services']['items'] == [
        {'selected': 'SSH', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 2},
        {'selected': 'HTTP', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 1},
    ]
    assert compiled.section_payloads['Traffic']['items'] == [
        {'selected': 'TCP', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 2, 'pattern': 'periodic', 'content_type': 'text'},
        {'selected': 'UDP', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 1, 'pattern': 'burst', 'content_type': 'text'},
    ]


def test_compile_ai_topology_intent_reserves_vulnerability_slots_inside_total_node_budget():
    """Planner-additive vulnerability nodes still consume an explicit total."""
    compiled = compile_ai_topology_intent(
        'Create a network with 12 nodes, 3 routers, and 2 web vulnerabilities.',
        vuln_catalog=[
            {'Name': 'appweb/CVE-2018-8715', 'Path': '/catalog/appweb/CVE-2018-8715/docker-compose.yml', 'Description': 'Web server vulnerability'},
            {'Name': 'jboss/CVE-2017-12149', 'Path': '/catalog/jboss/CVE-2017-12149/docker-compose.yml', 'Description': 'JBoss Java deserialization'},
        ],
    )

    node_items = compiled.section_payloads['Node Information']['items']
    vuln_items = compiled.section_payloads['Vulnerabilities']['items']

    assert compiled.locked_sections == ('Routing', 'Node Information', 'Vulnerabilities')
    # 12 total - 3 routers - 2 planner-added vulnerability nodes = 7 PCs.
    assert node_items == [
        {'selected': 'PC', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 7},
    ]
    assert vuln_items == [
        {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'appweb/CVE-2018-8715', 'v_path': '/catalog/appweb/CVE-2018-8715/docker-compose.yml'},
        {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'jboss/CVE-2017-12149', 'v_path': '/catalog/jboss/CVE-2017-12149/docker-compose.yml'},
    ]


def test_compile_ai_topology_intent_supports_word_counts_for_servers_and_vulnerable_docker_targets():
    compiled = compile_ai_topology_intent(
        'Generate two servers and three vulnerable docker targets.',
        vuln_catalog=[
            {'Name': 'Demo Vuln', 'Path': 'demo/path', 'Description': 'Demo desc'},
        ],
    )

    assert compiled.section_payloads['Node Information']['items'] == [
        {'selected': 'Server', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 2},
        {'selected': 'Docker', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 3},
    ]
    assert compiled.section_payloads['Vulnerabilities']['items'] == [
        {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'Demo Vuln', 'v_path': 'demo/path'},
        {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'Demo Vuln', 'v_path': 'demo/path'},
        {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'Demo Vuln', 'v_path': 'demo/path'},
    ]


def test_compile_ai_topology_intent_compiles_segmentation_counts():
    compiled = compile_ai_topology_intent(
        'Create a network with 2 firewall segments and 1 nat segment.'
    )

    assert compiled.locked_sections == ('Segmentation',)
    assert compiled.section_payloads['Segmentation']['items'] == [
        {'selected': 'Firewall', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 2},
        {'selected': 'NAT', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 1},
    ]


def test_compile_ai_topology_intent_compiles_listed_vulnerability_requests_as_multiple_targets():
    prompt = 'create a topology with 3 docker nodes and 20 total nodes. Use RIP for routing and include about 4 routers. Also, add sql injection, web, and another random vulnerability.'
    compiled = compile_ai_topology_intent(
        prompt,
        vuln_catalog=[
            {'Name': 'aaa/random-demo', 'Path': '/catalog/aaa/random-demo/docker-compose.yml', 'Description': 'Generic demo vulnerability'},
            {'Name': 'appweb/CVE-2018-8715', 'Path': '/catalog/appweb/CVE-2018-8715/docker-compose.yml', 'Description': 'Web server vulnerability'},
            {'Name': 'sqli-labs/demo', 'Path': '/catalog/sqli-labs/demo/docker-compose.yml', 'Description': 'SQL injection training app'},
        ],
    )

    assert extract_vulnerability_target_count(prompt) == 3
    assert compiled.intent.vulnerability_target_count == 3
    assert compiled.locked_sections == ('Routing', 'Node Information', 'Vulnerabilities')
    assert compiled.section_payloads['Routing']['items'] == [
        {'selected': 'RIP', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 4},
    ]
    assert compiled.section_payloads['Node Information']['items'] == [
        {'selected': 'PC', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 10},
        {'selected': 'Docker', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 3},
    ]
    assert compiled.section_payloads['Vulnerabilities']['items'] == [
        {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'sqli-labs/demo', 'v_path': '/catalog/sqli-labs/demo/docker-compose.yml'},
        {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'appweb/CVE-2018-8715', 'v_path': '/catalog/appweb/CVE-2018-8715/docker-compose.yml'},
        {'selected': 'Specific', 'v_metric': 'Count', 'v_count': 1, 'v_name': 'aaa/random-demo', 'v_path': '/catalog/aaa/random-demo/docker-compose.yml'},
    ]


def test_compile_ai_topology_intent_treats_vulnerable_hosts_as_subset_of_host_count():
    compiled = compile_ai_topology_intent(
        'two routers and five hosts where two hosts run vulnerable services',
        vuln_catalog=[
            {'Name': 'demo/one', 'Path': '/catalog/demo/one/docker-compose.yml'},
            {'Name': 'demo/two', 'Path': '/catalog/demo/two/docker-compose.yml'},
        ],
    )

    assert compiled.section_payloads['Routing']['items'][0]['v_count'] == 2
    assert compiled.section_payloads['Node Information']['items'] == [
        {'selected': 'PC', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 3},
    ]
    assert len(compiled.section_payloads['Vulnerabilities']['items']) == 2


def test_compile_ai_topology_intent_preserves_unquantified_services_and_segmentation():
    compiled = compile_ai_topology_intent(
        'four routers and ten hosts running SSH and HTTP with a firewalled DMZ and a NAT gateway'
    )

    assert compiled.section_payloads['Services']['items'] == [
        {'selected': 'SSH', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 10},
        {'selected': 'HTTP', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 10},
    ]
    assert compiled.section_payloads['Segmentation']['items'] == [
        {'selected': 'Firewall', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 1},
        {'selected': 'NAT', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 1},
    ]


def test_compile_ai_topology_intent_keeps_https_distinct_and_seeds_background_traffic():
    compiled = compile_ai_topology_intent(
        'four routers and ten hosts running HTTP and HTTPS with background traffic'
    )

    assert compiled.section_payloads['Services']['items'] == [
        {'selected': 'HTTP', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 10},
        {'selected': 'HTTPS', 'factor': 1.0, 'v_metric': 'Count', 'v_count': 10},
    ]
    assert compiled.section_payloads['Traffic']['items'] == [
        {
            'selected': 'TCP',
            'factor': 1.0,
            'v_metric': 'Count',
            'v_count': 1,
            'pattern': 'continuous',
            'content_type': 'text',
        },
    ]
def test_flag_node_generator_count_handles_plural_and_descriptor_prompts():
    from scenarioforge.planning.ai_topology_intent import extract_ai_topology_intent

    def count(prompt):
        return extract_ai_topology_intent(prompt).flag_node_generator_target_count

    assert count('add a flag node generator') == 1
    # Plural with no count used to fall through to 0 and seed nothing.
    assert count('add flag node generators') == 1
    assert count('add two ssh flag node generators') == 2
    assert count('add 3 routers and 2 flag node generators') == 2
    # A count that belongs to another section must not be borrowed.
    assert count('4 routers and a flag node generator') == 1
    assert count('create a scenario with 4 routers') == 0


def test_extract_flag_node_generator_query_hint_only_fires_on_descriptions():
    from scenarioforge.planning.ai_topology_intent import extract_flag_node_generator_query_hint as hint

    assert hint('add a flag node generator that leaks an ssh key') == 'leaks an ssh key'
    assert hint('add a flag node generator for a database challenge') == 'database challenge'
    assert hint('make an nfs flag node generator') == 'nfs'
    assert hint('add two ssh flag node generators') == 'ssh'
    # Undescribed requests stay Random rather than inventing a query.
    assert hint('add 3 flag node generators') == ''
    assert hint('add a random flag node generator') == ''
    assert hint('add 3 routers and 2 flag node generators') == ''
    assert hint('create a scenario with 4 routers') == ''


def test_search_flag_node_generator_catalog_for_prompt_ranks_by_name_and_description():
    from scenarioforge.planning.ai_topology_intent import search_flag_node_generator_catalog_for_prompt as search

    catalog = [
        {
            'id': 'ssh_key_bastion',
            'name': 'SSH: Key Bastion',
            'description': 'Key-only SSH bastion.',
            'outputs': [{'name': 'Flag(flag_id)'}],
        },
        {
            'id': 'nfs_share',
            'name': 'NFS: Build Cache Share',
            'description': 'Exported build cache share.',
            'outputs': [{'name': 'Directory(host, path)'}],
        },
        {'id': '', 'name': 'Broken entry', 'description': 'no id'},
    ]

    assert search('ssh key', catalog=catalog) == [{'id': 'ssh_key_bastion', 'name': 'SSH: Key Bastion'}]
    assert [entry['id'] for entry in search('share', catalog=catalog)] == ['nfs_share']
    assert search('postgres', catalog=catalog) == []
    assert search('ssh', catalog=[]) == []
    assert search('', catalog=catalog) == []
