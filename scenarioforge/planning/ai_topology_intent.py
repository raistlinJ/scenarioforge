from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass
import re
from typing import Any
from .node_plan import HOST_ROLE_DISPLAY_ORDER


_LOW_R2R_PATTERNS: tuple[str, ...] = (
    r'\blow\s+router(?:-to-router|\s+to\s+router)\s+link\s+ratio\b',
    r'\blow\s+r2r\b',
    r'\bminimal\s+router(?:-to-router|\s+to\s+router)\b',
    r'\bsparse\s+router(?:-to-router|\s+to\s+router)\b',
)

_HIGH_R2R_PATTERNS: tuple[str, ...] = (
    r'\bhigh\s+router(?:-to-router|\s+to\s+router)\s+link\s+ratio\b',
    r'\bdense\s+router(?:-to-router|\s+to\s+router)\b',
    r'\bmesh(?:ed)?\s+routers?\b',
    r'\bhigh\s+r2r\b',
)

_COUNT_WORDS: dict[str, int] = {
    'a': 1,
    'an': 1,
    'one': 1,
    'two': 2,
    'three': 3,
    'four': 4,
    'five': 5,
    'six': 6,
    'seven': 7,
    'eight': 8,
    'nine': 9,
    'ten': 10,
    'eleven': 11,
    'twelve': 12,
    'thirteen': 13,
    'fourteen': 14,
    'fifteen': 15,
    'sixteen': 16,
    'seventeen': 17,
    'eighteen': 18,
    'nineteen': 19,
    'twenty': 20,
    'pair of': 2,
    'a pair of': 2,
    'couple of': 2,
    'a couple of': 2,
}

_COUNT_TOKEN_PATTERN = r'\d+|a\s+pair\s+of|pair\s+of|a\s+couple\s+of|couple\s+of|an?|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|thirteen|fourteen|fifteen|sixteen|seventeen|eighteen|nineteen|twenty'

_ROLE_PATTERNS: tuple[tuple[str, str], ...] = (
    ('Server', rf'\b({_COUNT_TOKEN_PATTERN})\s+servers?\b'),
    ('Workstation', rf'\b({_COUNT_TOKEN_PATTERN})\s+workstations?\b|\b({_COUNT_TOKEN_PATTERN})\s+desktops?\b'),
    ('PC', rf'\b({_COUNT_TOKEN_PATTERN})\s+pcs?\b|\b({_COUNT_TOKEN_PATTERN})\s+clients?\b|\b({_COUNT_TOKEN_PATTERN})\s+hosts?\b'),
    ('Docker', rf'\b({_COUNT_TOKEN_PATTERN})\s+vulnerable\s+docker\s+(?:targets?|hosts?|nodes?|containers?)\b|\b({_COUNT_TOKEN_PATTERN})\s+docker\s+(?:targets?|hosts?|nodes?|containers?)\b|\b({_COUNT_TOKEN_PATTERN})\s+containers?\b'),
)


@dataclass(frozen=True)
class AiTopologyIntent:
    total_nodes: int | None
    router_count: int | None
    derived_host_count: int | None
    node_role_counts: dict[str, int]
    service_counts: dict[str, int]
    traffic_rows: list[dict[str, Any]]
    segmentation_counts: dict[str, int]
    vulnerability_target_count: int
    r2r_density: str
    flag_node_generator_target_count: int = 0


@dataclass(frozen=True)
class CompiledAiTopologyIntent:
    intent: AiTopologyIntent
    section_payloads: dict[str, dict[str, Any]]
    tool_seed_ops: list[dict[str, Any]]
    applied_actions: list[str]
    locked_sections: tuple[str, ...]

    @property
    def has_seed(self) -> bool:
        return bool(self.section_payloads)


def _extract_count_intent(user_prompt: str) -> dict[str, int]:
    text = str(user_prompt or '').strip().lower()
    if not text:
        return {}

    count_intent: dict[str, int] = {}

    count_token = rf'({_COUNT_TOKEN_PATTERN})'
    total_nodes_match = re.search(rf'\b(?:topology|scenario|network)\s+with\s+{count_token}\s+nodes?\b', text)
    if not total_nodes_match:
        total_nodes_match = re.search(rf'\b{count_token}\s+total\s+nodes?\b', text)
    if not total_nodes_match:
        total_nodes_match = re.search(rf'\b{count_token}\s+nodes?\b', text)
    if total_nodes_match:
        parsed = _parse_count_token(total_nodes_match.group(1))
        if parsed is not None:
            count_intent['total_nodes'] = max(0, parsed)

    router_total = 0
    for router_match in re.finditer(rf'\b{count_token}\s+(?:[a-z][a-z0-9-]*\s+){{0,2}}routers?(?![a-z0-9-])', text):
        parsed = _parse_count_token(router_match.group(1))
        if parsed is not None:
            router_total += max(0, parsed)
    if router_total > 0:
        count_intent['router_count'] = router_total

    if count_intent.get('total_nodes') is not None and count_intent.get('router_count') is not None:
        count_intent['derived_host_count'] = max(0, count_intent['total_nodes'] - count_intent['router_count'])

    return count_intent


def _extract_vulnerability_target_count(user_prompt: str) -> int:
    text = str(user_prompt or '').strip().lower()
    if not text:
        return 0

    count_token = rf'({_COUNT_TOKEN_PATTERN})'
    target_patterns = (
        rf'\b{count_token}\s+(?:[a-z][a-z0-9-]*\s+){{0,3}}vulnerabilit(?:y|ies)\b',
        rf'\b{count_token}\s+vulnerable\s+(?:services?|applications?|apps?|targets?|hosts?|nodes?|containers?)\b',
        rf'\b{count_token}\s+(?:hosts?|nodes?|containers?)\s+(?:that\s+|which\s+)?(?:run|runs|running|host|hosts|hosting|with)\s+(?:an?\s+)?vulnerable\s+(?:[a-z][a-z0-9-]*\s+){{0,2}}(?:services?|applications?|apps?)\b',
        rf'\b{count_token}\s+of\s+them\s+(?:run|runs|running|host|hosts|hosting|with)\s+(?:an?\s+)?vulnerable\s+(?:[a-z][a-z0-9-]*\s+){{0,2}}(?:services?|applications?|apps?)\b',
    )
    for pattern in target_patterns:
        match = re.search(pattern, text)
        if not match:
            continue
        parsed = _parse_count_token(match.group(1))
        if parsed is not None:
            return max(0, parsed)

    docker_target_match = re.search(rf'\b({_COUNT_TOKEN_PATTERN})\s+vulnerable\s+docker\s+(?:targets?|hosts?|nodes?|containers?)\b', text)
    if docker_target_match:
        parsed = _parse_count_token(docker_target_match.group(1))
        return max(0, int(parsed or 0))

    listed_hints = extract_vulnerability_query_hints(text)
    if listed_hints:
        return len(listed_hints)

    if re.search(r'\bvulnerabilit(?:y|ies)\b|\bvulns?\b', text):
        return 1
    return 0


_FLAG_NODE_GENERATOR_PHRASE = r'(?:flag[-\s]+node[-\s]*generators?|node[-\s]+flag[-\s]*generators?)'

# Words that end the backwards scan for a count: a count before one of these
# belongs to that other section ("3 routers and a flag node generator" is 1).
_FLAG_NODE_GENERATOR_COUNT_BLOCKERS = {
    'and', 'or', 'with', 'plus', 'router', 'routers', 'host', 'hosts', 'node', 'nodes',
    'switch', 'switches', 'service', 'services', 'vulnerability', 'vulnerabilities', 'vuln', 'vulns',
}


def _extract_flag_node_generator_target_count(user_prompt: str) -> int:
    text = str(user_prompt or '').strip().lower().replace('_', '-')
    if not text:
        return 0
    match = re.search(rf'\b({_COUNT_TOKEN_PATTERN})\s+{_FLAG_NODE_GENERATOR_PHRASE}\b', text)
    if match:
        return max(0, int(_parse_count_token(match.group(1)) or 0))
    phrase_match = re.search(rf'\b{_FLAG_NODE_GENERATOR_PHRASE}\b', text)
    if not phrase_match:
        return 0
    # A descriptor can sit between the count and the phrase ("two ssh flag node generators").
    for word in reversed(text[:phrase_match.start()].split()[-3:]):
        if word in _FLAG_NODE_GENERATOR_COUNT_BLOCKERS:
            break
        parsed = _parse_count_token(word)
        if parsed is not None:
            return max(0, int(parsed))
    return 1


def extract_vulnerability_target_count(user_prompt: str) -> int:
    return _extract_vulnerability_target_count(user_prompt)


def extract_vulnerability_query_hints(user_prompt: str) -> list[str]:
    text = str(user_prompt or '').strip().lower()
    if not text:
        return []

    has_vulnerability_context = re.search(r'\bvulnerabilit(?:y|ies)\b|\bvulns?\b', text)
    has_explicit_vulnerability_signal = re.search(r'\bsql\s+injection\b|\bcve-\d{4}-\d+\b', text)
    if not has_vulnerability_context and not has_explicit_vulnerability_signal:
        return []

    matches: list[tuple[int, str]] = []

    def _add_matches(canonical: str, pattern: str) -> None:
        for match in re.finditer(pattern, text):
            matches.append((match.start(), canonical))

    for keyword in (
        'appweb',
        'jboss',
        'tomcat',
        'nginx',
        'apache',
        'openssh',
        'jwt',
        'oauth',
        'mysql',
        'postgres',
        'mongodb',
        'redis',
    ):
        _add_matches(keyword, rf'\b{re.escape(keyword)}\b')

    _add_matches('sql injection', r'\bsql\s+injection\b')
    _add_matches('web', r'\bweb(?:-related)?\b|\bhttps?\b')
    _add_matches('ssh', r'\bssh\b')
    _add_matches('auth', r'\bauth(?:entication)?\b|\blogin\b|\btoken\b|\boauth\b')
    _add_matches('database', r'\bdatabase\b|\bdb\b')
    _add_matches('random', r'\b(?:another|one\s+more|extra)\s+random\s+vulnerabilit(?:y|ies)\b|\brandom\s+vulnerabilit(?:y|ies)\b')

    ordered: list[str] = []
    seen: set[str] = set()
    for _position, canonical in sorted(matches, key=lambda item: item[0]):
        if canonical in seen:
            continue
        seen.add(canonical)
        ordered.append(canonical)

    return ordered


def extract_vulnerability_query_hint(user_prompt: str) -> str:
    text = str(user_prompt or '').strip().lower()
    if not text or _extract_vulnerability_target_count(text) <= 0:
        return ''

    query_hints = extract_vulnerability_query_hints(text)
    if query_hints:
        first_hint = query_hints[0]
        return 'vulnerability' if first_hint == 'random' else first_hint

    explicit_keywords = (
        'appweb',
        'jboss',
        'tomcat',
        'nginx',
        'apache',
        'openssh',
        'jwt',
        'oauth',
        'mysql',
        'postgres',
        'mongodb',
        'redis',
    )
    for keyword in explicit_keywords:
        if keyword in text:
            return keyword

    keyword_groups = (
        ('web', ('web', 'http', 'https', 'apache', 'nginx', 'appweb', 'tomcat', 'jboss')),
        ('ssh', ('ssh', 'openssh')),
        ('auth', ('auth', 'authentication', 'login', 'jwt', 'token', 'oauth')),
        ('database', ('database', 'db', 'mysql', 'postgres', 'mongodb', 'redis')),
    )
    for canonical, keywords in keyword_groups:
        if any(keyword in text for keyword in keywords):
            return canonical

    phrase_match = re.search(r'\b(?:related to|for|about)\s+([a-z0-9][a-z0-9\s-]{0,40})', text)
    if phrase_match:
        phrase = ' '.join(phrase_match.group(1).split())
        return phrase[:40].strip()

    return 'vulnerability'


def _normalize_catalog_entry(entry: dict[str, Any]) -> dict[str, str]:
    return {
        'name': str(entry.get('Name') or entry.get('name') or '').strip(),
        'path': str(entry.get('Path') or entry.get('path') or '').strip(),
        'description': str(entry.get('Description') or entry.get('description') or '').strip(),
        'type': str(entry.get('Type') or entry.get('type') or '').strip(),
        'vector': str(entry.get('Vector') or entry.get('vector') or '').strip(),
        'cve': str(entry.get('CVE') or entry.get('cve') or '').strip(),
    }


def search_vulnerability_catalog_for_prompt(
    query: str,
    *,
    catalog: list[dict[str, Any]] | None = None,
    limit: int = 3,
) -> list[dict[str, str]]:
    query_text = str(query or '').strip().lower()
    if not query_text:
        return []

    catalog_items = list(catalog or [])
    if not catalog_items:
        return []

    tokens = [token for token in re.findall(r'[a-z0-9]+', query_text) if token]
    if not tokens:
        return []

    ranked: list[tuple[int, dict[str, str]]] = []
    for raw_entry in catalog_items:
        entry = _normalize_catalog_entry(raw_entry if isinstance(raw_entry, dict) else {})
        name = entry['name']
        path = entry['path']
        description = entry['description']
        if not name or not path:
            continue
        haystack = ' '.join([
            name.lower(),
            path.lower(),
            description.lower(),
            entry['type'].lower(),
            entry['vector'].lower(),
            entry['cve'].lower(),
        ])
        score = 0
        for token in tokens:
            if token in haystack:
                score += 2
            if token in name.lower():
                score += 3
            if token in path.lower():
                score += 2
            if token in description.lower():
                score += 1
        if score > 0:
            ranked.append((score, {'name': name, 'path': path}))

    ranked.sort(key=lambda item: (-item[0], item[1]['name'].lower(), item[1]['path'].lower()))
    selected = [entry for _score, entry in ranked[:max(1, limit)]]
    generic_tokens = {'vulnerability', 'vulnerabilities', 'vuln', 'vulns', 'docker', 'target', 'targets', 'host', 'hosts', 'node', 'nodes', 'container', 'containers', 'vulnerable'}
    if not selected and tokens and all(token in generic_tokens for token in tokens):
        normalized_catalog = [
            _normalize_catalog_entry(raw_entry if isinstance(raw_entry, dict) else {})
            for raw_entry in catalog_items
        ]
        normalized_catalog.sort(key=lambda entry: (entry['name'].lower(), entry['path'].lower()))
        return [
            {'name': entry['name'], 'path': entry['path']}
            for entry in normalized_catalog[:max(1, limit)]
            if entry['name'] and entry['path']
        ]
    if len(selected) >= max(1, limit):
        return selected
    if not selected:
        return selected

    seen = {(entry['name'], entry['path']) for entry in selected}
    normalized_catalog = [
        _normalize_catalog_entry(raw_entry if isinstance(raw_entry, dict) else {})
        for raw_entry in catalog_items
    ]
    normalized_catalog.sort(key=lambda entry: (entry['name'].lower(), entry['path'].lower()))
    for entry in normalized_catalog:
        if not entry['name'] or not entry['path']:
            continue
        key = (entry['name'], entry['path'])
        if key in seen:
            continue
        selected.append({'name': entry['name'], 'path': entry['path']})
        seen.add(key)
        if len(selected) >= max(1, limit):
            break
    return selected


def extract_flag_node_generator_query_hint(user_prompt: str) -> str:
    """Free-text query describing the flag-node-generator the prompt asks for.

    Returns '' when the prompt has no flag-node-generator intent, or when it asks
    for generators without describing one (those requests stay Random).
    """
    text = str(user_prompt or '').strip().lower()
    if not text or _extract_flag_node_generator_target_count(text) <= 0:
        return ''

    filler = {
        'a', 'an', 'the', 'some', 'of', 'pair', 'couple', 'random', 'another', 'more', 'new',
        'add', 'build', 'create', 'generate', 'give', 'include', 'make', 'me', 'need', 'please',
        'use', 'want',
    }

    descriptor_match = re.search(
        rf'{_FLAG_NODE_GENERATOR_PHRASE}\s+(?:that|which|to|for|with)\s+([a-z0-9][a-z0-9\s,./-]{{0,60}})',
        text,
    )
    if descriptor_match:
        words = descriptor_match.group(1).split()
        while words and words[0] in filler:
            words.pop(0)
        phrase = ' '.join(words).strip(' ,.')
        if phrase:
            return phrase[:60]

    phrase_match = re.search(rf'\b{_FLAG_NODE_GENERATOR_PHRASE}\b', text)
    if phrase_match:
        # Walk back from the phrase collecting descriptor words, stopping at the
        # count ("two ssh ...") or at a word that belongs to another section.
        descriptor: list[str] = []
        for word in reversed(text[:phrase_match.start()].split()):
            if (
                len(word) < 2
                or word in filler
                or word in _FLAG_NODE_GENERATOR_COUNT_BLOCKERS
                or _parse_count_token(word) is not None
            ):
                break
            descriptor.insert(0, word)
            if len(descriptor) >= 4:
                break
        phrase = ' '.join(descriptor).strip(' ,.')
        if phrase:
            return phrase[:40]

    return ''


def search_flag_node_generator_catalog_for_prompt(
    query: str,
    *,
    catalog: list[dict[str, Any]] | None = None,
    limit: int = 3,
) -> list[dict[str, str]]:
    """Rank enabled flag-node-generators against a free-text query.

    The catalog is passed in: planning stays I/O-free and never reads the
    installed generator directories itself.
    """
    query_text = str(query or '').strip().lower()
    if not query_text:
        return []

    catalog_items = [entry for entry in (catalog or []) if isinstance(entry, dict)]
    if not catalog_items:
        return []

    tokens = [token for token in re.findall(r'[a-z0-9]+', query_text) if token]
    if not tokens:
        return []

    ranked: list[tuple[int, dict[str, str]]] = []
    for entry in catalog_items:
        generator_id = str(entry.get('id') or entry.get('g_id') or '').strip()
        name = str(entry.get('name') or entry.get('g_name') or '').strip()
        if not generator_id or not name:
            continue
        description = str(entry.get('description') or '').strip()
        hints = ' '.join(str(hint or '') for hint in (entry.get('description_hints') or []))
        produces = ' '.join(
            str(item.get('name') or '') if isinstance(item, dict) else str(item or '')
            for item in (entry.get('outputs') or entry.get('produces') or [])
        )
        name_lower = name.lower()
        description_lower = description.lower()
        haystack = ' '.join([name_lower, description_lower, hints.lower(), produces.lower()])
        score = 0
        for token in tokens:
            if token in haystack:
                score += 2
            if token in name_lower:
                score += 3
            if token in description_lower:
                score += 1
        if score > 0:
            ranked.append((score, {'id': generator_id, 'name': name}))

    ranked.sort(key=lambda item: (-item[0], item[1]['name'].lower(), item[1]['id']))
    return [entry for _score, entry in ranked[:max(1, limit)]]


def extract_node_role_count_intent(user_prompt: str) -> dict[str, int]:
    text = str(user_prompt or '').strip().lower()
    if not text:
        return {}

    # References such as "five hosts where two hosts run vulnerable services"
    # describe a subset of the five hosts, not two additional PC nodes. Remove
    # those subset phrases before collecting ordinary host-role quantities.
    count_token = rf'(?:{_COUNT_TOKEN_PATTERN})'
    role_text = re.sub(
        rf'\b{count_token}\s+(?:hosts?|nodes?)\s+(?:that\s+|which\s+)?(?:run|runs|running|host|hosts|hosting|with)\s+(?:an?\s+)?vulnerable\s+(?:[a-z][a-z0-9-]*\s+){{0,2}}(?:services?|applications?|apps?)\b',
        ' vulnerability-targets ',
        text,
    )

    counts: dict[str, int] = {}
    for role, pattern in _ROLE_PATTERNS:
        total = 0
        for match in re.finditer(pattern, role_text):
            for group in match.groups():
                if group is None:
                    continue
                parsed = _parse_count_token(group)
                if parsed is None:
                    continue
                total += max(0, int(parsed))
        if total > 0:
            counts[role] = total
    return counts


def extract_routing_protocols_requested(user_prompt: str) -> list[str]:
    text = str(user_prompt or '').strip().lower()
    if not text:
        return []

    matches: list[str] = []
    for pattern, canonical in (
        (r'\bospfv3\b', 'OSPFv3'),
        (r'\bospf(?:v2)?\b', 'OSPFv2'),
        (r'\bripng\b', 'RIPNG'),
        (r'\brip\b', 'RIP'),
        (r'\bbgp\b', 'BGP'),
    ):
        if re.search(pattern, text) and canonical not in matches:
            matches.append(canonical)
    return matches


def explicit_host_role_count_total(user_prompt: str) -> int:
    return sum(extract_node_role_count_intent(user_prompt).values())


def _parse_count_token(value: Any) -> int | None:
    text = str(value or '').strip().lower()
    if not text:
        return None
    if text.isdigit():
        try:
            number = int(text)
        except Exception:
            return None
        return number if number > 0 else None
    return _COUNT_WORDS.get(text)


def _extract_shared_suffix_count_intent(
    text: str,
    *,
    suffix_pattern: str,
    label_patterns: tuple[tuple[str, str], ...],
    qualifier_max_words: int = 3,
) -> dict[str, int]:
    if not text:
        return {}

    separator_pattern = r'(?:\s*,\s*and\s+|\s+and\s+|\s*,\s*)'
    forbidden_qualifier_words = r'and|or|plus|a|an|one|two|three|four|five|six|seven|eight|nine|ten|eleven|twelve|pair|couple'
    qualifier_words = rf'(?:(?!(?:{forbidden_qualifier_words})\b)[a-z][a-z0-9-]*\s+){{0,{qualifier_max_words}}}'

    counts: dict[str, int] = {}
    for canonical, label_pattern in label_patterns:
        segment_pattern = re.compile(
            rf'\b(?P<count>{_COUNT_TOKEN_PATTERN})\s+{qualifier_words}(?P<label>{label_pattern})(?=(?:{separator_pattern}(?:{_COUNT_TOKEN_PATTERN})\s+|\s+{suffix_pattern}\b))'
        )
        total = 0
        for match in segment_pattern.finditer(text):
            number = _parse_count_token(match.group('count'))
            if number is None:
                continue
            total += number
        if total > 0:
            counts[canonical] = counts.get(canonical, 0) + total
    return counts


def extract_service_count_intent(user_prompt: str) -> dict[str, int]:
    text = str(user_prompt or '').strip().lower()
    if not text:
        return {}

    counts = _extract_shared_suffix_count_intent(
        text,
        suffix_pattern=r'services?',
        label_patterns=(
            ('SSH', r'ssh'),
            ('HTTPS', r'https'),
            ('HTTP', r'http|web'),
            ('DHCPClient', r'dhcp'),
        ),
        qualifier_max_words=3,
    )

    # Service presence is explicit even when the user does not quantify each
    # service ("six hosts running SSH and HTTP"). Seed every named service so a
    # model cannot silently drop one while filling the rest of the topology.
    host_counts = extract_node_role_count_intent(text)
    default_count = max(1, sum(host_counts.values()))
    for canonical, pattern in (
        ('SSH', r'\bssh\b'),
        ('HTTPS', r'\bhttps\b'),
        ('HTTP', r'\bhttp\b|\bweb\s+(?:server|service)\b'),
        ('DHCPClient', r'\bdhcp(?:\s+client)?\b'),
    ):
        if canonical not in counts and re.search(pattern, text):
            counts[canonical] = default_count
    return counts


def extract_traffic_protocol_count_intent(user_prompt: str) -> dict[str, int]:
    text = str(user_prompt or '').strip().lower()
    if not text:
        return {}

    flow_suffix = r'(?:traffic\s+flows?|flows?|traffic\s+streams?|streams?)'
    return _extract_shared_suffix_count_intent(
        text,
        suffix_pattern=flow_suffix,
        label_patterns=(
            ('TCP', r'tcp'),
            ('UDP', r'udp'),
        ),
        qualifier_max_words=3,
    )


def extract_traffic_pattern_count_intent(user_prompt: str) -> dict[str, int]:
    text = str(user_prompt or '').strip().lower()
    if not text:
        return {}

    flow_suffix = r'(?:traffic\s+flows?|flows?|traffic\s+streams?|streams?)'
    return _extract_shared_suffix_count_intent(
        text,
        suffix_pattern=rf'(?:(?:tcp|udp)\s+)?{flow_suffix}',
        label_patterns=(
            ('continuous', r'continuous|always\s+on|constant\s+rate'),
            ('periodic', r'periodic'),
            ('burst', r'burst(?:y)?'),
            ('poisson', r'poisson'),
            ('ramp', r'ramp'),
        ),
        qualifier_max_words=2,
    )


def extract_requested_traffic_patterns(user_prompt: str) -> list[str]:
    text = str(user_prompt or '').strip().lower()
    if not text:
        return []

    matches: list[str] = []
    for pattern, canonical in (
        (r'\bcontinuous\b|\balways\s+on\b|\bconstant\s+rate\b', 'continuous'),
        (r'\bperiodic\b', 'periodic'),
        (r'\bburst(?:y)?\b', 'burst'),
        (r'\bpoisson\b', 'poisson'),
        (r'\bramp\b', 'ramp'),
    ):
        if re.search(pattern, text) and canonical not in matches:
            matches.append(canonical)
    return matches


def build_seeded_traffic_rows(user_prompt: str) -> list[dict[str, Any]]:
    protocol_counts = extract_traffic_protocol_count_intent(user_prompt)
    pattern_counts = extract_traffic_pattern_count_intent(user_prompt)
    if not protocol_counts and re.search(r'\bbackground\s+traffic\b', str(user_prompt or '').lower()):
        protocol_counts = {'TCP': 1}
    if not protocol_counts:
        return []

    requested_patterns = extract_requested_traffic_patterns(user_prompt)

    rows: list[dict[str, Any]] = []
    protocol_queue = [[protocol, count] for protocol, count in protocol_counts.items() if count > 0]
    pattern_queue = [[pattern_name, count] for pattern_name, count in pattern_counts.items() if count > 0]

    if pattern_queue and sum(count for _pattern, count in pattern_queue) == sum(count for _protocol, count in protocol_queue):
        pattern_index = 0
        for protocol, protocol_count in protocol_queue:
            remaining = protocol_count
            while remaining > 0 and pattern_index < len(pattern_queue):
                pattern_name, pattern_count = pattern_queue[pattern_index]
                if pattern_count <= 0:
                    pattern_index += 1
                    continue
                assigned = min(remaining, pattern_count)
                rows.append({
                    'protocol': protocol,
                    'count': assigned,
                    'pattern': pattern_name,
                    'content_type': 'text',
                })
                remaining -= assigned
                pattern_queue[pattern_index][1] -= assigned
                if pattern_queue[pattern_index][1] <= 0:
                    pattern_index += 1
            if remaining > 0:
                rows.append({
                    'protocol': protocol,
                    'count': remaining,
                    'pattern': 'continuous',
                    'content_type': 'text',
                })
        return rows

    if len(requested_patterns) > 1:
        return []

    default_pattern = next(iter(pattern_counts.keys()), '')
    if not default_pattern and len(requested_patterns) == 1:
        default_pattern = requested_patterns[0]
    if not default_pattern:
        default_pattern = 'continuous'

    for protocol, count in protocol_counts.items():
        rows.append({
            'protocol': protocol,
            'count': count,
            'pattern': default_pattern,
            'content_type': 'text',
        })
    return rows


def extract_segmentation_control_count_intent(user_prompt: str) -> dict[str, int]:
    text = str(user_prompt or '').strip().lower()
    if not text:
        return {}

    counts: dict[str, int] = {}
    count_token = rf'({_COUNT_TOKEN_PATTERN})'
    firewall_match = re.search(
        rf'\b{count_token}\s+(?:stateful\s+)?(?:firewalls?|firewalled\s+(?:segments?|subnets?|zones?))\b',
        text,
    )
    if firewall_match:
        parsed = _parse_count_token(firewall_match.group(1))
        if parsed is not None:
            counts['Firewall'] = parsed
    elif re.search(r'\bfirewalls?\b|\bfirewalled\b|\bfw\b', text):
        counts['Firewall'] = 1

    nat_match = re.search(rf'\b{count_token}\s+(?:nat|snat|dnat)(?:\s+(?:gateways?|segments?|rules?|controls?))?\b', text)
    if nat_match:
        parsed = _parse_count_token(nat_match.group(1))
        if parsed is not None:
            counts['NAT'] = parsed
    elif re.search(r'\b(?:nat|snat|dnat)(?:\s+gateway)?\b', text):
        counts['NAT'] = 1
    return counts


def extract_r2r_density_intent(user_prompt: str) -> str:
    text = str(user_prompt or '').strip().lower()
    if not text:
        return ''
    if any(re.search(pattern, text) for pattern in _LOW_R2R_PATTERNS):
        return 'low'
    if any(re.search(pattern, text) for pattern in _HIGH_R2R_PATTERNS):
        return 'high'
    return ''


def has_low_r2r_intent(user_prompt: str) -> bool:
    return extract_r2r_density_intent(user_prompt) == 'low'


def extract_ai_topology_intent(user_prompt: str) -> AiTopologyIntent:
    count_intent = _extract_count_intent(user_prompt)
    return AiTopologyIntent(
        total_nodes=count_intent.get('total_nodes'),
        router_count=count_intent.get('router_count'),
        derived_host_count=count_intent.get('derived_host_count'),
        node_role_counts=extract_node_role_count_intent(user_prompt),
        service_counts=extract_service_count_intent(user_prompt),
        traffic_rows=build_seeded_traffic_rows(user_prompt),
        segmentation_counts=extract_segmentation_control_count_intent(user_prompt),
        vulnerability_target_count=_extract_vulnerability_target_count(user_prompt),
        r2r_density=extract_r2r_density_intent(user_prompt),
        flag_node_generator_target_count=_extract_flag_node_generator_target_count(user_prompt),
    )


def compile_ai_topology_intent(
    user_prompt: str,
    *,
    vuln_catalog: list[dict[str, Any]] | None = None,
) -> CompiledAiTopologyIntent:
    intent = extract_ai_topology_intent(user_prompt)
    section_payloads: dict[str, dict[str, Any]] = {}
    tool_seed_ops: list[dict[str, Any]] = []
    applied_actions: list[str] = []
    locked_sections: list[str] = []

    if intent.router_count and intent.router_count > 0:
        routing_protocols = extract_routing_protocols_requested(user_prompt)
        selected_protocol = routing_protocols[0] if routing_protocols else 'OSPFv2'
        routing_item: dict[str, Any] = {
            'selected': selected_protocol,
            'factor': 1.0,
            'v_metric': 'Count',
            'v_count': int(intent.router_count),
        }
        if intent.r2r_density == 'low':
            routing_item['r2r_mode'] = 'Min'
        elif intent.r2r_density == 'high':
            routing_item['r2r_mode'] = 'Uniform'
        section_payloads['Routing'] = {
            'density': 0.0,
            'items': [routing_item],
        }
        tool_seed_ops.append({
            'kind': 'routing',
            'protocol': selected_protocol,
            'count': int(intent.router_count),
            'r2r_mode': routing_item.get('r2r_mode'),
        })
        applied_actions.append(f'Routing routers={int(intent.router_count)}')
        locked_sections.append('Routing')

    node_role_counts = dict(intent.node_role_counts)
    host_budget = intent.derived_host_count if intent.derived_host_count is not None else intent.total_nodes
    vulnerability_slots_to_reserve = max(0, int(intent.vulnerability_target_count or 0))
    if host_budget is not None:
        # Vulnerability rows become additive Docker nodes in the planner, but an
        # explicit total-node budget includes those nodes. Reserve their slots
        # here so the final topology, rather than only Node Information, matches
        # the stated total.
        node_information_budget = max(0, int(host_budget) - vulnerability_slots_to_reserve)
        remaining_hosts = max(0, node_information_budget - sum(node_role_counts.values()))
        if remaining_hosts > 0:
            node_role_counts['PC'] = node_role_counts.get('PC', 0) + remaining_hosts
    elif vulnerability_slots_to_reserve > 0 and node_role_counts.get('PC', 0) > 0:
        # A generic host quantity is inclusive when the prompt says some of
        # those hosts are vulnerable. The planner supplies that subset as Docker
        # challenge nodes, so reduce only the flexible PC row.
        node_role_counts['PC'] = max(0, node_role_counts['PC'] - vulnerability_slots_to_reserve)

    if node_role_counts:
        node_items: list[dict[str, Any]] = []
        for role in HOST_ROLE_DISPLAY_ORDER:
            count = int(node_role_counts.get(role) or 0)
            if count <= 0:
                continue
            node_items.append({
                'selected': role,
                'factor': 1.0,
                'v_metric': 'Count',
                'v_count': count,
            })
            tool_seed_ops.append({
                'kind': 'node',
                'role': role,
                'count': count,
            })
            applied_actions.append(f'Node {role}={count}')
        if node_items:
            host_total = sum(item['v_count'] for item in node_items)
            section_payloads['Node Information'] = {
                'density': 0,
                'total_nodes': max(0, int(host_total or 0)),
                'items': node_items,
            }
            locked_sections.append('Node Information')

    if intent.service_counts:
        service_items: list[dict[str, Any]] = []
        for service_name in ('SSH', 'HTTP', 'HTTPS', 'DHCPClient'):
            count = int(intent.service_counts.get(service_name) or 0)
            if count <= 0:
                continue
            service_items.append({
                'selected': service_name,
                'factor': 1.0,
                'v_metric': 'Count',
                'v_count': count,
            })
            tool_seed_ops.append({
                'kind': 'service',
                'service': service_name,
                'count': count,
            })
            applied_actions.append(f'Service {service_name}={count}')
        if service_items:
            section_payloads['Services'] = {'density': 0.0, 'items': service_items}
            locked_sections.append('Services')

    if intent.traffic_rows:
        traffic_items: list[dict[str, Any]] = []
        for row in intent.traffic_rows:
            protocol = str(row.get('protocol') or '').strip()
            count = int(row.get('count') or 0)
            pattern = str(row.get('pattern') or 'continuous').strip() or 'continuous'
            content_type = str(row.get('content_type') or 'text').strip() or 'text'
            if not protocol or count <= 0:
                continue
            traffic_items.append({
                'selected': protocol,
                'factor': 1.0,
                'v_metric': 'Count',
                'v_count': count,
                'pattern': pattern,
                'content_type': content_type,
            })
            tool_seed_ops.append({
                'kind': 'traffic',
                'protocol': protocol,
                'count': count,
                'pattern': pattern,
                'content_type': content_type,
            })
            applied_actions.append(f'Traffic {protocol} {pattern}={count}')
        if traffic_items:
            section_payloads['Traffic'] = {'density': 0.0, 'items': traffic_items}
            locked_sections.append('Traffic')

    if intent.segmentation_counts:
        segmentation_items: list[dict[str, Any]] = []
        for control in ('Firewall', 'NAT'):
            count = int(intent.segmentation_counts.get(control) or 0)
            if count <= 0:
                continue
            segmentation_items.append({
                'selected': control,
                'factor': 1.0,
                'v_metric': 'Count',
                'v_count': count,
            })
            tool_seed_ops.append({
                'kind': 'segmentation',
                'selected': control,
                'count': count,
            })
            applied_actions.append(f'Segmentation {control}={count}')
        if segmentation_items:
            section_payloads['Segmentation'] = {'density': 0.0, 'items': segmentation_items}
            locked_sections.append('Segmentation')

    if intent.vulnerability_target_count > 0 and vuln_catalog:
        query_hints = extract_vulnerability_query_hints(user_prompt)
        requested_count = max(1, int(intent.vulnerability_target_count))
        candidate_queries = [
            'vulnerability' if str(hint or '').strip().lower() == 'random' else str(hint or '').strip()
            for hint in query_hints
            if str(hint or '').strip()
        ]
        if not candidate_queries:
            query_hint = extract_vulnerability_query_hint(user_prompt)
            if query_hint:
                candidate_queries = [query_hint]

        candidate_pool: list[dict[str, str]] = []
        seen_candidates: set[tuple[str, str]] = set()

        def _append_unique(entries: list[dict[str, str]], *, first_only: bool = False) -> None:
            added = 0
            for entry in entries:
                name = str(entry.get('name') or '').strip()
                path = str(entry.get('path') or '').strip()
                if not name or not path:
                    continue
                key = (name, path)
                if key in seen_candidates:
                    continue
                seen_candidates.add(key)
                candidate_pool.append({'name': name, 'path': path})
                added += 1
                if first_only and added >= 1:
                    break

        hint_candidate_sets: list[list[dict[str, str]]] = []
        for query in candidate_queries:
            hint_candidate_sets.append(
                search_vulnerability_catalog_for_prompt(
                    query,
                    catalog=vuln_catalog,
                    limit=requested_count,
                )
            )

        if len(hint_candidate_sets) > 1:
            for entries in hint_candidate_sets:
                _append_unique(entries, first_only=True)
                if len(candidate_pool) >= requested_count:
                    break

        if len(candidate_pool) < requested_count:
            for entries in hint_candidate_sets:
                _append_unique(entries)
                if len(candidate_pool) >= requested_count:
                    break

        if len(candidate_pool) < requested_count:
            _append_unique(
                search_vulnerability_catalog_for_prompt(
                    'vulnerability',
                    catalog=vuln_catalog,
                    limit=requested_count,
                )
            )

        vuln_items: list[dict[str, Any]] = []
        if candidate_pool:
            for index in range(requested_count):
                candidate = candidate_pool[index % len(candidate_pool)]
                vuln_items.append({
                    'selected': 'Specific',
                    'v_metric': 'Count',
                    'v_count': 1,
                    'v_name': candidate['name'],
                    'v_path': candidate['path'],
                })
                tool_seed_ops.append({
                    'kind': 'vulnerability',
                    'v_name': candidate['name'],
                    'v_path': candidate['path'],
                    'v_count': 1,
                })
                applied_actions.append(f'Vulnerability {candidate["name"]}')
        if vuln_items:
            section_payloads['Vulnerabilities'] = {
                'density': 0.0,
                'items': vuln_items,
                'flag_type': 'text',
            }
            locked_sections.append('Vulnerabilities')

    if intent.flag_node_generator_target_count > 0:
        requested_count = max(1, int(intent.flag_node_generator_target_count))
        section_payloads['Flag Node Generators'] = {
            'density': 0.0,
            'items': [{
                'selected': 'Random',
                'factor': 1.0,
                'v_metric': 'Count',
                'v_count': requested_count,
            }],
        }
        tool_seed_ops.append({'kind': 'flag-node-generator', 'count': requested_count})
        applied_actions.append(f'Flag Node Generators={requested_count}')
        locked_sections.append('Flag Node Generators')

    return CompiledAiTopologyIntent(
        intent=intent,
        section_payloads=section_payloads,
        tool_seed_ops=tool_seed_ops,
        applied_actions=applied_actions,
        locked_sections=tuple(locked_sections),
    )


def apply_compiled_sections_to_scenario(
    scenario_payload: dict[str, Any],
    compiled: CompiledAiTopologyIntent,
) -> dict[str, Any]:
    result = deepcopy(scenario_payload if isinstance(scenario_payload, dict) else {})
    if not compiled.has_seed:
        return result
    sections = result.get('sections') if isinstance(result.get('sections'), dict) else {}
    next_sections = deepcopy(sections)
    for section_name, section_payload in compiled.section_payloads.items():
        next_sections[section_name] = deepcopy(section_payload)
    result['sections'] = next_sections
    return result
