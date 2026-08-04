"""A pivot earns its own chain step only when the provider's challenge doesn't
already hand the participant code execution there."""

import pytest

from scenarioforge.utils import pivot_chain as pc


# --------------------------------------------------------------------------- #
# The capability test
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("fact", [
    "CodeExecution(host)",
    "Shell(host)",
    "RootShell(host)",
    "WebRCE(app)",
    "Pivot(host)",
])
def test_rce_shaped_facts_grant_a_pivot(fact):
    # Shell/RootShell/WebRCE reach CodeExecution through the existing
    # subsumption rules rather than being enumerated here.
    assert pc.grants_pivot([fact]) is True


@pytest.mark.parametrize("fact", [
    "WebAuthBypass(app)",
    "File(host, path)",
    "Credential(user, password)",
    "Knowledge(value)",
    "ExposedSecret(service)",
    "Misconfiguration(service)",
    "UploadPrimitive(app)",
])
def test_non_execution_facts_do_not_grant_a_pivot(fact):
    assert pc.grants_pivot([fact]) is False


def test_no_facts_at_all_grants_nothing():
    assert pc.grants_pivot([]) is False
    assert pc.grants_pivot(None) is False


def test_granting_facts_reports_what_qualified():
    facts = pc.granting_facts(["RootShell(host)", "Credential(user, password)"])
    # RootShell subsumes to Shell + CodeExecution; only the granting one is named.
    assert "CodeExecution(host)" in facts
    assert not any("Credential" in f for f in facts)


def test_whitespace_spelling_variants_match():
    # Generators write both `Fact(a,b)` and `Fact(a, b)`; canonicalization
    # settles that, which is why the argument spacing here is irrelevant.
    assert pc.grants_pivot(["CodeExecution( host )"]) is True
    assert pc.grants_pivot(["Shell(host , user)"]) is True


def test_fact_name_case_follows_the_rest_of_the_system():
    # canonical_fact_key normalizes argument spacing, not the fact name, so a
    # miscased fact does not match here either. Being lenient in this one place
    # would classify a fact as pivot-granting that the solver would still fail
    # to match everywhere else.
    assert pc.grants_pivot(["codeexecution(host)"]) is False


def test_impact_shorthands_map_through_metadata():
    from scenarioforge.vulns.metadata import IMPACT_PROVIDES
    granting = {"remote_code_execution", "command_injection", "deserialization",
                "web_rce", "privilege_escalation"}
    for impact, provides in IMPACT_PROVIDES.items():
        expected = impact in granting
        assert pc.grants_pivot(provides) is expected, impact


# --------------------------------------------------------------------------- #
# Classifying a provider against the chain
# --------------------------------------------------------------------------- #

def _chain():
    return [
        {"name": "docker-21", "provides": ["CodeExecution(host)"], "challenge": "CVE-rce"},
        {"name": "flaggenslot-6", "provides": ["Flag(flag_id)"], "challenge": "gen-6"},
        {"name": "docker-26", "provides": "Credential(user, password)", "challenge": "leak"},
    ]


def test_provider_with_rce_challenge_is_absorbed():
    d = pc.classify_pivot("docker-21", "172.21.240.0/24", _chain())
    assert d.disposition == pc.ABSORBED
    assert d.is_own_step is False
    assert "CodeExecution(host)" in d.granting_facts
    assert d.provider_challenge == "CVE-rce"
    assert "not separate work" in d.reason


def test_provider_whose_challenge_only_leaks_a_credential_gets_its_own_step():
    d = pc.classify_pivot("docker-26", "172.21.240.0/24", _chain())
    assert d.disposition == pc.OWN_STEP
    assert d.is_own_step is True
    assert d.granting_facts == []
    assert "does not grant code execution" in d.reason


def test_provider_with_no_chain_challenge_gets_its_own_step():
    # A bare SSH box or a router: nothing in the chain sits on it.
    d = pc.classify_pivot("router-1", "172.21.240.0/24", _chain(), entry_kind="ssh", entry_port=22)
    assert d.disposition == pc.OWN_STEP
    assert "carries no chain challenge" in d.reason
    assert d.entry_kind == "ssh" and d.entry_port == 22


def test_provides_can_be_a_comma_string():
    chain = [{"name": "n1", "provides": "Shell(host), Credential(user)"}]
    assert pc.classify_pivot("n1", "10.0.0.0/24", chain).disposition == pc.ABSORBED


def test_alternate_provides_keys_are_read():
    for key in ("Provides", "provides_facts", "effective_provides", "PivotProduces"):
        chain = [{"name": "n1", key: ["CodeExecution(host)"]}]
        assert pc.classify_pivot("n1", "10.0.0.0/24", chain).disposition == pc.ABSORBED, key


def test_node_is_matched_by_any_of_its_identifiers():
    chain = [{"container_name": "docker-21", "provides": ["Shell(host)"]}]
    assert pc.classify_pivot("docker-21", "10.0.0.0/24", chain).disposition == pc.ABSORBED


def test_matching_is_case_insensitive():
    chain = [{"name": "Docker-21", "provides": ["Shell(host)"]}]
    assert pc.classify_pivot("docker-21", "10.0.0.0/24", chain).disposition == pc.ABSORBED


def test_extra_provides_supplements_the_chain_node():
    # The caller knows the node runs an RCE vuln even though the chain entry
    # does not spell it out.
    chain = [{"name": "docker-21"}]
    d = pc.classify_pivot("docker-21", "10.0.0.0/24", chain,
                          extra_provides=["remote code execution"] and ["Shell(host)"])
    assert d.disposition == pc.ABSORBED


# --------------------------------------------------------------------------- #
# Classifying a whole pivot_access plan
# --------------------------------------------------------------------------- #

def _plan():
    return {"providers": [
        {"subnet": "172.21.240.0/24", "node_name": "docker-21",
         "entry": {"kind": "vulnerability", "port": 1053}},
        {"subnet": "10.99.0.0/24", "node_name": "router-9",
         "entry": {"kind": "ssh", "port": 22}},
    ]}


def test_plan_classification_covers_every_provider():
    decisions = pc.classify_pivot_access(_plan(), _chain())
    assert [d.subnet for d in decisions] == ["172.21.240.0/24", "10.99.0.0/24"]
    assert decisions[0].disposition == pc.ABSORBED     # docker-21 has RCE
    assert decisions[1].disposition == pc.OWN_STEP     # router SSH box
    assert decisions[0].entry_kind == "vulnerability"
    assert decisions[1].entry_port == 22


def test_plan_classification_accepts_provides_supplied_per_node():
    decisions = pc.classify_pivot_access(
        _plan(), [], provides_by_node={"docker-21": ["RootShell(host)"]})
    assert decisions[0].disposition == pc.ABSORBED
    assert decisions[1].disposition == pc.OWN_STEP


def test_plan_classification_handles_empty_and_malformed_input():
    assert pc.classify_pivot_access(None, _chain()) == []
    assert pc.classify_pivot_access({"providers": []}, _chain()) == []
    assert pc.classify_pivot_access({"providers": ["junk", None]}, _chain()) == []


def test_decision_serializes_for_reports():
    d = pc.classify_pivot("docker-21", "172.21.240.0/24", _chain())
    payload = d.as_dict()
    assert payload["disposition"] == pc.ABSORBED
    assert payload["provider_node"] == "docker-21"
    assert payload["granting_facts"]
    assert isinstance(payload["reason"], str) and payload["reason"]


def test_two_argument_shell_grants_a_pivot():
    # `_SUBSUMES` only maps the one-argument Shell(host); Shell(host, user) is
    # equally a shell on the host and must not be pushed into its own step.
    assert pc.grants_pivot(["Shell(host, user)"]) is True
    assert pc.grants_pivot(["Shell(host , user)"]) is True


def test_granting_set_covers_the_whole_shell_family():
    for fact in ("Shell(host)", "Shell(host, user)", "RootShell(host)",
                 "CodeExecution(host)", "WebRCE(app)", "Pivot(host)"):
        assert pc.grants_pivot([fact]) is True, fact


# --------------------------------------------------------------------------- #
# A pivot that is its own step earns a hint, tiered by how findable it is
# --------------------------------------------------------------------------- #

def _own_step(entry_kind, port=2222):
    from scenarioforge.utils.pivot_chain import OWN_STEP, PivotStepDecision

    return PivotStepDecision(
        subnet='172.21.240.0/24', provider_node='pivot-172-21-240-0',
        disposition=OWN_STEP, reason='bare SSH box', entry_kind=entry_kind,
        entry_port=port,
    )


def test_a_pivot_onto_a_challenge_node_is_a_medium_hint():
    # The participant is scanning that node anyway and will find the challenge,
    # so a nudge is enough.
    for kind in ('vulnerability', 'flag-node-generator'):
        decision = _own_step(kind)
        assert decision.hint_level() == 'medium'
        assert list(decision.hint_levels()) == ['medium']
        assert decision.hint_levels()['medium'] == [decision.instruction()]


def test_a_pivot_onto_a_bare_ssh_box_is_a_high_hint():
    # Nothing to solve on it and nothing saying "this is the door", so without
    # being told a participant has no reason to try it at all.
    decision = _own_step('ssh')
    assert decision.hint_level() == 'high'
    assert list(decision.hint_levels()) == ['high']
    assert 'SSH' in decision.hint_levels()['high'][0]


def test_an_absorbed_pivot_gets_no_hint_of_its_own():
    # It is a consequence of a challenge the participant is already hinted
    # through; hinting it separately would give that step away.
    from scenarioforge.utils.pivot_chain import ABSORBED, PivotStepDecision

    decision = PivotStepDecision(
        subnet='172.21.240.0/24', provider_node='docker-21', disposition=ABSORBED,
        reason='the challenge already grants code execution', entry_kind='vulnerability',
        entry_port=8080,
    )
    assert decision.hint_levels() == {}


def test_the_hint_travels_on_the_decision_payload():
    payload = _own_step('ssh').as_dict()
    assert payload['hint_level'] == 'high'
    assert payload['hint_levels']['high']
    assert payload['instruction'] in payload['hint_levels']['high']


def test_both_guides_render_the_pivot_hint_from_the_decision():
    # Guides are client-rendered, so a hint rule needs a twin in each template
    # or they drift. Neither may recompute the tier.
    from pathlib import Path

    for name, helper in (('webapp/templates/flow.html', 'pivotHintGroupsFor'),
                         ('webapp/templates/reports.html', 'reportPivotHintGroups')):
        src = Path(name).read_text(encoding='utf-8')
        assert helper in src, name
        assert 'hint_levels' in src, name
