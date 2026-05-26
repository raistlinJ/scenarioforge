from __future__ import annotations

from scripts import flag_test_core_e2e_check as smoke


def test_preset_preferred_ids_sample() -> None:
    assert smoke._preset_preferred_ids("sample", kind="flag-generator") == []
    assert smoke._preset_preferred_ids("sample", kind="flag-node-generator") == []


def test_ordered_candidates_prioritizes_preset_ids_when_available() -> None:
    available = ["second_gen", "other_gen", "first_gen"]
    preferred = ["first_gen", "missing_node_gen", "second_gen"]

    ordered = smoke._ordered_candidates(available, preferred)

    assert ordered == ["first_gen", "second_gen", "other_gen"]


def test_ordered_candidates_falls_back_to_available_when_preset_missing() -> None:
    available = ["gen_a", "gen_b"]
    preferred = ["missing_1", "missing_2"]

    ordered = smoke._ordered_candidates(available, preferred)

    assert ordered == ["gen_a", "gen_b"]
