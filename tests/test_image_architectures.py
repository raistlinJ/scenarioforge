"""Architecture detection for catalog items.

A vulhub recipe pinning an amd64-only image runs on an arm64 CORE VM only under
qemu emulation, and heavy applications do not survive that -- a real run had two
Confluence nodes exit 139 (SIGSEGV) mid-boot, restart, and lose the addressing
CORE applies at execute, failing the scenario for a reason that looked like a
networking fault.

The load-bearing property here is that "unknown" never masquerades as an answer.
An unscanned catalog must not disable itself, and a stack whose images share no
common architecture must not read as merely unscanned.
"""

from __future__ import annotations

import pytest

from scenarioforge.utils import image_architectures as ia


@pytest.fixture(autouse=True)
def _clear_architecture_cache():
    """Lookups are memoized per image ref, so a ref reused across tests would
    otherwise be answered from an earlier test's mock."""
    ia.clear_image_architecture_cache()
    yield
    ia.clear_image_architecture_cache()


# --------------------------------------------------------------------------- #
# Normalization: the same CPU has several spellings
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("raw,expected", [
    ("x86_64", "amd64"),
    ("X86-64", "amd64"),
    ("x64", "amd64"),
    ("amd64", "amd64"),
    ("aarch64", "arm64"),
    ("arm64", "arm64"),
    ("linux/amd64", "amd64"),
    ("linux/arm64", "arm64"),
    ("i686", "386"),
    ("", ""),
    (None, ""),
])
def test_architecture_names_are_normalised(raw, expected):
    # A catalog scanned on a machine that says `x86_64` must compare correctly
    # against a host that says `amd64`.
    assert ia.normalize_architecture(raw) == expected


# --------------------------------------------------------------------------- #
# Reading the compose file
# --------------------------------------------------------------------------- #

def test_image_refs_are_collected_in_order_without_duplicates():
    obj = {"services": {
        "web": {"image": "nginx:1"},
        "db": {"image": "postgres:12"},
        "other": {"image": "nginx:1"},
    }}
    assert ia.compose_image_refs(obj) == ["nginx:1", "postgres:12"]


def test_build_only_services_contribute_no_image():
    # Nothing is pulled, so nothing pins the architecture -- it follows the
    # build host.
    obj = {"services": {"web": {"build": "."}}}
    assert ia.compose_image_refs(obj) == []


def test_interpolated_image_names_are_skipped():
    # "${TAG}" resolves per run, so it cannot be looked up here.
    obj = {"services": {"web": {"image": "app:${TAG}"}}}
    assert ia.compose_image_refs(obj) == []


def test_declared_platform_is_read_from_the_compose_file():
    obj = {"services": {"web": {"image": "x", "platform": "linux/amd64"}}}
    assert ia.compose_declared_platforms(obj) == ["amd64"]


@pytest.mark.parametrize("bad", [None, [], "nope", {}, {"services": None}])
def test_malformed_compose_is_handled(bad):
    assert ia.compose_image_refs(bad) == []
    assert ia.compose_declared_platforms(bad) == []


# --------------------------------------------------------------------------- #
# Resolution order: declared > local > registry
# --------------------------------------------------------------------------- #

def test_a_declared_platform_wins_without_any_lookup(monkeypatch):
    # The author said so outright; no reason to ask Docker at all.
    monkeypatch.setattr(ia, "image_architectures",
                        lambda *_a, **_k: pytest.fail("should not look up a declared platform"))
    result = ia.compose_architectures(
        {"services": {"web": {"image": "x", "platform": "linux/amd64"}}}
    )
    assert result["architectures"] == ["amd64"]
    assert result["source"] == "declared"


def test_local_inspect_is_preferred_over_the_registry(monkeypatch):
    monkeypatch.setattr(ia, "_docker_available", lambda: True)
    monkeypatch.setattr(ia, "_architectures_from_local", lambda _i: ["arm64"])
    monkeypatch.setattr(ia, "_architectures_from_registry",
                        lambda _i: pytest.fail("registry must not be consulted when cached locally"))
    assert ia.image_architectures("alpine:3.19") == (["arm64"], "local")


def test_registry_is_used_when_the_image_is_not_cached(monkeypatch):
    monkeypatch.setattr(ia, "_docker_available", lambda: True)
    monkeypatch.setattr(ia, "_architectures_from_local", lambda _i: [])
    monkeypatch.setattr(ia, "_architectures_from_registry", lambda _i: ["amd64", "arm64"])
    assert ia.image_architectures("nginx:1") == (["amd64", "arm64"], "registry")


def test_registry_can_be_disabled_for_offline_scans(monkeypatch):
    # An air-gapped host has no registry; it must degrade to unknown rather
    # than stall or guess.
    monkeypatch.setattr(ia, "_docker_available", lambda: True)
    monkeypatch.setattr(ia, "_architectures_from_local", lambda _i: [])
    monkeypatch.setattr(ia, "_architectures_from_registry",
                        lambda _i: pytest.fail("registry must not be consulted when disabled"))
    assert ia.image_architectures("nginx:1", allow_registry=False) == ([], ia.UNKNOWN)


def test_no_docker_binary_yields_unknown_not_a_guess(monkeypatch):
    monkeypatch.setattr(ia, "_docker_available", lambda: False)
    assert ia.image_architectures("nginx:1") == ([], ia.UNKNOWN)


# --------------------------------------------------------------------------- #
# A stack runs natively only where every one of its images does
# --------------------------------------------------------------------------- #

def _fake_lookup(mapping):
    def _lookup(image, allow_registry=True):
        archs = mapping.get(image)
        return (list(archs), "registry") if archs else ([], ia.UNKNOWN)
    return _lookup


def test_stack_architecture_is_the_intersection_across_images(monkeypatch):
    monkeypatch.setattr(ia, "image_architectures", _fake_lookup({
        "app": ["amd64", "arm64"],
        "db": ["amd64"],
    }))
    result = ia.compose_architectures(
        {"services": {"app": {"image": "app"}, "db": {"image": "db"}}}
    )
    # One amd64-only sidecar is enough to make the whole node amd64-only.
    assert result["architectures"] == ["amd64"]


def test_a_stack_with_no_common_architecture_is_resolved_not_unknown(monkeypatch):
    monkeypatch.setattr(ia, "image_architectures", _fake_lookup({
        "app": ["amd64"],
        "cache": ["arm64"],
    }))
    result = ia.compose_architectures(
        {"services": {"app": {"image": "app"}, "cache": {"image": "cache"}}}
    )
    assert result["architectures"] == []
    # Crucially NOT "unknown": this was resolved, and the answer is that no
    # single architecture runs the whole stack.
    assert result["source"] != ia.UNKNOWN
    assert result["per_image"]


def test_partially_resolved_stacks_are_marked_as_such(monkeypatch):
    monkeypatch.setattr(ia, "image_architectures", _fake_lookup({"app": ["amd64"]}))
    result = ia.compose_architectures(
        {"services": {"app": {"image": "app"}, "mystery": {"image": "mystery"}}}
    )
    assert result["source"].startswith("partial-")
    assert result["unresolved"] == ["mystery"]


def test_a_build_only_stack_is_unknown_rather_than_unsupported():
    result = ia.compose_architectures({"services": {"web": {"build": "."}}})
    assert result["architectures"] == []
    assert result["source"] == ia.UNKNOWN


# --------------------------------------------------------------------------- #
# The verdict: runs here, does not run here, or not yet known
# --------------------------------------------------------------------------- #

def test_known_architecture_matching_the_host_runs_natively():
    assert ia.runs_natively_on(["amd64", "arm64"], "arm64") is True
    assert ia.runs_natively_on(["amd64"], "x86_64") is True


def test_known_architecture_not_matching_the_host_does_not():
    assert ia.runs_natively_on(["amd64"], "arm64") is False


def test_an_empty_architecture_list_is_never_read_as_unsupported():
    # This is what stops an unscanned catalog from disabling itself wholesale.
    assert ia.runs_natively_on([], "arm64") is None
    assert ia.runs_natively_on(None, "arm64") is None


def test_summary_distinguishes_unscanned_from_no_common_architecture():
    unscanned = {"architectures": [], "source": ia.UNKNOWN, "per_image": {}, "unresolved": ["x"]}
    conflicting = {"architectures": [], "source": "registry",
                   "per_image": {"a": ["amd64"], "b": ["arm64"]}, "unresolved": []}
    assert ia.summary_runs_natively(unscanned, "arm64") is None, "unscanned must stay unknown"
    assert ia.summary_runs_natively(conflicting, "arm64") is False, (
        "a stack whose images share no architecture needs emulation wherever it runs"
    )


def test_summary_reports_the_host_specific_answer():
    amd_only = {"architectures": ["amd64"], "source": "registry",
                "per_image": {"a": ["amd64"]}, "unresolved": []}
    assert ia.summary_runs_natively(amd_only, "arm64") is False
    assert ia.summary_runs_natively(amd_only, "x86_64") is True


@pytest.mark.parametrize("bad", [None, "nope", []])
def test_summary_handles_malformed_input(bad):
    assert ia.summary_runs_natively(bad, "arm64") is None


# --------------------------------------------------------------------------- #
# Reading a compose file from disk never raises
# --------------------------------------------------------------------------- #

def test_missing_compose_file_is_unknown_not_an_error():
    result = ia.architecture_summary_for_compose_file("/nonexistent/docker-compose.yml")
    assert result["architectures"] == []
    assert result["source"] == ia.UNKNOWN


def test_unparseable_compose_file_is_unknown_not_an_error(tmp_path):
    bad = tmp_path / "docker-compose.yml"
    bad.write_text("::: not yaml :::", encoding="utf-8")
    result = ia.architecture_summary_for_compose_file(str(bad))
    assert result["source"] == ia.UNKNOWN


def test_compose_file_on_disk_is_scanned(tmp_path, monkeypatch):
    monkeypatch.setattr(ia, "image_architectures", _fake_lookup({"nginx:1": ["amd64"]}))
    compose = tmp_path / "docker-compose.yml"
    compose.write_text("services:\n  web:\n    image: nginx:1\n", encoding="utf-8")
    result = ia.architecture_summary_for_compose_file(str(compose))
    assert result["architectures"] == ["amd64"]


# --------------------------------------------------------------------------- #
# Memoization: importing a repository must not re-query one image per generator
# --------------------------------------------------------------------------- #

def test_repeated_lookups_query_the_registry_once(monkeypatch):
    """An 80-generator repo sharing a base image resolved it 80 times, taking
    ~2.2s each, which made the import look hung."""
    calls: list[str] = []

    monkeypatch.setattr(ia, "_docker_available", lambda: True)
    monkeypatch.setattr(ia, "_architectures_from_local", lambda _i: [])

    def _registry(image):
        calls.append(image)
        return ["amd64", "arm64"]

    monkeypatch.setattr(ia, "_architectures_from_registry", _registry)

    for _ in range(25):
        archs, source = ia.image_architectures("shared/base:1")
        assert archs == ["amd64", "arm64"]
        assert source == "registry"

    assert calls == ["shared/base:1"]


def test_distinct_images_are_each_resolved(monkeypatch):
    calls: list[str] = []
    monkeypatch.setattr(ia, "_docker_available", lambda: True)
    monkeypatch.setattr(ia, "_architectures_from_local", lambda _i: [])

    def _registry(image):
        calls.append(image)
        return ["amd64"]

    monkeypatch.setattr(ia, "_architectures_from_registry", _registry)

    ia.image_architectures("one:1")
    ia.image_architectures("two:2")
    ia.image_architectures("one:1")

    assert calls == ["one:1", "two:2"]


def test_unresolved_lookups_expire_so_a_pulled_image_is_seen(monkeypatch):
    """A transient registry failure must not pin an image to 'unknown' for the
    life of a long-running webapp process."""
    monkeypatch.setattr(ia, "_docker_available", lambda: True)
    monkeypatch.setattr(ia, "_architectures_from_registry", lambda _i: [])
    monkeypatch.setattr(ia, "_architectures_from_local", lambda _i: [])

    archs, source = ia.image_architectures("later/pulled:1")
    assert archs == [] and source == ia.UNKNOWN

    # The image is now available locally, and the negative entry has aged out.
    monkeypatch.setattr(ia, "_architectures_from_local", lambda _i: ["arm64"])
    monkeypatch.setattr(
        ia, "_CACHE_TTL_UNRESOLVED_S", -1.0
    )

    archs, source = ia.image_architectures("later/pulled:1")
    assert archs == ["arm64"]
    assert source == "local"


def test_cached_result_cannot_be_mutated_by_a_caller(monkeypatch):
    monkeypatch.setattr(ia, "_docker_available", lambda: True)
    monkeypatch.setattr(ia, "_architectures_from_local", lambda _i: ["amd64"])

    first, _ = ia.image_architectures("mutate/me:1")
    first.append("sneaky")

    second, _ = ia.image_architectures("mutate/me:1")
    assert second == ["amd64"]
