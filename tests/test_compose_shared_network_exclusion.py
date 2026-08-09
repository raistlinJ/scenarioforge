"""A vuln/generator whose services talk to each other must still work under
CORE-only networking -- and the few that genuinely cannot must be excluded.

ScenarioForge runs every generated service with `network_mode: none` so an
exploited node cannot reach the host or another node through a Docker-managed
gateway. A vulnerability whose app addresses its *own* sidecar by service name
(nginx -> php-fpm, app -> db) could then never reach it and crash-looped
permanently. That took down a whole CORE session in a real eval run: nginx
crashed on `host not found in upstream "php"`, and CORE's daemon then threw an
unhandled exception wiring a veth into the dead container's stale PID, aborting
the rest of session boot including three unrelated routers.

The fix is a repair, not an exclusion: sidecars join the node's own network
namespace and reach each other over loopback, with `extra_hosts` mapping each
service name to 127.0.0.1 so the recipe's own config resolves unchanged. The
namespace holds only `lo` -- no Docker interface, no gateway, no route to the
host -- so isolation is preserved and CORE still owns eth0.

Only stacks that cannot share one namespace stay excluded: one namespace is one
port space, so two services binding the same container port genuinely collide.

Coverage:
  1. The repair transform itself.
  2. The blocker detector that decides repairable vs. not.
  3. Batch scans of the installed vuln catalog and generator packs, if present
     on this machine (skipped otherwise -- they are local state, not in the repo).
"""

from __future__ import annotations

import os
from pathlib import Path

import pytest
import yaml

from scenarioforge.utils.compose_networking import (
    compose_stack_needs_shared_network,
    compose_stack_shared_netns_blockers,
    compose_stack_shared_netns_plan,
)
from scenarioforge.utils.vuln_process import (
    _apply_shared_netns_sidecars,
    _vuln_catalog_item_unusable_under_core_networking,
    load_vuln_catalog,
)
from scenarioforge.generator_manifests import discover_generator_manifests


REPO_ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------------------- #
# 1. Does this stack rely on service-to-service networking at all?
# --------------------------------------------------------------------------- #

def test_single_service_stack_never_needs_a_shared_network():
    assert not compose_stack_needs_shared_network({"services": {"web": {"image": "nginx"}}})


def test_multi_service_stack_with_no_isolation_needs_a_shared_network():
    obj = {
        "services": {
            "nginx": {"image": "vulhub/nginx:1.4.2"},
            "php": {"image": "vulhub/php:5.6-fpm"},
        }
    }
    assert compose_stack_needs_shared_network(obj)


def test_multi_service_stack_already_self_isolated_does_not_need_one():
    obj = {
        "services": {
            "a": {"image": "x", "network_mode": "none"},
            "b": {"image": "y", "network_mode": "none"},
        }
    }
    assert not compose_stack_needs_shared_network(obj)


def test_explicit_depends_on_or_links_are_not_required_to_detect_the_need():
    # The upstream vulhub nginx/CVE-2013-4547 recipe -- confirmed against the
    # real file -- declares neither `depends_on` nor `links` nor `networks`;
    # vanilla `docker-compose up` needs none of them for service-name DNS. A
    # detector requiring an explicit marker would miss the exact recipe that
    # broke a real run.
    obj = {
        "services": {
            "nginx": {"image": "vulhub/nginx:1.4.2",
                      "volumes": ["./nginx.conf:/usr/local/nginx/conf/nginx.conf"]},
            "php": {"image": "vulhub/php:5.6-fpm", "command": ["php-fpm"]},
        }
    }
    assert compose_stack_needs_shared_network(obj)


@pytest.mark.parametrize("bad", [None, [], "not a dict", {"services": "not a dict"}, {}])
def test_malformed_input_is_treated_as_not_needing_one(bad):
    assert not compose_stack_needs_shared_network(bad)


# --------------------------------------------------------------------------- #
# 2. Repairable vs. not: one namespace is one port space
# --------------------------------------------------------------------------- #

def test_distinct_ports_are_repairable():
    obj = {
        "services": {
            "nginx": {"image": "n", "ports": ["8080:80"]},
            "php": {"image": "p", "expose": ["9000"]},
        }
    }
    assert compose_stack_shared_netns_blockers(obj) == []


def test_a_duplicate_instance_is_dropped_rather_than_blocking_the_stack():
    # The real shape of php/xdebug-rce: two independent web apps, both on
    # container port 80, published to different host ports. Different host
    # ports do not help -- inside one namespace both want to bind :80. Only one
    # can be the node, so the duplicate is dropped and the recipe still works.
    obj = {
        "services": {
            "xdebug2": {"image": "a", "ports": ["8080:80"]},
            "xdebug3": {"image": "b", "ports": ["8081:80"]},
        }
    }
    plan = compose_stack_shared_netns_plan(obj)
    assert plan["blockers"] == []
    assert plan["drop"] == ["xdebug3"]


def test_a_duplicate_that_something_kept_depends_on_still_blocks():
    # Dropping it would leave a dangling `depends_on` and a broken stack, so
    # this is the case that genuinely cannot be repaired.
    obj = {
        "services": {
            "web": {"image": "a", "ports": ["8080:80"]},
            "twin": {"image": "b", "ports": ["8081:80"]},
            "worker": {"image": "c", "depends_on": ["twin"]},
        }
    }
    plan = compose_stack_shared_netns_plan(obj)
    assert plan["blockers"] == ["80"]
    assert "twin" not in plan["drop"]


def test_the_node_service_is_never_the_one_dropped():
    obj = {
        "services": {
            "docker-8": {"image": "a", "ports": ["8080:80"]},
            "twin": {"image": "b", "ports": ["8081:80"]},
        }
    }
    assert compose_stack_shared_netns_plan(obj, "docker-8")["drop"] == ["twin"]


def test_inject_copy_helper_is_ignored_when_looking_for_conflicts():
    # ScenarioForge injects its own one-shot copier; it binds nothing and must
    # never be what makes a stack look unrepairable.
    obj = {
        "services": {
            "web": {"image": "w", "ports": ["8080:80"]},
            "inject_copy": {"image": "alpine", "ports": ["9999:80"]},
        }
    }
    assert compose_stack_shared_netns_blockers(obj) == []


def test_port_forms_are_normalised_before_comparison():
    # "127.0.0.1:8080:80/tcp" and "80/tcp" are the same container port, so the
    # second service is recognised as the duplicate.
    obj = {
        "services": {
            "a": {"ports": ["127.0.0.1:8080:80/tcp"]},
            "b": {"expose": ["80/tcp"]},
        }
    }
    assert compose_stack_shared_netns_plan(obj)["drop"] == ["b"]


# --------------------------------------------------------------------------- #
# 3. The repair transform
# --------------------------------------------------------------------------- #

def _nginx_php_stack():
    return {
        "services": {
            "docker-8": {
                "image": "vulhub/nginx:1.4.2",
                "ports": ["8080:80"],
                "depends_on": ["inject_copy"],
            },
            "php": {"image": "vulhub/php:5.6-fpm", "command": ["php-fpm"]},
            "inject_copy": {"image": "alpine:3.19", "network_mode": "none"},
        }
    }


def test_repair_puts_sidecars_in_the_nodes_namespace():
    out, applied, reason = _apply_shared_netns_sidecars(_nginx_php_stack(), "docker-8")
    assert applied, reason
    assert out["services"]["php"]["network_mode"] == "service:docker-8"
    # Joining a namespace requires the owner to exist first.
    assert out["services"]["php"]["depends_on"] == ["docker-8"]


def test_repair_keeps_the_node_isolated_exactly_as_before():
    # The whole point: the node's own posture is unchanged, so CORE still owns
    # eth0 and there is still no Docker gateway.
    out, applied, _ = _apply_shared_netns_sidecars(_nginx_php_stack(), "docker-8")
    assert applied
    assert out["services"]["docker-8"]["network_mode"] == "none"
    assert "networks" not in out


def test_repair_maps_sidecar_names_to_loopback_so_recipe_configs_resolve():
    # `fastcgi_pass php:9000` must keep working verbatim -- this mapping is what
    # turns the original "host not found in upstream" crash into a working path.
    out, applied, _ = _apply_shared_netns_sidecars(_nginx_php_stack(), "docker-8")
    assert applied
    assert "php:127.0.0.1" in out["services"]["docker-8"]["extra_hosts"]


def test_repair_preserves_the_inject_copy_dependency():
    # Dropping it leaves /flow_injects empty even when the artifacts exist.
    out, applied, _ = _apply_shared_netns_sidecars(_nginx_php_stack(), "docker-8")
    assert applied
    assert out["services"]["docker-8"]["depends_on"] == ["inject_copy"]


def test_repair_converts_host_published_ports_to_expose():
    out, applied, _ = _apply_shared_netns_sidecars(_nginx_php_stack(), "docker-8")
    assert applied
    node = out["services"]["docker-8"]
    assert "ports" not in node
    assert "80" in [str(p) for p in node.get("expose", [])]


def test_repair_repoints_an_inherited_sidecar_mapping_at_loopback():
    # After the repair the sidecar genuinely lives on loopback, so a mapping
    # inherited from the recipe that points anywhere else is now wrong and
    # would leave the stack as broken as before.
    stack = _nginx_php_stack()
    stack["services"]["docker-8"]["extra_hosts"] = ["php:10.0.0.9"]
    out, applied, _ = _apply_shared_netns_sidecars(stack, "docker-8")
    assert applied
    entries = out["services"]["docker-8"]["extra_hosts"]
    assert "php:127.0.0.1" in entries
    assert "php:10.0.0.9" not in entries


def test_repair_leaves_non_sidecar_host_mappings_alone():
    # A recipe pinning a genuinely external hostname is not ours to rewrite.
    stack = _nginx_php_stack()
    stack["services"]["docker-8"]["extra_hosts"] = ["api.example.com:203.0.113.5"]
    out, applied, _ = _apply_shared_netns_sidecars(stack, "docker-8")
    assert applied
    entries = out["services"]["docker-8"]["extra_hosts"]
    assert "api.example.com:203.0.113.5" in entries
    assert "php:127.0.0.1" in entries


def test_repair_does_not_duplicate_sidecar_mappings_when_run_twice():
    stack = _nginx_php_stack()
    out, applied, _ = _apply_shared_netns_sidecars(stack, "docker-8")
    assert applied
    out2, applied2, _ = _apply_shared_netns_sidecars(out, "docker-8")
    assert applied2
    entries = out2["services"]["docker-8"]["extra_hosts"]
    assert entries.count("php:127.0.0.1") == 1


def test_repair_drops_a_duplicate_instance_and_keeps_real_sidecars():
    # The ecshop shape: two app instances plus one genuine shared sidecar. The
    # duplicate app goes; the sidecar stays and joins the namespace.
    stack = {
        "services": {
            "docker-8": {"image": "a", "ports": ["8080:80"], "depends_on": ["mysql"]},
            "twin": {"image": "b", "ports": ["8081:80"], "depends_on": ["mysql"]},
            "mysql": {"image": "m"},
        }
    }
    out, applied, reason = _apply_shared_netns_sidecars(stack, "docker-8")
    assert applied
    assert "twin" not in out["services"], "the duplicate instance should be dropped"
    assert out["services"]["mysql"]["network_mode"] == "service:docker-8"
    assert "twin" in reason and "dropped" in reason


def test_repair_still_refuses_when_a_duplicate_cannot_be_dropped():
    stack = {
        "services": {
            "docker-8": {"image": "a", "ports": ["8080:80"]},
            "twin": {"image": "b", "ports": ["8081:80"]},
            "worker": {"image": "c", "depends_on": ["twin"]},
        }
    }
    out, applied, reason = _apply_shared_netns_sidecars(stack, "docker-8")
    assert not applied
    assert "80" in reason
    # Refusing must leave the input untouched for the caller's fallback path.
    assert "twin" in out["services"]


def test_repair_is_a_noop_for_a_single_service_stack():
    stack = {"services": {"docker-8": {"image": "a"}}}
    _out, applied, reason = _apply_shared_netns_sidecars(stack, "docker-8")
    assert not applied
    assert "no sidecars" in reason


def test_repair_reports_when_the_node_service_is_absent():
    stack = {"services": {"web": {"image": "a"}, "db": {"image": "b"}}}
    _out, applied, reason = _apply_shared_netns_sidecars(stack, "docker-8")
    assert not applied
    assert "not in compose" in reason


@pytest.mark.parametrize("bad", [None, "nope", {}, {"services": None}])
def test_repair_handles_malformed_input(bad):
    _out, applied, _reason = _apply_shared_netns_sidecars(bad, "docker-8")
    assert not applied


# --------------------------------------------------------------------------- #
# 4. Batch scan: the installed vulnerability catalog, if present
# --------------------------------------------------------------------------- #

def _installed_vuln_catalog_present() -> bool:
    return (REPO_ROOT / "outputs" / "installed_vuln_catalogs" / "_catalogs_state.json").exists()


@pytest.mark.skipif(not _installed_vuln_catalog_present(), reason="no vuln catalog installed on this machine")
def test_no_selectable_vuln_is_unusable_under_core_networking(monkeypatch):
    monkeypatch.delenv("CORETG_COMPOSE_ALLOW_INTERNAL_NETWORKING", raising=False)

    catalog = load_vuln_catalog(str(REPO_ROOT))
    assert catalog, "catalog state exists but load_vuln_catalog returned nothing"

    offenders = [
        item.get("Name") for item in catalog
        if _vuln_catalog_item_unusable_under_core_networking(item)
    ]
    assert not offenders, (
        f"{len(offenders)} selectable vuln(s) cannot work under CORE-only networking and "
        f"may take the whole scenario down: {sorted(offenders)[:10]}"
    )


@pytest.mark.skipif(not _installed_vuln_catalog_present(), reason="no vuln catalog installed on this machine")
def test_multi_service_vulns_are_repaired_rather_than_excluded(monkeypatch):
    # Regression guard for the fix's whole purpose: before the shared-namespace
    # repair, every multi-service recipe was dropped (80 of 295 in the catalog
    # this was built against). They should now be selectable again.
    monkeypatch.delenv("CORETG_COMPOSE_ALLOW_INTERNAL_NETWORKING", raising=False)
    catalog = load_vuln_catalog(str(REPO_ROOT))

    multi_service = 0
    for item in catalog:
        path = str(item.get("Path") or "")
        if not path or not os.path.exists(path):
            continue
        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                compose_obj = yaml.safe_load(f)
        except Exception:
            continue
        if compose_stack_needs_shared_network(compose_obj):
            multi_service += 1

    assert multi_service > 0, (
        "no multi-service vulnerability is selectable -- the shared-namespace "
        "repair is not taking effect and they are being excluded again"
    )


@pytest.mark.skipif(not _installed_vuln_catalog_present(), reason="no vuln catalog installed on this machine")
def test_opting_in_skips_the_filter_entirely(monkeypatch):
    monkeypatch.delenv("CORETG_COMPOSE_ALLOW_INTERNAL_NETWORKING", raising=False)
    filtered = load_vuln_catalog(str(REPO_ROOT))

    monkeypatch.setenv("CORETG_COMPOSE_ALLOW_INTERNAL_NETWORKING", "1")
    full = load_vuln_catalog(str(REPO_ROOT))

    assert len(full) >= len(filtered)


# --------------------------------------------------------------------------- #
# 5. Batch scan: installed generator packs, if present
# --------------------------------------------------------------------------- #

@pytest.mark.parametrize("kind", ["flag-generator", "flag-node-generator"])
def test_no_enabled_generator_is_unusable_under_core_networking(kind, monkeypatch):
    if not (REPO_ROOT / "outputs" / "installed_generators").exists():
        pytest.skip("no installed generator packs on this machine")
    monkeypatch.delenv("CORETG_COMPOSE_ALLOW_INTERNAL_NETWORKING", raising=False)

    generators, _plugins, errors = discover_generator_manifests(
        repo_root=str(REPO_ROOT), kind=kind, include_disabled=False,
    )
    assert not errors, f"manifest load errors for {kind}: {errors[:5]}"

    offenders = [(g.get("id"), g.get("name")) for g in generators if g.get("_disabled_reason")]
    assert not offenders, (
        f"{len(offenders)} enabled {kind}(s) cannot work under CORE-only networking: {offenders[:10]}"
    )


# --------------------------------------------------------------------------- #
# 6. The repair must survive the real generation pipeline, not just unit calls
# --------------------------------------------------------------------------- #
#
# Two ordering traps make this worth testing end to end rather than only
# against `_apply_shared_netns_sidecars` directly:
#
#   * the node service is only renamed to its CORE name (`docker-8`) late, in
#     the alias step -- repairing before that names the wrong service in the
#     sidecars' `network_mode: service:<node>`;
#   * by then every service has been forced to `network_mode: none`, so asking
#     "does this stack need service networking?" at that point answers False.
#     The verdict has to be captured before that transform runs.
#
# Both were live bugs caught only by exercising the real entry point.

def test_generation_pipeline_applies_the_repair(tmp_path, monkeypatch):
    from scenarioforge.utils.vuln_process import prepare_compose_for_assignments

    monkeypatch.delenv("CORETG_COMPOSE_ALLOW_INTERNAL_NETWORKING", raising=False)

    recipe = tmp_path / "recipe" / "docker-compose.yml"
    recipe.parent.mkdir(parents=True)
    recipe.write_text(
        "services:\n"
        "  nginx:\n"
        "    image: vulhub/nginx:1.4.2\n"
        "    ports:\n"
        '     - "8080:80"\n'
        "  php:\n"
        "    image: vulhub/php:5.6-fpm\n",
        encoding="utf-8",
    )

    out_base = tmp_path / "out"
    written = prepare_compose_for_assignments(
        {"docker-8": {"Name": "nginx/CVE-2013-4547", "Path": str(recipe),
                      "Type": "docker-compose", "Vector": ""}},
        out_base=str(out_base),
    )
    generated = [p for p in (written or []) if p.endswith(".yml") and "orig" not in p]
    assert generated, "pipeline produced no compose file"

    with open(generated[0], "r", encoding="utf-8") as f:
        obj = yaml.safe_load(f)
    services = obj["services"]

    # The node keeps CORE's isolation and owns the namespace.
    assert services["docker-8"]["network_mode"] == "none"
    # The sidecar joins it, named by the node's FINAL name.
    assert services["php"]["network_mode"] == "service:docker-8"
    # ...and the recipe's own `fastcgi_pass php:9000` resolves.
    assert "php:127.0.0.1" in services["docker-8"]["extra_hosts"]


def test_generation_pipeline_leaves_single_service_recipes_isolated(tmp_path, monkeypatch):
    from scenarioforge.utils.vuln_process import prepare_compose_for_assignments

    monkeypatch.delenv("CORETG_COMPOSE_ALLOW_INTERNAL_NETWORKING", raising=False)

    recipe = tmp_path / "recipe" / "docker-compose.yml"
    recipe.parent.mkdir(parents=True)
    recipe.write_text(
        "services:\n  web:\n    image: nginx\n    ports:\n     - \"8080:80\"\n",
        encoding="utf-8",
    )
    written = prepare_compose_for_assignments(
        {"docker-9": {"Name": "x/single", "Path": str(recipe),
                      "Type": "docker-compose", "Vector": ""}},
        out_base=str(tmp_path / "out"),
    )
    generated = [p for p in (written or []) if p.endswith(".yml") and "orig" not in p]
    assert generated
    with open(generated[0], "r", encoding="utf-8") as f:
        obj = yaml.safe_load(f)
    # Nothing to share a namespace with; unchanged posture.
    assert obj["services"]["docker-9"]["network_mode"] == "none"
    assert not any(
        str(svc.get("network_mode", "")).startswith("service:")
        for svc in obj["services"].values()
    )


# --------------------------------------------------------------------------- #
# 7. Namespace-sharing sidecars must actually be started
# --------------------------------------------------------------------------- #
#
# `docker compose up -d <node>` -- what CORE runs -- starts only the node and
# what the node depends on. The dependency here runs the other way (the sidecar
# joins the node's namespace, so it depends on the node), and declaring it in
# reverse is a cycle Compose rejects outright. Verified against Docker: without
# an explicit start the node comes up alone and its own sidecar never runs.

def test_shared_namespace_sidecars_are_discoverable_for_startup(tmp_path):
    from scenarioforge.builders.topology import _compose_shared_namespace_services

    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n"
        "  docker-8:\n    image: n\n    network_mode: none\n"
        "  php:\n    image: p\n    network_mode: \"service:docker-8\"\n"
        "  inject_copy:\n    image: a\n    network_mode: none\n",
        encoding="utf-8",
    )
    assert _compose_shared_namespace_services(str(compose), "docker-8") == ["php"]


def test_no_sidecars_reported_for_a_plain_isolated_stack(tmp_path):
    from scenarioforge.builders.topology import _compose_shared_namespace_services

    compose = tmp_path / "docker-compose.yml"
    compose.write_text(
        "services:\n  docker-8:\n    image: n\n    network_mode: none\n", encoding="utf-8"
    )
    assert _compose_shared_namespace_services(str(compose), "docker-8") == []


def test_sidecar_discovery_survives_a_missing_or_unreadable_file(tmp_path):
    from scenarioforge.builders.topology import _compose_shared_namespace_services

    assert _compose_shared_namespace_services(str(tmp_path / "nope.yml"), "docker-8") == []
    bad = tmp_path / "bad.yml"
    bad.write_text("::: not yaml :::", encoding="utf-8")
    assert _compose_shared_namespace_services(str(bad), "docker-8") == []


# --------------------------------------------------------------------------- #
# 8. Duplicate instances must survive the real pipeline's transform order
# --------------------------------------------------------------------------- #
#
# A third ordering trap, caught only end to end: secondary services have their
# `ports`/`expose` stripped before the repair runs (they conflict with
# `network_mode: service:`), which erases the very port collisions the drop plan
# is computed from. Recomputing at repair time finds nothing and keeps both
# instances, which then fight over the port at runtime. The plan has to be
# captured against the original recipe.

def _write_recipe(tmp_path, body):
    recipe = tmp_path / "recipe" / "docker-compose.yml"
    recipe.parent.mkdir(parents=True, exist_ok=True)
    recipe.write_text(body, encoding="utf-8")
    return recipe


def _generated(tmp_path, recipe, node):
    from scenarioforge.utils.vuln_process import prepare_compose_for_assignments

    written = prepare_compose_for_assignments(
        {node: {"Name": "x/dup", "Path": str(recipe), "Type": "docker-compose", "Vector": ""}},
        out_base=str(tmp_path / f"out-{node}"),
    )
    generated = [p for p in (written or []) if p.endswith(".yml") and "orig" not in p]
    assert generated, "pipeline produced no compose file"
    with open(generated[0], "r", encoding="utf-8") as f:
        return yaml.safe_load(f)["services"]


def test_pipeline_drops_a_duplicate_instance_and_keeps_the_real_sidecar(tmp_path, monkeypatch):
    # The ecshop shape: two app versions plus one shared mysql.
    monkeypatch.delenv("CORETG_COMPOSE_ALLOW_INTERNAL_NETWORKING", raising=False)
    recipe = _write_recipe(tmp_path, (
        "services:\n"
        "  ecshop27:\n    image: vulhub/ecshop:2.7.3\n    depends_on: [mysql]\n"
        '    ports: ["8080:80"]\n'
        "  ecshop36:\n    image: vulhub/ecshop:3.6.0\n    depends_on: [mysql]\n"
        '    ports: ["8081:80"]\n'
        "  mysql:\n    image: mysql:5.5\n"
    ))
    services = _generated(tmp_path, recipe, "docker-5")

    assert "ecshop36" not in services, "the duplicate instance must be dropped"
    assert services["docker-5"]["network_mode"] == "none"
    assert services["mysql"]["network_mode"] == "service:docker-5", "the real sidecar stays"
    assert "mysql:127.0.0.1" in services["docker-5"]["extra_hosts"]


def test_pipeline_drops_a_duplicate_with_no_sidecar_at_all(tmp_path, monkeypatch):
    # The php/xdebug-rce shape: two independent instances, nothing else.
    monkeypatch.delenv("CORETG_COMPOSE_ALLOW_INTERNAL_NETWORKING", raising=False)
    recipe = _write_recipe(tmp_path, (
        "services:\n"
        '  xdebug2:\n    image: vulhub/php:7.1-xdebug\n    ports: ["8080:80"]\n'
        '  xdebug3:\n    image: vulhub/php:7.4-xdebug\n    ports: ["8081:80"]\n'
    ))
    services = _generated(tmp_path, recipe, "docker-6")

    assert "xdebug3" not in services
    assert services["docker-6"]["network_mode"] == "none"
    # Nothing is left needing the namespace, and the node is a valid target.
    assert not any(
        str(s.get("network_mode", "")).startswith("service:") for s in services.values()
    )
