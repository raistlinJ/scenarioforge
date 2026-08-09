"""The node service's restart policy must be bounded.

CORE configures a docker node *after* its container is running -- interface
address, host-side default route, traffic agent -- all inside the container's
network namespace, and nothing re-applies them. An unbounded restart therefore
turns one crashing image into a silent loop that keeps discarding that config,
surfacing as unrelated reachability/routing/traffic failures.
"""

from scenarioforge.utils import vuln_process


def test_restart_attempts_are_bounded_and_small():
    assert isinstance(vuln_process.CORETG_NODE_RESTART_MAX_ATTEMPTS, int)
    assert 1 <= vuln_process.CORETG_NODE_RESTART_MAX_ATTEMPTS <= 5


def test_node_service_uses_capped_on_failure_not_unless_stopped():
    import inspect
    src = inspect.getsource(vuln_process)
    # The policy is written into the generated compose; assert on the source so
    # a future edit cannot quietly restore the unbounded form.
    assert "node_svc['restart'] = f'on-failure:{CORETG_NODE_RESTART_MAX_ATTEMPTS}'" in src
    assert "node_svc['restart'] = 'unless-stopped'" not in src


def test_policy_string_is_valid_compose_syntax():
    policy = f"on-failure:{vuln_process.CORETG_NODE_RESTART_MAX_ATTEMPTS}"
    kind, _, attempts = policy.partition(":")
    assert kind == "on-failure"
    assert attempts.isdigit() and int(attempts) > 0
