import unittest

from simulator import SolverSession


def _node(label, ip, adjacent=None, adjacent_ips=None, gen_id=""):
    return {
        "label": label,
        "ip": ip,
        "type": "Docker",
        "gen_id": gen_id,
        "gen_name": "",
        "gen_kind": "",
        "gen_catalog": "",
        "flag": "",
        "file_path": "",
        "binary_path": "",
        "file_paths": [],
        "file_content": "",
        "resolved_outputs": {},
        "resolved_inputs": {},
        "binary_hint": "",
        "cve": "",
        "vulnerabilities": [],
        "is_vuln": False,
        "services": ["SSH"],
        "adjacent": adjacent or [],
        "adjacent_ips": adjacent_ips or [],
    }


def _make_sim():
    node_state = {
        "n1": _node("docker-1", "10.0.1.1", adjacent=["docker-2"], adjacent_ips=["10.0.1.2"]),
        "n2": _node("docker-2", "10.0.1.2", adjacent=["docker-1"], adjacent_ips=["10.0.1.1"]),
        "n3": _node("docker-3", "10.0.1.3"),  # unreachable from n1: no adjacency either way
    }
    return {
        "root_id":     "n1",
        "node_state":  node_state,
        "label_to_id": {"docker-1": "n1", "docker-2": "n2", "docker-3": "n3"},
        "ip_to_id":    {"10.0.1.1": "n1", "10.0.1.2": "n2", "10.0.1.3": "n3"},
        "node_counts": {"Docker": 3},
        "ip_map": {"n1": "10.0.1.1", "n2": "10.0.1.2", "n3": "10.0.1.3"},
        "node_map": {},
        "port_map": {},
        "svc_banners": {},
        "fact_dependencies": [],
    }


class EchoTests(unittest.TestCase):
    def test_echo_returns_its_argument(self):
        session = SolverSession(_make_sim())
        self.assertEqual(session.run_command("echo hello world"), "hello world")

    def test_echo_strips_surrounding_quotes(self):
        session = SolverSession(_make_sim())
        self.assertEqual(session.run_command('echo "hello world"'), "hello world")

    def test_bare_echo_returns_empty_string(self):
        session = SolverSession(_make_sim())
        self.assertEqual(session.run_command("echo"), "")


class PingTests(unittest.TestCase):
    def test_ping_missing_target_is_a_usage_error(self):
        session = SolverSession(_make_sim())
        self.assertEqual(session.run_command("ping"), "ping: usage error: Destination address required")

    def test_ping_unknown_host_reports_name_not_known(self):
        session = SolverSession(_make_sim())
        self.assertEqual(session.run_command("ping nosuchhost"),
                          "ping: nosuchhost: Name or service not known")

    def test_ping_adjacent_node_by_label_succeeds(self):
        session = SolverSession(_make_sim())
        output = session.run_command("ping docker-2")
        self.assertIn("PING docker-2 (10.0.1.2)", output)
        self.assertIn("0% packet loss", output)

    def test_ping_adjacent_node_by_ip_succeeds(self):
        session = SolverSession(_make_sim())
        output = session.run_command("ping -c 3 10.0.1.2")
        self.assertIn("PING 10.0.1.2 (10.0.1.2)", output)
        self.assertIn("0% packet loss", output)

    def test_ping_current_node_succeeds(self):
        session = SolverSession(_make_sim())
        output = session.run_command("ping docker-1")
        self.assertIn("0% packet loss", output)

    def test_ping_non_adjacent_known_node_is_unreachable(self):
        session = SolverSession(_make_sim())
        output = session.run_command("ping docker-3")
        self.assertIn("Destination Host Unreachable", output)
        self.assertIn("100% packet loss", output)


class UnknownCommandHintTests(unittest.TestCase):
    def test_fallback_hint_mentions_ping_and_echo(self):
        session = SolverSession(_make_sim())
        output = session.run_command("frobnicate")
        self.assertIn("ping", output)
        self.assertIn("echo", output)


if __name__ == "__main__":
    unittest.main()
