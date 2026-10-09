"""Explicitly remove one owned CORE session using the normal CLI connection config.

Usable independently of CAF/orchestrator; never deletes unrelated sessions.
"""

import argparse
import json
from scenarioforge import cli


def reset_session(xml, scenario, session_id):
    if type(session_id) is not int or session_id < 1:
        raise ValueError("A positive owned CORE session ID is required")
    backend = cli._load_web_backend_module()
    args = cli._build_cli_parser().parse_args(
        ["execute", "--xml", str(xml), "--scenario", scenario]
    )
    _, config, _ = cli._resolve_cli_core_context(
        args, backend=backend, scenario_name=scenario
    )
    if cli._cli_should_delegate_remote(config):
        config = backend._require_core_ssh_credentials(config)
        errors = []
        sessions = backend._list_active_core_sessions_via_remote_python(
            config, errors=errors, logger=backend.app.logger
        )
        if errors:
            raise RuntimeError("Could not confirm CORE session inventory before reset")
        if not any(str(row.get("id")) == str(session_id) for row in sessions):
            return dict(status="ok", session_id=session_id, already_absent=True)
        result = backend._execute_remote_core_session_action(
            config, "delete", session_id, logger=backend.app.logger
        )
        sessions = backend._list_active_core_sessions_via_remote_python(
            config, errors=errors, logger=backend.app.logger
        )
        if errors or any(str(row.get("id")) == str(session_id) for row in sessions):
            raise RuntimeError("CORE session deletion was not confirmed")
        return result
    from core.api.grpc.client import CoreGrpcClient

    client = CoreGrpcClient(
        address=f"{config.get('host','localhost')}:{config.get('port',50051)}"
    )
    client.connect()
    try:
        identify = lambda row: (
            row.get("id") if isinstance(row, dict) else getattr(row, "id", None)
        )
        if not any(
            str(identify(row)) == str(session_id) for row in client.get_sessions() or []
        ):
            return dict(status="ok", session_id=session_id, already_absent=True)
        client.delete_session(session_id)
        if any(
            str(identify(row)) == str(session_id) for row in client.get_sessions() or []
        ):
            raise RuntimeError("CORE session deletion was not confirmed")
    finally:
        closer = getattr(client, "close", None) or getattr(client, "disconnect", None)
        if callable(closer):
            closer()
    return dict(status="ok", session_id=session_id)


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--xml", required=True)
    parser.add_argument("--scenario", required=True)
    parser.add_argument("--session", type=int, required=True)
    args = parser.parse_args(argv)
    print(json.dumps(reset_session(args.xml, args.scenario, args.session)))


if __name__ == "__main__":
    main()
