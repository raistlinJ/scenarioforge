"""Generate the evaluation artifact belonging to a successful execution."""
import io
import ipaddress
import json
import logging
import os
import zipfile
from pathlib import Path
from types import SimpleNamespace

from .export import export_package, sha256


def build_execution_package(*, backend, xml_path, scenario, session_id, core_cfg,
                            output, suite_id, allow=None, disallow=(), definitions=None, expected_xml_sha256=None, split="development"):

    from scenarioforge import cli

    xml_path = Path(xml_path).resolve()
    before = xml_path.read_bytes()
    if expected_xml_sha256 is not None and sha256(before) != expected_xml_sha256:
        raise ValueError("Scenario XML changed after execution; evaluation generation refused")
    state = cli._flow_state_from_xml(str(xml_path), scenario)
    if not isinstance(state, dict) or not state.get('chain'):
        raise ValueError('No saved resolved Flow chain; run flag sequencing before execution')
    graph = backend._attack_graph_for_chain(chain_nodes=state['chain'], scenario_label=scenario,
                                          flag_assignments=state.get('flag_assignments', []))
    if allow is None:
        allow = sorted({str(ipaddress.ip_network(f"{node['ipv4']}/32", strict=False))
                        for node in graph['nodes'] if node.get('ipv4')})
    readiness = {'status': 'unverified', 'checks': []}
    if session_id is not None:
        stream = io.StringIO()
        try:
            cli._run_cli_artifact_checks(backend=backend,
                args=SimpleNamespace(xml=str(xml_path), scenario=scenario), core_cfg=core_cfg,
                session_id=int(session_id), strict=True, stream=stream)
            markers = [line[len(cli.CHECK_ARTIFACTS_MARKER):].strip()
                       for line in stream.getvalue().splitlines() if line.startswith(cli.CHECK_ARTIFACTS_MARKER)]
            if markers:
                readiness = json.loads(markers[-1])
        except Exception:
            logging.getLogger(__name__).exception('Evaluation readiness collection failed')
            # Do not expose connection exceptions, which may contain credentials.
            readiness = {'status': 'error', 'ok': False, 'checks': [],
                         'error': 'Readiness checks failed; inspect the ScenarioForge server logs'}
    if xml_path.read_bytes() != before:
        raise ValueError('Scenario XML changed during evaluation generation; execute the saved version again')
    archive = Path(str(output) + ".zip")
    if archive.exists():
        raise ValueError("Evaluation ZIP already exists; choose a new output directory")
    manifest = export_package(xml_path=xml_path, graph=graph, output=output, suite_id=suite_id,
                              allow=allow, disallow=disallow, definitions=definitions,
                              readiness=readiness, split=split, session_id=int(session_id) if session_id is not None else None)
    output = Path(output)
    # Use manifest-relative paths, never arbitrary directory contents.
    temporary = archive.with_suffix('.zip.tmp')
    descriptor = os.open(temporary, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o600)
    try:
        with os.fdopen(descriptor, 'wb') as stream:
            with zipfile.ZipFile(stream, 'w', compression=zipfile.ZIP_DEFLATED) as bundle:
                for name in ['manifest.json', *manifest['files']]:
                    bundle.write(output / name, arcname=name)
            stream.flush()
            os.fsync(stream.fileno())
        temporary.replace(archive)
    finally:
        temporary.unlink(missing_ok=True)
    metadata = json.loads((output / 'evaluator/task-metadata.json').read_text())
    required = {key for task in metadata.values() for key in task['required_checks']}
    checks = {c.get('key'): c.get('status') for c in readiness.get('checks', [])}
    ready = (readiness.get('status') == 'complete' and readiness.get('ok') is True
             and readiness.get('overall') == 'pass' and readiness.get('session_confirmed') is True
             and readiness.get('xml_sha256') == sha256(before)
             and all(checks.get(key) == 'pass' for key in required))
    return {'state': 'complete', 'suite_id': suite_id, 'package_hash': manifest['package_hash'],
            'archive': str(archive.resolve()), 'allow': allow, 'disallow': list(disallow),
            'readiness_passed': ready,
            'message': 'Evaluation package ready' if ready else 'Package generated, but readiness did not pass; evaluation execution will be blocked'}
