"""Live progress output for CLI artifact checks."""

import io
from types import SimpleNamespace

from scenarioforge import cli


class _ProgressBackend:
    def __init__(self):
        self.scheduled = False
        self.payloads = [
            {
                'status': 'running', 'step': 1, 'total': 2, 'label': 'Checking containers',
            },
            {
                'status': 'running', 'step': 1, 'total': 2, 'label': 'Checking containers',
            },
            {
                'status': 'running', 'step': 2, 'total': 2, 'label': 'Checking services',
            },
            {
                'status': 'complete', 'step': 2, 'total': 2, 'label': 'Complete',
                'overall': 'pass', 'overall_summary': '2 passed', 'checks': [
                    {
                        'key': 'containers', 'label': 'Checking containers',
                        'status': 'pass', 'summary': 'ok', 'items': [],
                    },
                    {
                        'key': 'services', 'label': 'Checking services',
                        'status': 'pass', 'summary': 'ok', 'items': [],
                    },
                ],
            },
        ]

    def _list_active_core_sessions(self, host, port, core_cfg):
        return [{'id': 7}]

    def _init_artifact_check_progress(self, check_id, *, session_id, scenario):
        self.check_id = check_id

    def _schedule_artifact_checks(self, check_id, **kwargs):
        self.scheduled = True

    def _get_artifact_check_progress(self, check_id):
        if len(self.payloads) > 1:
            return self.payloads.pop(0)
        return self.payloads[0]


def test_cli_prints_each_artifact_check_step_as_it_changes(monkeypatch):
    backend = _ProgressBackend()
    args = SimpleNamespace(scenario='Progress scenario', xml='/tmp/scenario.xml')
    out = io.StringIO()
    monkeypatch.setattr(cli.time, 'sleep', lambda _seconds: None)

    ok = cli._run_cli_artifact_checks(
        backend=backend,
        args=args,
        core_cfg={'host': 'localhost', 'port': 50051},
        session_id=7,
        stream=out,
    )

    text = out.getvalue()
    assert ok is True
    assert backend.scheduled is True
    assert text.count('[check-artifacts] Step 1/2: Checking containers') == 1
    assert text.count('[check-artifacts] Step 2/2: Checking services') == 1
    assert text.index('Step 1/2') < text.index('Step 2/2') < text.index('Artifact checks')
