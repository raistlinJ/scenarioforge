import json
import shutil
from types import SimpleNamespace

import pytest
from flask import Flask, jsonify

import scenarioforge.cli as cli
from scenarioforge.utils.guide_export import render_guides
from test_guide_exports import sample_challenges


@pytest.mark.skipif(shutil.which('node') is None, reason='Node.js required')
def test_cli_guides_exports_saved_flow_and_protects_existing_files(tmp_path, monkeypatch, capsys):
    nodes, assignments = sample_challenges()
    app = Flask(__name__)
    from flask import request

    def preview():
        assert request.args['prefer_flow'] == '1'
        assert request.args['xml_path'] == str(tmp_path / 'scenario.xml')
        return jsonify(ok=True, chain=nodes, flag_assignments=assignments,
                       participant_network_setup={'items': [{'address_cidr': '10.20.0.2/24', 'gateway': '10.20.0.1'}]})

    app.view_functions['api_flow_attackflow_preview'] = preview
    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: SimpleNamespace(app=app))
    monkeypatch.setattr(cli, '_cli_phase_scenario', lambda *a, **k: 'Training')
    monkeypatch.setattr(cli, '_flow_state_from_xml', lambda *a: {'chain': nodes})
    args = cli._build_cli_parser().parse_args(['guides', '--xml', str(tmp_path / 'scenario.xml')])
    assert cli._run_guides_phase(args) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload['ok']
    for fmt in ['html', 'md']:
        participant = (tmp_path / 'guides' / f'Training.participant-guide.{fmt}').read_text()
        facilitator = (tmp_path / 'guides' / f'Training.facilitator-guide.{fmt}').read_text()
        assert 'FLAG_ONLY_FOR_FACILITATOR' not in participant
        assert 'FACILITATOR_ONLY_PROVIDER' not in participant
        assert 'FLAG_ONLY_FOR_FACILITATOR_1' in facilitator
        assert '10.20.0.2/24' in participant
    assert cli._run_guides_phase(args) == 1
    assert 'already exists' in capsys.readouterr().err
    args.force = True
    args.guide_audience = 'participant'
    args.guide_format = 'markdown'
    assert cli._run_guides_phase(args) == 0
    assert set(json.loads(capsys.readouterr().out)['outputs']) == {'participant'}


def test_guides_missing_flow_does_not_create_outputs(tmp_path, monkeypatch, capsys):
    monkeypatch.setattr(cli, '_load_web_backend_module', lambda: object())
    monkeypatch.setattr(cli, '_cli_phase_scenario', lambda *a, **k: 'Training')
    monkeypatch.setattr(cli, '_flow_state_from_xml', lambda *a: None)
    args = cli._build_cli_parser().parse_args(['guides', '--xml', str(tmp_path / 'scenario.xml')])
    assert cli._run_guides_phase(args) == 1
    assert 'Run flag-sequencing first' in capsys.readouterr().err
    assert not (tmp_path / 'guides').exists()


def test_renderer_missing_node(monkeypatch):
    monkeypatch.setattr(shutil, 'which', lambda _: None)
    with pytest.raises(RuntimeError, match='requires Node.js'):
        render_guides('Training', {}, ['participant'])


def test_guides_phase_help():
    help_text = cli._build_cli_help_parser('guides').format_help()
    for flag in ['--guide-audience', '--guide-format', '--output-dir', '--output-prefix', '--force']:
        assert flag in help_text
