"""Offline installer contracts: never invoke apt, git, qm, or guest commands."""
import os
from pathlib import Path
import shlex
import subprocess

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / 'scripts/provision/proxmox/install-scenarioforge-lab.sh'


def probe(body, *, env=None):
    clean = {k: v for k, v in os.environ.items() if not k.startswith('SF_')}
    clean.update(env or {})
    return subprocess.run(['bash', '-c', f'source {shlex.quote(str(INSTALLER))}\n{body}'],
                          capture_output=True, text=True, env=clean, timeout=20)


def test_defaults_and_opt_in():
    result = probe('printf "%s|%s|%s|%s" "$ORCHESTRATOR" "$ORCHESTRATOR_URL" "$CYBER_AGENT_FLOW_EVAL_URL" "$CYBER_AGENT_FLOW_EVAL_REF"')
    assert result.returncode == 0, result.stderr
    assert result.stdout == '0|https://github.com/raistlinJ/cyber-agent-flow-orchestrator.git|https://github.com/raistlinJ/cyber-agent-flow-eval.git|main'


def test_config_environment_and_cli_precedence(tmp_path):
    config = tmp_path / 'lab.conf'
    config.write_text('orchestrator=false\norchestrator_url=https://example.org/config.git\norchestrator_ref=config\ncyber_agent_flow_eval_url=https://example.org/eval.git\ncyber_agent_flow_eval_ref=eval-config\n')
    result = probe(f'''parse_args --config {shlex.quote(str(config))} --orchestrator --orchestrator-ref cli --cyber-agent-flow-eval-ref eval-cli >&2
printf '%s|%s|%s|%s|%s' "$ORCHESTRATOR" "$ORCHESTRATOR_URL" "$ORCHESTRATOR_REF" "$CYBER_AGENT_FLOW_EVAL_URL" "$CYBER_AGENT_FLOW_EVAL_REF"
''', env={'SF_ORCHESTRATOR_URL': 'https://example.org/environment.git'})
    assert result.returncode == 0, result.stderr
    assert result.stdout == '1|https://example.org/environment.git|cli|https://example.org/eval.git|eval-cli'


@pytest.mark.parametrize('assignment', [
    'ORCHESTRATOR=bogus',
    'ORCHESTRATOR_URL=file:///tmp/repo',
    'ORCHESTRATOR_URL=https://user:password@example.org/repo',
    'ORCHESTRATOR_REF=--upload-pack=evil',
    'CYBER_AGENT_FLOW_EVAL_URL=ssh://example.org/repo',
    'CYBER_AGENT_FLOW_EVAL_REF=--evil',
])
def test_invalid_host_sources_rejected_without_caf(assignment):
    result = probe(f'ORCHESTRATOR=1\nCYBER_AGENT_FLOW=0\n{assignment}\nvalidate_orchestrator')
    assert result.returncode != 0


def test_disabled_orchestrator_does_nothing():
    result = probe('run() { exit 99; }; ORCHESTRATOR=0; install_orchestrator')
    assert result.returncode == 0, result.stderr
    assert result.stdout == ''


def test_host_dry_run_plans_both_packages_without_writes(tmp_path):
    target = tmp_path / 'host'
    result = probe(f'''parse_args install-orchestrator --dry-run --orchestrator-url https://example.org/orch.git --cyber-agent-flow-eval-url https://example.org/eval.git
[[ "$COMMAND" == install-orchestrator ]]
ORCHESTRATOR=1
ORCHESTRATOR_DIR={shlex.quote(str(target))}
ORCHESTRATOR_CERT_DIR={shlex.quote(str(tmp_path / "certs"))}
install_orchestrator
''')
    assert result.returncode == 0, result.stderr
    assert not target.exists()
    output = result.stdout + result.stderr
    assert 'git clone -- https://example.org/orch.git' in output
    assert 'git clone -- https://example.org/eval.git' in output
    assert 'uv pip install --python' in output
    assert '--editable' in output
    assert 'uv pip check' in output
    assert 'cyber-agent-flow-orchestrator --help' in output
    assert 'create-cert --hostname localhost' in output
    assert not (tmp_path / 'certs').exists()
    assert 'systemctl' not in output


def test_unmanaged_host_checkout_preserved(tmp_path):
    marker = tmp_path / 'important'
    marker.write_text('preserve')
    result = probe(f'ORCHESTRATOR=1\nORCHESTRATOR_DIR={shlex.quote(str(tmp_path))}\npreflight_orchestrator')
    assert result.returncode != 0
    assert 'unmanaged directory' in result.stderr
    assert marker.read_text() == 'preserve'


def test_new_settings_are_saved_for_guest_rebuilds():
    result = probe('''ORCHESTRATOR=1
ORCHESTRATOR_REF=host-pin
CYBER_AGENT_FLOW_EVAL_REF=eval-pin
save_orchestrator_state
save_caf_state
''')
    assert result.returncode == 0, result.stderr
    assert 'ORCHESTRATOR=1' in result.stdout
    assert 'ORCHESTRATOR_REF=host-pin' in result.stdout
    assert 'CYBER_AGENT_FLOW_EVAL_REF=eval-pin' in result.stdout


def test_cli_smoke_failure_stops_before_publishing_commands(tmp_path):
    result = probe(f'''ORCHESTRATOR=1
ORCHESTRATOR_DIR={shlex.quote(str(tmp_path / 'host'))}
# Stub every mutation and fail the evaluator CLI, without touching the host.
run() {{
    printf 'CALL %s\\n' "$*"
    case "$1" in */bin/cyber-agent-flow-eval) return 19 ;; esac
    return 0
}}
install_orchestrator
''')
    assert result.returncode == 19, result.stderr
    assert 'cyber-agent-flow-eval --help' in result.stdout
    assert 'CALL ln ' not in result.stdout
    assert not (tmp_path / 'host').exists()


def test_first_install_creates_certificate_once_and_preserves_replacement(tmp_path):
    cert_dir = tmp_path / 'certs'
    calls = tmp_path / 'cert-calls'
    # Stand in for the installed CLI; its cryptographic implementation is tested
    # in the orchestrator project. Here exercise installer arguments/lifecycle.
    body = f'''ORCHESTRATOR_CERT_DIR={shlex.quote(str(cert_dir))}
hostname() {{ if [[ "$1" == -f ]]; then echo pve.lab; else echo pve; fi; }}
cert_cli() {{
    printf '%s\\n' "$*" >> {shlex.quote(str(calls))}
    [[ "$1" == create-cert ]]
    (umask 077; printf certificate > "$ORCHESTRATOR_CERT_DIR/cert.pem"; printf key > "$ORCHESTRATOR_CERT_DIR/key.pem")
}}
install_orchestrator_certificate cert_cli
'''
    result = probe(body)
    assert result.returncode == 0, result.stderr
    cert, key = cert_dir / 'cert.pem', cert_dir / 'key.pem'
    assert cert.exists() and key.stat().st_mode & 0o077 == 0
    assert '--hostname localhost --hostname 127.0.0.1 --hostname ::1 --hostname pve --hostname pve.lab' in calls.read_text()
    assert '--days 365' in calls.read_text()
    # Simulate the operator replacing the self-signed pair with a CA-issued pair.
    cert.write_text('operator certificate chain')
    key.write_text('operator private key')
    result = probe(body)
    assert result.returncode == 0, result.stderr
    assert len(calls.read_text().splitlines()) == 1
    assert cert.read_text() == 'operator certificate chain'
    assert key.read_text() == 'operator private key'


@pytest.mark.parametrize('existing', ['cert.pem', 'key.pem'])
def test_incomplete_certificate_pair_is_preserved_and_rejected(tmp_path, existing):
    original = tmp_path / existing
    original.write_text('preserve me')
    result = probe(f'''ORCHESTRATOR_CERT_DIR={shlex.quote(str(tmp_path))}
run() {{ exit 99; }}
install_orchestrator_certificate unused-cli
''')
    assert result.returncode != 0 and result.returncode != 99
    assert 'incomplete TLS certificate pair' in result.stderr
    assert original.read_text() == 'preserve me'
    assert len(list(tmp_path.iterdir())) == 1


def test_certificate_dry_run_creates_no_files(tmp_path):
    cert_dir = tmp_path / 'certs'
    result = probe(f'''ORCHESTRATOR_CERT_DIR={shlex.quote(str(cert_dir))}
DRY_RUN=1
install_orchestrator_certificate /missing/cli
''')
    assert result.returncode == 0, result.stderr
    assert 'create-cert' in result.stdout
    assert not cert_dir.exists()


def test_certificate_generation_failure_propagates(tmp_path):
    result = probe(f'''ORCHESTRATOR_CERT_DIR={shlex.quote(str(tmp_path))}
cert_cli() {{ return 23; }}
install_orchestrator_certificate cert_cli
''')
    assert result.returncode == 23
    assert not (tmp_path / 'cert.pem').exists()
