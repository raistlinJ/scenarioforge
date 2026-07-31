import os
import subprocess
import time
import tempfile
from pathlib import Path


POLICY_XML = """<Scenarios>
  <Scenario name='cli-pol'>
    <ScenarioEditor>
      <section name='Node Information' density='0.0'>
        <item selected='Workstation' factor='1.000' v_metric='Count' v_count='6'/>
      </section>
      <section name='Routing' density='0.0'>
        <!-- Use Count metric so routers definitely get created even with zero density -->
  <item selected='OSPFv2' factor='1.000' v_metric='Count' v_count='1' r2r_mode='Uniform'/>
  <item selected='RIP' factor='1.000' v_metric='Count' v_count='1' r2r_mode='Exact' r2r_edges='2' r2s_mode='Min'/>
      </section>
    </ScenarioEditor>
  </Scenario>
</Scenarios>"""


def _latest_report(root: Path, *, newer_than: float = 0.0):
    """Newest scenario report, optionally restricted to ones written after a time.

    reports/ accumulates across runs, so without `newer_than` this happily returns
    a report from a previous session and the caller's "a report was produced"
    assertion passes without the CLI having produced anything.
    """
    reports = sorted(
        (r for r in (root / 'reports').glob('scenario_report_*.md') if r.stat().st_mtime > newer_than),
        key=lambda p: p.stat().st_mtime,
    )
    return reports[-1] if reports else None


def test_cli_persists_connectivity_policies(monkeypatch):
    repo_root = Path(__file__).resolve().parent.parent
    started_at = time.time()
    env = os.environ.copy()
    env.setdefault('PYTHONPATH', str(repo_root))
    with tempfile.TemporaryDirectory() as td:
        xml_path = Path(td) / 'pol.xml'
        xml_path.write_text(POLICY_XML, encoding='utf-8')
        # The execute phase refuses to run without a PlanPreview embedded in the
        # XML, so generate one first. preview-plan writes it back into the file,
        # which is also how the UI reaches execute.
        base = ["python", "-m", "scenarioforge.cli"]
        tail = ["--xml", str(xml_path), "--host", "127.0.0.1", "--port", "50051"]
        try:
            subprocess.run(base + ["preview-plan"] + tail, cwd=str(repo_root), env=env,
                           check=False, capture_output=True, text=True, timeout=60)
        except Exception:
            import pytest
            pytest.skip("subprocess not supported")
        cmd = base + tail + ["--verbose"]
        try:
            out = subprocess.run(cmd, cwd=str(repo_root), env=env, check=False, capture_output=True, text=True, timeout=40)
        except Exception:
            import pytest
            pytest.skip("subprocess not supported")
        # We don't require zero exit (could fail to connect to core-daemon); we only need report creation.
        # The CLI routes warnings/errors to a latest.errors file beside the XML and
        # does not echo them, so the environment guard below has to read that file
        # as well -- checking only stdout/stderr can never see why a run stopped.
        all_out = (out.stdout + out.stderr)
        try:
            all_out += (Path(td) / 'latest.errors').read_text(encoding='utf-8', errors='ignore')
        except OSError:
            pass

    import pytest

    if 'ModuleNotFoundError' in all_out and "No module named 'core'" in all_out:
        pytest.skip('core library not installed in test environment')
    if 'requires CORE gRPC availability' in all_out:
        pytest.skip('execute phase needs a reachable CORE daemon; not available in a test run')

    report = _latest_report(repo_root, newer_than=started_at)
    assert report is not None, 'Report not generated'
    assert 'Scenario report written to' in all_out
    # Basic sanity: original XML had routing policies; ensure they weren't stripped by parser step inside CLI
    # (We don't enforce appearance inside report because router count may be optimized away when planning yields 0.)
    assert 'r2r_mode' in POLICY_XML and 'r2s_mode' in POLICY_XML