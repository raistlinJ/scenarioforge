"""Execute empties the shared runtime scratch directories before generating.

`/tmp/traffic` and `/tmp/segmentation` live on the CORE host, are bind-mounted
read-only into nodes, and are reused by every run. Each generator clears its own
directory, but only when that feature runs, so a scenario with no traffic would
otherwise inherit the previous scenario's scripts and report them as its own
runtime state. Nothing in these directories outlives the run that wrote it, so
the reset removes their contents wholesale.
"""

import os

from scenarioforge.cli import RUNTIME_ARTIFACT_DIRS, _reset_runtime_artifact_dirs


def _dirs(tmp_path):
    traffic = tmp_path / 'traffic'
    seg = tmp_path / 'segmentation'
    traffic.mkdir()
    seg.mkdir()
    return traffic, seg, (str(traffic), str(seg))


def test_configured_dirs_cover_traffic_and_segmentation():
    assert set(RUNTIME_ARTIFACT_DIRS) == {'/tmp/traffic', '/tmp/segmentation'}


def test_directory_contents_are_removed_wholesale(tmp_path):
    traffic, seg, spec = _dirs(tmp_path)
    (traffic / 'traffic_9_s1.py').write_text('x')
    (traffic / 'traffic_summary.json').write_text('x')
    (traffic / 'notes.txt').write_text('x')
    (seg / 'seg_allow_1_1.py').write_text('x')
    (seg / 'allow_verification.json').write_text('x')

    removed = _reset_runtime_artifact_dirs(spec)

    assert removed[str(traffic)] == 3
    assert removed[str(seg)] == 2
    assert list(traffic.iterdir()) == []
    assert list(seg.iterdir()) == []


def test_subdirectories_and_symlinks_are_removed(tmp_path):
    _traffic, seg, spec = _dirs(tmp_path)
    keep = seg / 'target.txt'
    keep.write_text('x')
    nested = seg / 'subdir'
    nested.mkdir()
    (nested / 'inner.py').write_text('x')
    os.symlink(str(keep), str(seg / 'link'))

    _reset_runtime_artifact_dirs(spec)

    assert list(seg.iterdir()) == []


def test_directories_themselves_survive(tmp_path):
    # Compose bind-mounts reference these paths, so the directory must remain.
    traffic, seg, spec = _dirs(tmp_path)
    (traffic / 'traffic_1_s1.py').write_text('x')

    _reset_runtime_artifact_dirs(spec)

    assert traffic.is_dir()
    assert seg.is_dir()


def test_missing_directory_is_created(tmp_path):
    missing = tmp_path / 'never-existed'

    assert _reset_runtime_artifact_dirs((str(missing),)) == {}
    assert missing.is_dir()


def test_reset_is_idempotent(tmp_path):
    traffic, _seg, spec = _dirs(tmp_path)
    (traffic / 'traffic_1_s1.py').write_text('x')

    assert _reset_runtime_artifact_dirs(spec)[str(traffic)] == 1
    assert _reset_runtime_artifact_dirs(spec) == {}


def test_reset_is_placed_after_the_topo_phase_returns():
    # A topology-only run must not clear artifacts it never generated, so the
    # reset has to sit downstream of the topo early return.
    from scenarioforge import cli

    text = open(cli.__file__, encoding='utf-8').read()
    assert text.index("if args.phase == 'topo':") < text.index('_reset_runtime_artifact_dirs()')
