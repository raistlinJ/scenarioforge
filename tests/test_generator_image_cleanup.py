"""Flow cleanup must not delete generator images it would immediately rebuild.

A generator image is tagged `coretg-gen-<source-dir>-<service>-<digest>:latest`
where the digest covers every file that affects the build, so the tag is
self-validating: any edit to the source produces a different tag. Cleanup used
to delete every `coretg-gen-*` image under the label "old generator images" --
no age filter, no keep set -- so the cache was empty on every run, `Using: 0
cached` was permanent, and each Generate rebuilt everything. That also breaks
air-gapped hosts, because a rebuild needs the base image the cache existed to
avoid fetching.

The digest is shared with `scripts/run_flag_generator.py` rather than
reimplemented: two implementations would mean cleanup deleting exactly the
images the runner would have reused.
"""

from __future__ import annotations

import ast
import json
import pathlib

import pytest

from scenarioforge.utils.generator_images import (
    IMAGE_PREFIX,
    current_image_markers,
    image_tag,
    is_current,
    slugify,
    source_cache_digest,
    stale_images,
)

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]


@pytest.fixture()
def generator_root(tmp_path: pathlib.Path) -> pathlib.Path:
    root = tmp_path / 'flag_generators'
    pack = root / 'p_test-pack__42'
    pack.mkdir(parents=True)
    (pack / 'generator.py').write_text("print('flag')\n", encoding='utf-8')
    (pack / 'docker-compose.yml').write_text("services:\n  generator:\n    image: x\n", encoding='utf-8')
    return root


def test_an_installed_generator_image_is_never_stale(generator_root: pathlib.Path) -> None:
    pack = generator_root / 'p_test-pack__42'
    tag = image_tag(str(pack), 'generator')
    assert stale_images([tag], [str(generator_root)]) == []


def test_an_image_whose_source_changed_becomes_stale(generator_root: pathlib.Path) -> None:
    pack = generator_root / 'p_test-pack__42'
    old_tag = image_tag(str(pack), 'generator')
    (pack / 'generator.py').write_text("print('different flag')\n", encoding='utf-8')
    new_tag = image_tag(str(pack), 'generator')
    assert old_tag != new_tag, 'a source edit must change the digest'
    assert stale_images([old_tag, new_tag], [str(generator_root)]) == [old_tag]


def test_an_uninstalled_generators_image_is_stale(generator_root: pathlib.Path) -> None:
    orphan = f'{IMAGE_PREFIX}p-gone-9-generator-deadbeef1234:latest'
    assert stale_images([orphan], [str(generator_root)]) == [orphan]


def test_non_generator_images_are_never_reported(generator_root: pathlib.Path) -> None:
    # Cleanup decides only about images it understands; a vulnerability image or
    # a framework prerequisite must not be swept up by this rule.
    others = ['ubuntu:22.04', 'python:3.12-slim', 'coretg/scenarios-x-docker-1:iproute2']
    assert stale_images(others, [str(generator_root)]) == []


def test_per_run_compose_files_do_not_change_the_digest(generator_root: pathlib.Path) -> None:
    """Otherwise every run would invalidate its own cache.

    `docker-compose.hostnet.<pid>_<ms>.yml` is written on each run inside the
    source directory, so counting it would change the digest every time.
    """
    pack = generator_root / 'p_test-pack__42'
    before = source_cache_digest(str(pack))
    (pack / 'docker-compose.hostnet.123_456.yml').write_text('services: {}\n', encoding='utf-8')
    (pack / '__pycache__').mkdir()
    (pack / '__pycache__' / 'generator.cpython-312.pyc').write_bytes(b'\x00\x01')
    assert source_cache_digest(str(pack)) == before


def test_digest_matches_the_runner_exactly(generator_root: pathlib.Path) -> None:
    """The runner must be using this module, not its own copy.

    A second implementation is the failure this sharing prevents: cleanup would
    compute a different tag and delete an image the runner would have reused.
    """
    import importlib.util

    spec = importlib.util.spec_from_file_location(
        'rfg_under_test', REPO_ROOT / 'scripts' / 'run_flag_generator.py'
    )
    runner = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(runner)
    pack = generator_root / 'p_test-pack__42'
    assert runner._source_cache_digest(pack) == source_cache_digest(str(pack))
    assert runner.slugify('Foo Bar__baz') == slugify('Foo Bar__baz')

    runner_source = (REPO_ROOT / 'scripts' / 'run_flag_generator.py').read_text(encoding='utf-8')
    assert 'def _source_cache_digest' not in runner_source, 'the runner must not keep its own copy'
    assert 'def slugify' not in runner_source


def _rendered_remote_cleanup_script() -> str:
    source = (REPO_ROOT / 'scenarioforge' / 'cli.py').read_text(encoding='utf-8')
    tree = ast.parse(source)
    fn = next(n for n in tree.body if isinstance(n, ast.FunctionDef)
              and n.name == '_best_effort_cli_flag_sequencing_cleanup')
    assign = next(n for n in ast.walk(fn) if isinstance(n, ast.Assign)
                  and getattr(n.targets[0], 'id', '') == 'script')
    return ''.join(p.value if isinstance(p, ast.Constant) else json.dumps('STUB')
                   for p in assign.value.values)


def test_remote_cleanup_no_longer_deletes_every_generator_image() -> None:
    script = _rendered_remote_cleanup_script()
    compile(script, '<flow-cleanup-remote>', 'exec')
    assert "grep -E '^coretg-gen-[^:]+:' | xargs -r docker rmi -f" not in script, \
        'the blanket delete is the bug'
    assert 'GEN_IMAGES_SRC' in script and 'stale_images' in script
    # Listing must not go through the helper that clips output for logging, or a
    # long image list is truncated and the missing images look stale.
    assert "_capture(['docker','images'" in script


def test_local_cleanup_uses_the_same_rule() -> None:
    source = (REPO_ROOT / 'scenarioforge' / 'cli.py').read_text(encoding='utf-8')
    assert 'from .utils.generator_images import stale_images' in source
    assert source.count("grep -E '^coretg-gen-[^:]+:' | xargs -r docker rmi -f") == 0


def test_embedded_module_source_is_executable() -> None:
    from scenarioforge.cli import _generator_images_source

    namespace: dict = {}
    exec(compile(_generator_images_source(), 'generator_images.py', 'exec'), namespace)
    assert callable(namespace['stale_images'])
    assert namespace['IMAGE_PREFIX'] == IMAGE_PREFIX


def test_is_current_requires_both_prefix_and_digest(generator_root: pathlib.Path) -> None:
    markers = current_image_markers([str(generator_root)])
    prefix, digest = next(iter(markers))
    assert is_current(f'{prefix}generator-{digest}:latest', markers)
    # Right generator, wrong digest.
    assert not is_current(f'{prefix}generator-000000000000:latest', markers)
    # Right digest, different generator.
    assert not is_current(f'{IMAGE_PREFIX}other-pack-1-generator-{digest}:latest', markers)
