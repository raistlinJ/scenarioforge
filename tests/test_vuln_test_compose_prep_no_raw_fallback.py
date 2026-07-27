"""The catalog test flows must never fall back to the raw catalog compose.

The raw vulhub compose has no `ip` tooling baked in and keeps its published
ports, so a container started from it cannot set a default gateway inside CORE.
Silently substituting it looks like success until the node is already running
with no route.
"""

import logging

import pytest

from webapp.routes.vuln_catalog_test_start import _prepare_test_compose


class _Recorder(logging.Logger):
    pass


@pytest.fixture
def logger():
    return logging.getLogger('test-vuln-prep')


def test_returns_prepared_path_on_success(tmp_path, monkeypatch, logger):
    prepared = tmp_path / 'docker-compose-vuln-test-1.yml'
    prepared.write_text('services: {}\n', encoding='utf-8')

    import scenarioforge.utils.vuln_process as vp

    monkeypatch.setattr(vp, 'prepare_compose_for_assignments', lambda *a, **k: [str(prepared)])

    path, err = _prepare_test_compose(
        compose_path='/catalog/kibana/CVE-2019-7609/docker-compose.yml',
        item_id=1,
        item_name='kibana/CVE-2019-7609',
        run_dir=str(tmp_path),
        node_name='vuln-test-1',
        logger=logger,
    )
    assert err is None
    assert path == str(prepared)


def test_errors_instead_of_using_raw_compose_when_prep_raises(tmp_path, monkeypatch, logger):
    import scenarioforge.utils.vuln_process as vp

    def boom(*a, **k):
        raise RuntimeError('wrapper build context missing')

    monkeypatch.setattr(vp, 'prepare_compose_for_assignments', boom)

    raw = '/catalog/kibana/CVE-2019-7609/docker-compose.yml'
    path, err = _prepare_test_compose(
        compose_path=raw,
        item_id=1,
        item_name='kibana/CVE-2019-7609',
        run_dir=str(tmp_path),
        node_name='vuln-test-1',
        logger=logger,
    )
    assert err is not None
    assert 'wrapper build context missing' in err
    # Caller must treat this as fatal rather than starting the raw compose.
    assert path == raw


def test_errors_when_prep_returns_nothing(tmp_path, monkeypatch, logger):
    """The empty-list path needs no exception to reach the raw compose."""
    import scenarioforge.utils.vuln_process as vp

    monkeypatch.setattr(vp, 'prepare_compose_for_assignments', lambda *a, **k: [])

    path, err = _prepare_test_compose(
        compose_path='/catalog/kibana/CVE-2019-7609/docker-compose.yml',
        item_id=1,
        item_name='kibana/CVE-2019-7609',
        run_dir=str(tmp_path),
        node_name='vuln-test-1',
        logger=logger,
    )
    assert err is not None
    assert 'produced no file' in err


def test_real_prep_wraps_kibana_and_drops_published_ports(tmp_path, logger):
    """End-to-end on the actual failing catalog entry shape."""
    raw = tmp_path / 'raw' / 'docker-compose.yml'
    raw.parent.mkdir(parents=True)
    raw.write_text(
        "\n".join(
            [
                "version: '2'",
                'services:',
                ' kibana:',
                '   image: vulhub/kibana:6.5.4',
                '   depends_on:',
                '    - elasticsearch',
                '   ports:',
                '    - "5601:5601"',
                ' elasticsearch:',
                '   image: vulhub/elasticsearch:6.8.6',
                '',
            ]
        ),
        encoding='utf-8',
    )
    out_base = tmp_path / 'out'
    out_base.mkdir()

    path, err = _prepare_test_compose(
        compose_path=str(raw),
        item_id=7,
        item_name='kibana/CVE-2019-7609',
        run_dir=str(out_base),
        node_name='vuln-test-7',
        logger=logger,
    )
    assert err is None

    import yaml

    obj = yaml.safe_load(open(path, encoding='utf-8'))
    node_svc = obj['services']['vuln-test-7']
    image = str(node_svc.get('image') or '')
    assert image.startswith('coretg/') and image.endswith(':iproute2'), image
    assert node_svc['labels']['coretg.wrapper_base_image'] == 'vulhub/kibana:6.5.4'
    # Published ports are what made the raw file identifiable in the field.
    assert 'ports' not in node_svc
