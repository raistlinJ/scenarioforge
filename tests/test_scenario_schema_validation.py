import os
import glob
from lxml import etree

SCHEMA_PATH = os.path.join(os.path.dirname(__file__), '..', 'schemas', 'xml', 'scenarios.xsd')
SCHEMA_PATH = os.path.abspath(SCHEMA_PATH)

def _load_schema():
    with open(SCHEMA_PATH, 'rb') as f:
        doc = etree.parse(f)
    return etree.XMLSchema(doc)

def _validate_file(schema, path):
    with open(path, 'rb') as f:
        doc = etree.parse(f)
    schema.assertValid(doc)

def test_sample_xml_validates():
    schema = _load_schema()
    sample_candidates = [
        'examples/sample.xml',
        'sample_config_1scen.xml',
        'sample_config_2scen.xml'
    ]
    found_any = False
    for rel in sample_candidates:
        path = os.path.abspath(rel)
        if os.path.exists(path):
            # Skip files that are clearly CORE session exports (contain <scenario> root lower-case)
            txt_head = open(path, 'r', errors='ignore').read(1000)
            if '<scenario' in txt_head and '<Scenarios' not in txt_head:
                continue
            _validate_file(schema, path)
            found_any = True
    if not found_any:
        return

def test_generated_schema_samples_if_present():
    """If bulk-generated schema samples exist under outputs/schema-samples, validate them.

    This test is optional; it will pass quickly if the directory does not exist.
    """
    schema = _load_schema()
    samples_dir = os.path.abspath('outputs/schema-samples')
    if not os.path.isdir(samples_dir):
        return  # nothing to do
    xml_files = glob.glob(os.path.join(samples_dir, '*.xml'))
    for xf in xml_files:
        _validate_file(schema, xf)


def _validates(schema, section_attrs='', item_attrs=''):
    from lxml import etree as _etree

    xml = (
        '<Scenarios><Scenario name="S1"><ScenarioEditor><BaseScenario/>'
        f'<section name="Segmentation" density="0.5"{section_attrs}>'
        f'<item selected="Firewall" factor="1.0"{item_attrs}/>'
        '</section></ScenarioEditor></Scenario></Scenarios>'
    )
    return schema.validate(_etree.fromstring(xml.encode()))


def test_schema_accepts_every_segmentation_setting_spelling():
    """The schema must accept what the parser reads and the writer emits.

    `_write_segmentation_settings_attrs` puts these on the <section>, so a
    schema that omits them rejects scenarios ScenarioForge itself produced.
    Driven off `_SETTING_ATTRS` so a new spelling cannot be added to the parser
    without the schema following.
    """
    from scenarioforge.parsers.segmentation import (
        SEGMENTATION_SETTING_DEFAULTS, _SETTING_ATTRS,
    )

    schema = _load_schema()
    sample = {'nat_mode': 'SNAT', 'include_hosts': 'true', 'dnat_probability': '0.25',
              'allow_src_subnet_prob': '0.3', 'allow_dst_subnet_prob': '0.3',
              'accessible_by_pivot': 'true', 'pivot_provider': 'flag-node-generator'}
    for key in SEGMENTATION_SETTING_DEFAULTS:
        assert key in sample, f'no sample value for setting {key}'
        for attr in _SETTING_ATTRS.get(key, (key,)):
            assert _validates(schema, f' {attr}="{sample[key]}"'), \
                f'schema rejects section attribute {attr}'


def test_schema_accepts_the_row_level_pivot_switch():
    # The editor writes the switch and the provider on the <item>; the aliases
    # are what the parser also reads.
    schema = _load_schema()
    for attr in ('pivot_enabled', 'pivot_required'):
        assert _validates(schema, item_attrs=f' {attr}="true"'), attr
    for attr in ('pivot_provider', 'access_provider'):
        assert _validates(schema, item_attrs=f' {attr}="flag-node-generator"'), attr


def test_schema_still_rejects_nonsense_values():
    # The point of typing these rather than leaving them xs:string.
    schema = _load_schema()
    assert not _validates(schema, ' nat_mode="NOPE"')
    assert not _validates(schema, ' dnat_probability="1.5"')
    assert not _validates(schema, ' allow_src_subnet_prob="-0.1"')
    assert not _validates(schema, ' accessible_by_pivot="maybe"')


def test_schema_accepts_a_scenario_the_editor_would_write():
    """End to end: the shape observed in a real saved scenario."""
    schema = _load_schema()
    assert _validates(
        schema,
        section_attrs=' explicit_count="2" weight_rows="0" count_rows="1" weight_sum="0.000"',
        item_attrs=' v_metric="Count" v_count="2" pivot_enabled="true"'
                   ' pivot_provider="flag-node-generator"',
    )
