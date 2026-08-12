"""A compose file must still be YAML after CORE's host-side printf escaping.

Every compose this project writes is read twice more after PyYAML: the printf
format string CORE renders it through, which doubles each backslash, and then
`docker compose` itself. PyYAML's default emitter writes a multiline string as
a double-quoted scalar, spelling inner quotes `\\"`. Doubling those backslashes
leaves the `"` free to close the scalar early, and the rest of the command is
reparsed as YAML.

Observed on `rocketchat/CVE-2021-22911` (dataset-catalog-coverage-057): one
pass re-dumped the prepared compose with a plain `yaml.safe_dump`, the printf
pass ran over it, and the command's inner `_id: 'rs0'` became a stray mapping
key. `docker compose up` refused the file with "mapping values are not allowed
in this context", docker-6 never started, and the run failed as a CORE startup
timeout two layers away.
"""

from __future__ import annotations

import re

import yaml

from scenarioforge.utils.compose_shell import dump_compose_yaml

# The shape that broke it: a multiline command carrying escaped inner quotes.
ROCKETCHAT_COMMAND = (
    'bash -c\n'
    '  "for i in `seq 1 30`; do\n'
    '    mongo mongo/rocketchat --eval \\"\n'
    "      rs.initiate({\n"
    "        _id: 'rs0',\n"
    "        members: [ { _id: 0, host: 'localhost:27017' } ]})\\\" &&\n"
    '    s=$$? && break || s=$$?;\n'
    '  done; (exit $$s)"\n'
)


def _printf_escape(text: str) -> str:
    """The escaping applied in builders/topology.py before CORE renders it."""
    text = text.replace('\\', '\\\\\\\\')
    return re.sub(r'(?<!%)%(?!%)', '%%', text)


def _compose(command: str) -> dict:
    return {'services': {'mongo-init-replica': {'image': 'mongo:4.0', 'command': command}}}


def test_multiline_command_survives_printf_escaping() -> None:
    escaped = _printf_escape(dump_compose_yaml(_compose(ROCKETCHAT_COMMAND)))
    yaml.safe_load(escaped)  # must not raise


def test_a_plain_safe_dump_is_what_breaks_it() -> None:
    """Anchors why the helper exists, so the reason cannot be lost to a cleanup."""
    escaped = _printf_escape(yaml.safe_dump(_compose(ROCKETCHAT_COMMAND), sort_keys=False))
    try:
        yaml.safe_load(escaped)
    except yaml.YAMLError:
        return
    raise AssertionError(
        'plain safe_dump now survives printf escaping; if PyYAML changed, '
        'recheck whether dump_compose_yaml is still required'
    )


def test_multiline_values_use_a_literal_block() -> None:
    text = dump_compose_yaml(_compose(ROCKETCHAT_COMMAND))
    assert 'command: |' in text, text
    assert '\\n' not in text, 'newlines must be real, not escape sequences'


def test_single_line_values_are_left_alone() -> None:
    text = dump_compose_yaml({'services': {'a': {'command': 'mongod --replSet rs0'}}})
    assert 'command: mongod --replSet rs0' in text, text


def test_the_command_text_round_trips() -> None:
    """A block scalar must not quietly alter what the container runs."""
    loaded = yaml.safe_load(dump_compose_yaml(_compose(ROCKETCHAT_COMMAND)))
    assert loaded['services']['mongo-init-replica']['command'] == ROCKETCHAT_COMMAND


def test_a_value_no_block_scalar_can_hold_still_dumps_validly() -> None:
    # Trailing whitespace on a line cannot be represented literally; PyYAML has
    # to fall back to a quoted style, and asking for `|` must not break that.
    awkward = 'first line   \n\tsecond\r\nthird'
    text = dump_compose_yaml({'services': {'a': {'command': awkward}}})
    assert yaml.safe_load(text)['services']['a']['command'] == awkward


def test_no_compose_writer_reaches_for_plain_safe_dump() -> None:
    """The failure returns the moment one writer puts the escapes back.

    topology.py writes the compose from several independent repair passes
    (working_dir sanitation, JVM heap capping, the app-user shim, platform
    fallback). Each one re-dumps the whole document, so any single one using
    `yaml.safe_dump` undoes the block-scalar form for every service.
    """
    from pathlib import Path

    source = Path(__file__).resolve().parents[1] / 'scenarioforge' / 'builders' / 'topology.py'
    text = source.read_text(encoding='utf-8')
    assert 'yaml.safe_dump' not in text, (
        'builders/topology.py writes compose documents; use '
        'compose_shell.dump_compose_yaml so multiline commands stay literal blocks'
    )
