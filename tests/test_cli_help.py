from scenarioforge import cli


def test_new_phase_help_hides_flow_and_execute_only_flags() -> None:
    help_text = cli._build_cli_help_parser('new').format_help()
    core_defaults = cli._cli_core_argument_defaults()
    new_defaults = cli._cli_new_argument_defaults()

    assert '--density-count' in help_text
    assert '--seed-role' in help_text
    assert '--seed-service' in help_text
    assert '--seed-segmentation' in help_text
    assert '--seed-vulnerability' in help_text
    assert '--host' in help_text
    assert '--flow-mode' not in help_text
    assert '--preview-full' not in help_text
    assert '--prefix' not in help_text
    assert f"(default: {core_defaults['host']})" in help_text
    assert f"(default: {new_defaults['density_count']})" in help_text


def test_flag_sequencing_help_shows_flow_defaults() -> None:
    help_text = cli._build_cli_help_parser('flag-sequencing').format_help()

    assert '--flow-mode' in help_text
    assert '--flow-length' in help_text
    assert '--seed-role' not in help_text
    assert '(default: 5)' in help_text
    assert '(default: 3)' in help_text


def test_general_help_points_to_phase_specific_help() -> None:
    help_text = cli._build_cli_help_parser(None).format_help()

    assert 'flag-sequencing' in help_text
    assert 'Use "cli.py <phase> --help" to view phase-specific options.' in help_text
    assert 'cleanup-scenarioforge-docker --dry-run' in help_text
    assert 'cleanup-scenarioforge-docker --force' in help_text
    assert 'removes all Docker' in help_text
    assert 'containers/images/build cache' in help_text
    assert 'unused volumes/networks' in help_text
    assert '--flow-mode' not in help_text
