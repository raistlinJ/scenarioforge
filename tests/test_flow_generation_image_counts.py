"""The Generation Results modal reports generator-image reuse.

The resolve response carries a structured pulled/cached/pending tally so the UI
can explain why one Generate takes minutes and the next seconds.
"""

from webapp.flow_prepare_preview_execute import _image_counts_summary
from webapp.flow_prepare_preview_helpers import build_prepare_preview_success_payload


def test_summary_splits_pulled_cached_and_pending():
    assert _image_counts_summary({'pulling': 2, 'cached': 5}, 8) == {
        'pulled': 2, 'cached': 5, 'pending': 1, 'total': 8,
    }


def test_summary_pending_is_zero_when_all_runs_reported():
    assert _image_counts_summary({'pulling': 0, 'cached': 3}, 3)['pending'] == 0


def test_summary_pending_never_negative():
    # A run can report more outcomes than the chain length if a generator retries.
    assert _image_counts_summary({'pulling': 4, 'cached': 4}, 3)['pending'] == 0


def test_summary_tolerates_missing_or_junk_values():
    assert _image_counts_summary(None, None) == {'pulled': 0, 'cached': 0, 'pending': 0, 'total': 0}
    assert _image_counts_summary({'pulling': 'x', 'cached': -2}, 'y') == {
        'pulled': 0, 'cached': 0, 'pending': 0, 'total': 0,
    }


class _StubBackend:
    """Only path normalization is needed to build the response payload."""

    @staticmethod
    def _abs_path_or_original(value, **kwargs):
        return value


def _payload(**overrides):
    kwargs = dict(
        scenario_label='S1', scenario_norm='s1', length=0, requested_length=0, stats={},
        chain_nodes=[], flag_assignments_out=[], flags_enabled=False, flow_valid=True,
        flow_errors=[], flow_errors_detail=None, host_ip_map={}, meta=None,
        base_plan_path='', out_path='', best_effort=False, elapsed_s=0.0,
        generator_runs=[], progress_log=[], generation_failures=[], generation_skipped=[],
        created_run_dirs=[], failed_run_dirs=[], cleanup_generated_artifacts=False,
        cleanup_deleted_run_dirs=[], phase_timings={}, debug_dag=False, dag_debug=None,
        warning=None, backend=_StubBackend(),
    )
    kwargs.update(overrides)
    return build_prepare_preview_success_payload(**kwargs)


def test_response_payload_carries_image_counts():
    counts = {'pulled': 1, 'cached': 2, 'pending': 0, 'total': 3}
    assert _payload(image_counts=counts)['image_counts'] == counts


def test_response_payload_defaults_to_empty_counts():
    # Callers that never ran generators still get a well-formed key.
    assert _payload()['image_counts'] == {}
