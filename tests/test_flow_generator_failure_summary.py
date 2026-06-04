from webapp.flow_prepare_preview_helpers import summarize_remote_generator_failure


def test_remote_generator_failure_summary_prefers_runner_output_over_traceback() -> None:
    stdout = "[compose] generator source digest abc for /tmp/gen\n[cmd] stderr: pull access denied\n"
    stderr = "Traceback (most recent call last):\n  File \"runner.py\", line 1, in <module>\nsubprocess.CalledProcessError: Command '['docker', 'compose', 'run']' returned non-zero exit status 1.\n"

    note = summarize_remote_generator_failure(rc=1, stdout=stdout, stderr=stderr)

    assert "pull access denied" in note
    assert "runner traceback summary" in note
    assert "Traceback (most recent call last)" not in note
