from pathlib import Path

from webapp.flow_prepare_preview_helpers import summarize_remote_generator_failure


def test_remote_generator_failure_summary_prefers_runner_output_over_traceback() -> None:
    stdout = "[compose] generator source digest abc for /tmp/gen\n[cmd] stderr: pull access denied\n"
    stderr = "Traceback (most recent call last):\n  File \"runner.py\", line 1, in <module>\nsubprocess.CalledProcessError: Command '['docker', 'compose', 'run']' returned non-zero exit status 1.\n"

    note = summarize_remote_generator_failure(rc=1, stdout=stdout, stderr=stderr)

    assert "pull access denied" in note
    assert "runner traceback summary" in note
    assert "Traceback (most recent call last)" not in note


def test_remote_generator_failure_summary_classifies_docker_dns_timeout() -> None:
    stdout = """
[cmd] stderr: failed to solve: python:3.11-slim: failed to resolve source metadata for docker.io/library/python:3.11-slim
failed to do request: Head "https://registry-1.docker.io/v2/library/python/manifests/3.11-slim": dial tcp: lookup registry-1.docker.io on 8.8.8.8:53: read udp 11.0.0.21:48223->8.8.8.8:53: i/o timeout
"""
    stderr = "Traceback (most recent call last):\nsubprocess.CalledProcessError: docker compose run failed\n"

    note = summarize_remote_generator_failure(rc=2, stdout=stdout, stderr=stderr)

    assert "Docker image pull/DNS failed on the CORE VM" in note
    assert "registry-1.docker.io" in note
    assert "pre-pull/cache the image" in note
    assert "Traceback (most recent call last)" not in note


def test_remote_generator_runner_enables_direct_python_first_for_core_vm() -> None:
    helper_text = Path("webapp/flow_prepare_preview_helpers.py").read_text(encoding="utf-8", errors="ignore")

    assert "env.setdefault('CORETG_RUN_FLAG_GENERATOR_PY_FALLBACK','1')" in helper_text
    assert "env.setdefault('CORETG_RUN_FLAG_GENERATOR_PY_FIRST','1')" in helper_text
