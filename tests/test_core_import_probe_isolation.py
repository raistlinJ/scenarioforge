import os
import pathlib
import subprocess
import sys
import textwrap


def test_cli_import_ignores_noisy_non_core_package_on_pythonpath(tmp_path) -> None:
    fake_core = tmp_path / "core"
    fake_core.mkdir()
    (fake_core / "__init__.py").write_text(
        textwrap.dedent(
            """
            import sys

            print("meshroom plugin traceback: No module named 'pyalicevision'", file=sys.stderr)
            raise ModuleNotFoundError("No module named 'pyalicevision'")
            """
        ),
        encoding="utf-8",
    )

    repo_root = pathlib.Path(__file__).resolve().parents[1]
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(tmp_path), str(repo_root)])

    proc = subprocess.run(
        [
            sys.executable,
            "-c",
            "import scenarioforge.cli as cli; print('available=' + str(cli.CORE_GRPC_AVAILABLE))",
        ],
        cwd=str(repo_root),
        env=env,
        capture_output=True,
        text=True,
        check=False,
        timeout=30,
    )

    combined = (proc.stdout or "") + (proc.stderr or "")
    assert proc.returncode == 0, combined
    assert "available=False" in proc.stdout
    assert "pyalicevision" not in combined
    assert "meshroom plugin traceback" not in combined
