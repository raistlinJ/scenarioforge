from __future__ import annotations

import contextlib
import importlib
import io
from typing import Any


def quiet_import(module_name: str) -> tuple[bool, Any | None, Exception | None]:
    """Import a CORE module without leaking noisy third-party import output.

    Some workstations carry unrelated Python projects on PYTHONPATH with a
    top-level ``core`` package. Importing those packages can print tracebacks
    while they probe their own plugins. ScenarioForge treats CORE imports as an
    optional capability probe at startup, so keep those failures quiet and let
    real CORE operations report concrete errors later.
    """
    stdout = io.StringIO()
    stderr = io.StringIO()
    try:
        with contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            return True, importlib.import_module(module_name), None
    except Exception as exc:
        return False, None, exc
