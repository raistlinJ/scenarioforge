"""Shared guard for tests that read the machine's installed catalogs.

Most tests get an isolated temp catalog root from the autouse fixture in
``conftest.py``, so a test can never damage the operator's real catalogs by
forgetting to isolate itself. A few exercise preview and Flow against real
vulnerabilities and need a catalog that actually has items in it.

Those opt out with ``pytestmark = REQUIRES_REAL_CATALOG``. Opting out puts the
operator's data back in reach, so it is only for tests that **read**.
"""

from __future__ import annotations

import pytest

from webapp import app_backend as _app_backend


def has_installed_vulnerabilities() -> bool:
    """Whether this machine has a vulnerability catalog with items in it."""
    try:
        state = _app_backend._load_vuln_catalogs_state() or {}
    except Exception:
        return False
    for catalog in state.get('catalogs') or []:
        if isinstance(catalog, dict) and int(catalog.get('compose_count') or 0) > 0:
            return True
    return False


# Read the machine's catalogs instead of the isolated temp root, and skip when
# there is nothing installed to sequence over -- a fresh clone, or CI.
REQUIRES_REAL_CATALOG = [
    pytest.mark.real_installed_catalogs,
    pytest.mark.skipif(
        not has_installed_vulnerabilities(),
        reason='no vulnerability catalog installed on this machine',
    ),
]
