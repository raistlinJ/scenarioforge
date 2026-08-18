"""Short-lived progress records that a blocking request can publish as it works.

Several operations run as one long POST -- installing a catalog, reconciling the
CORE VM -- and the browser has nothing to show until they return. Each writes
progress here under a client-supplied id and the client polls for it, which
avoids streaming (abandoned `stream_with_context` generators leak Flask request
contexts and break unrelated requests).

Records expire so a client that goes away cannot pin memory.
"""

from __future__ import annotations

import copy
import re
import threading
import time
from typing import Any

PROGRESS_ID_RE = re.compile(r"^[A-Za-z0-9_-]{8,80}$")
TTL_SECONDS = 15 * 60

_LOCK = threading.Lock()
_PROGRESS: dict[str, dict[str, Any]] = {}


def _expire() -> None:
    cutoff = time.time() - TTL_SECONDS
    with _LOCK:
        for progress_id in list(_PROGRESS):
            if float(_PROGRESS[progress_id].get('updated_at') or 0) < cutoff:
                _PROGRESS.pop(progress_id, None)


def update(
    progress_id: str,
    *,
    step: str,
    detail: str = '',
    current: int = 0,
    total: int = 0,
    status: str = 'running',
) -> None:
    """Publish the latest state for one operation. A bad or empty id is a no-op."""
    if not progress_id or not PROGRESS_ID_RE.fullmatch(str(progress_id)):
        return
    percent = 0
    if total > 0:
        percent = max(0, min(100, int(round((current / total) * 100))))
    with _LOCK:
        _PROGRESS[str(progress_id)] = {
            'id': str(progress_id),
            'step': str(step or ''),
            'detail': str(detail or ''),
            'current': int(current),
            'total': int(total),
            'percent': percent,
            'status': status,
            'updated_at': time.time(),
        }


def snapshot(progress_id: str) -> dict[str, Any] | None:
    _expire()
    with _LOCK:
        state = _PROGRESS.get(str(progress_id))
        return copy.deepcopy(state) if isinstance(state, dict) else None
