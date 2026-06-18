from __future__ import annotations

import os
import sys

if __package__ in (None, ''):
    _repo_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    if _repo_root not in sys.path:
        sys.path.insert(0, _repo_root)

from webapp import app_backend as backend

app = backend.app


def main() -> None:
    try:
        port = int(os.environ.get('CORETG_PORT') or os.environ.get('PORT') or '9090')
    except Exception:
        port = 9090
    host = os.environ.get('CORETG_HOST') or '0.0.0.0'
    debug = backend._env_flag('CORETG_DEBUG', False) or backend._env_flag('FLASK_DEBUG', False)
    use_reloader = backend._env_flag('CORETG_USE_RELOADER', False)

    try:
        did_scrub = backend._scrub_hitl_validation_usernames_in_scenario_catalog()
        if did_scrub:
            app.logger.info('[hitl_validation] scrubbed usernames from scenario_catalog.json')
    except Exception:
        pass
    try:
        did_backfill = backend._backfill_hitl_config_from_editor_snapshots()
        if did_backfill:
            app.logger.info('[hitl_config] backfilled hitl_config from editor snapshots')
    except Exception:
        pass
    try:
        did_scrub_cfg = backend._scrub_unverified_hitl_config_in_scenario_catalog()
        if did_scrub_cfg:
            app.logger.info('[hitl_config] scrubbed unverified hitl_config entries from scenario_catalog.json')
    except Exception:
        pass

    app.run(host=host, port=port, debug=debug, use_reloader=use_reloader, threaded=True)


if __name__ == '__main__':
    main()
