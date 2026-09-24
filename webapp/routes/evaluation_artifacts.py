"""Report artifact download, authorized against run history and scenario access."""
from flask import jsonify, send_file
from webapp.routes._registration import begin_route_registration, mark_routes_registered


def register(app, *, backend, artifacts):
    if not begin_route_registration(app, 'evaluation_artifacts_routes'):
        return

    def authorized_run(run_id):
        user = backend._current_user()
        if not user or user.get('role') not in {'admin', 'builder'}:
            return None
        record = next((r for r in backend._load_run_history() if str(r.get('run_id')) == run_id), None)
        if not record:
            return None
        names = record.get('scenario_names') or [record.get('scenario_name')]
        names = [n for n in names if isinstance(n, str) and n]
        visible, _, _ = backend._builder_filter_report_scenarios(names, '', user=user)
        if not names or set(visible) != set(names):
            return None
        return record

    @app.get('/api/reports/<run_id>/evaluation')
    def evaluation_artifact_status(run_id):
        if authorized_run(run_id) is None:
            return jsonify(ok=False, error='Evaluation artifact unavailable for this user/run'), 403
        result = artifacts.status(run_id)
        result.pop('archive', None)
        return jsonify(result)

    @app.get('/api/reports/<run_id>/evaluation/download')
    def evaluation_artifact_download(run_id):
        if authorized_run(run_id) is None:
            return jsonify(ok=False, error='Evaluation artifact unavailable for this user/run'), 403
        result = artifacts.status(run_id)
        if result.get('state') != 'complete':
            return jsonify(ok=False, error=result.get('message')), 409
        # Path is derived from the authorized run, not from a caller-supplied path.
        archive = artifacts.directory(run_id) / 'package.zip'
        if not archive.is_file() or archive.is_symlink():
            return jsonify(ok=False, error='Evaluation archive missing'), 404
        response = send_file(archive, as_attachment=True, download_name=result['suite_id'] + '.zip')
        response.headers['Cache-Control'] = 'private, no-store'
        return response

    mark_routes_registered(app, 'evaluation_artifacts_routes')
