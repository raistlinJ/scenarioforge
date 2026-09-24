"""Background creation and private storage of execution evaluation artifacts."""
import hashlib
import json
import threading
from pathlib import Path

from scenarioforge.evaluation.execution import build_execution_package


class EvaluationArtifacts:
    def __init__(self, backend):
        self.backend = backend
        self.lock = threading.Lock()
        self.active = set()

    def directory(self, run_id):
        key = hashlib.sha256(str(run_id).encode()).hexdigest()[:24]
        return Path(self.backend._outputs_dir()) / 'evaluation-packages' / key

    def status(self, run_id):
        path = self.directory(run_id) / 'status.json'
        if not path.is_file():
            return {'state': 'missing', 'message': 'No evaluation package was generated for this execution'}
        result = json.loads(path.read_text())
        if result['state'] == 'preparing' and str(run_id) not in self.active:
            return {'state': 'error', 'message': 'Package generation was interrupted; execute the scenario again'}
        return result

    def _write(self, directory, value):
        path = directory / 'status.json'
        temporary = directory / 'status.json.tmp'
        temporary.write_text(json.dumps(value))
        temporary.chmod(0o600)
        temporary.replace(path)

    def schedule(self, *, run_id, xml_path, scenario, session_id, core_cfg):
        run_id = str(run_id)
        directory = self.directory(run_id)
        expected_xml_sha256 = hashlib.sha256(Path(xml_path).read_bytes()).hexdigest()
        with self.lock:
            if (directory / 'status.json').exists():
                return
            directory.mkdir(parents=True, mode=0o700, exist_ok=True)
            self.active.add(run_id)
            self._write(directory, {'state': 'preparing', 'message': 'Checking deployment and preparing evaluation package'})
        # Copy connection values before the execute monitor releases its state.
        config = dict(core_cfg or {})
        def worker():
            try:
                result = build_execution_package(backend=self.backend, xml_path=xml_path,
                    scenario=scenario, session_id=session_id, core_cfg=config,
                    output=directory / 'package', suite_id='eval-' + directory.name,
                    expected_xml_sha256=expected_xml_sha256)
            except Exception as exc:
                self.backend.app.logger.exception('Evaluation artifact generation failed for run %s', run_id)
                result = {'state': 'error', 'message': 'Evaluation package could not be generated; check saved Flow flags, addresses, and server logs'}
            try:
                self._write(directory, result)
            finally:
                with self.lock:
                    self.active.discard(run_id)
        thread = threading.Thread(target=worker, daemon=True, name='evaluation-' + directory.name)
        try:
            thread.start()
        except Exception:
            with self.lock:
                self.active.discard(run_id)
            self._write(directory, {'state': 'error', 'message': 'Could not start evaluation package generation'})
            raise
