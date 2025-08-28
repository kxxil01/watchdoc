import os
import tempfile
from types import SimpleNamespace

from docker_updater import DockerUpdater, ServiceConfig


def make_updater():
    u = DockerUpdater.__new__(DockerUpdater)
    u.logger = __import__('logging').getLogger('test')
    # Minimal fields used by methods
    u.compose_timeout_sec = 5
    u.health_timeout = 5
    u.health_stable_seconds = 0
    u.state_backup_count = 2
    u.state_lock_file = ''
    u.state_backup_dir = None
    # Provide a minimal docker client placeholder
    u.docker_client = SimpleNamespace(containers=SimpleNamespace(list=lambda **kwargs: []))
    return u


def test_in_maintenance_window_true():
    u = make_updater()
    assert u._in_maintenance_window('00:00-23:59') is True


def test_perform_update_with_rollback_health_failure(monkeypatch, tmp_path):
    u = make_updater()
    svc = ServiceConfig(
        name='svc', image='nginx:latest', compose_file=str(tmp_path / 'dc.yml'), compose_service='web'
    )
    open(svc.compose_file, 'w').write('')

    calls = []
    monkeypatch.setattr(u, 'update_compose_file', lambda s, img: calls.append(('update', img)) or True)
    monkeypatch.setattr(u, 'restart_service', lambda s: True)
    monkeypatch.setattr(u, 'wait_for_health', lambda s: False)

    ok = u.perform_update_with_rollback(svc, 'nginx:old', 'nginx:new', 'sha256:new')
    assert ok is False
    assert calls[0] == ('update', 'nginx:new')
    assert calls[1] == ('update', 'nginx:old')


class FakeContainer:
    def __init__(self, img_id):
        self._id = img_id
        self.attrs = {'State': {'Status': 'running'}}
        self.image = SimpleNamespace(id=img_id)

    def reload(self):
        return


def test_perform_update_with_rollback_success(monkeypatch, tmp_path):
    u = make_updater()
    svc = ServiceConfig(
        name='svc', image='nginx:latest', compose_file=str(tmp_path / 'dc.yml'), compose_service='web'
    )
    open(svc.compose_file, 'w').write('')

    calls = []
    monkeypatch.setattr(u, 'update_compose_file', lambda s, img: calls.append(('update', img)) or True)
    monkeypatch.setattr(u, 'restart_service', lambda s: True)
    monkeypatch.setattr(u, 'wait_for_health', lambda s: True)
    monkeypatch.setattr(u, '_find_service_containers', lambda s: [FakeContainer('sha256:abcd')])

    ok = u.perform_update_with_rollback(svc, 'nginx:old', 'nginx:new', 'sha256:abcd')
    assert ok is True
    assert calls[0] == ('update', 'nginx:new')
