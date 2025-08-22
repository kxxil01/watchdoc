import os
import json
import tempfile
from datetime import datetime
from docker_updater import DockerUpdater, ServiceConfig


def make_updater():
    u = DockerUpdater.__new__(DockerUpdater)
    u.logger = __import__('logging').getLogger('test')
    # Initialize fields used by save_state/load_state when bypassing __init__
    u.state_backup_count = 2
    u.state_lock_file = ''
    u.state_backup_dir = None
    return u


def test_save_and_load_state_roundtrip(tmp_path):
    u = make_updater()
    u.services = [
        ServiceConfig(
            name='svc1',
            image='nginx:latest',
            compose_file=str(tmp_path / 'dc.yml'),
            compose_service='web'
        )
    ]
    u.state_file = str(tmp_path / 'state.json')

    # Set state and save
    u.services[0].current_digest = 'sha256:abc123'
    u.services[0].current_tag = 'v1.2.3'
    u.services[0].last_updated = datetime(2024, 1, 1, 12, 0, 0)
    u.save_state()

    # Create a new instance and load
    u2 = make_updater()
    u2.services = [
        ServiceConfig(
            name='svc1',
            image='nginx:latest',
            compose_file=str(tmp_path / 'dc.yml'),
            compose_service='web'
        )
    ]
    u2.state_file = u.state_file
    u2.load_state()

    svc = u2.services[0]
    assert svc.current_digest == 'sha256:abc123'
    assert svc.current_tag == 'v1.2.3'
    assert isinstance(svc.last_updated, datetime)


def test_state_backup_rotation_and_recovery(tmp_path):
    # Configure updater to keep only 2 backups
    u = make_updater()
    u.services = [
        ServiceConfig(
            name='svc1',
            image='nginx:latest',
            compose_file=str(tmp_path / 'dc.yml'),
            compose_service='web'
        )
    ]
    u.state_file = str(tmp_path / 'state.json')
    u.state_backup_count = 2

    # Create several saves to generate backups
    for i in range(4):
        u.services[0].current_digest = f'sha256:abc{i}'
        u.services[0].current_tag = f'v1.0.{i}'
        u.services[0].last_updated = datetime(2024, 1, 1, 12, 0, i)
        u.save_state()

    backups = [p for p in tmp_path.iterdir() if p.name.startswith('updater_state-')]
    assert len(backups) <= 2

    # Corrupt main state and ensure we can load from backup
    with open(u.state_file, 'w') as f:
        f.write('{corrupted json')

    u2 = make_updater()
    u2.services = [
        ServiceConfig(
            name='svc1',
            image='nginx:latest',
            compose_file=str(tmp_path / 'dc.yml'),
            compose_service='web'
        )
    ]
    u2.state_file = u.state_file
    u2.load_state()
    assert u2.services[0].current_tag is not None
