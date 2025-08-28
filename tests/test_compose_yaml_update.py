import os
import tempfile
from docker_updater import DockerUpdater, ServiceConfig


def make_updater_with_logger(tmpdir):
    # Build minimal instance with sane defaults
    u = DockerUpdater.__new__(DockerUpdater)
    u.logger = __import__('logging').getLogger('test')
    u.services = []
    return u


def write_compose(contents: str) -> str:
    fd, path = tempfile.mkstemp(prefix='compose-', suffix='.yml')
    with os.fdopen(fd, 'w') as f:
        f.write(contents)
    return path


def test_update_compose_file_image_change(tmp_path):
    u = make_updater_with_logger(tmp_path)
    compose = """
version: '3'
services:
  app:
    image: nginx:latest
"""
    compose_path = write_compose(compose)
    svc = ServiceConfig(
        name='test-svc',
        image='nginx:latest',
        compose_file=compose_path,
        compose_service='app'
    )

    assert u.update_compose_file(svc, 'nginx:1.2.3') is True

    # Verify file content updated
    with open(compose_path, 'r') as f:
        content = f.read()
    assert 'nginx:1.2.3' in content

    # Re-applying same image should return False (no-op)
    assert u.update_compose_file(svc, 'nginx:1.2.3') is False
