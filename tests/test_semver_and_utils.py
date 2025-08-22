import datetime
import types
from docker_updater import DockerUpdater


def make_updater():
    # Create a minimal instance without running __init__ (avoids Docker init)
    return DockerUpdater.__new__(DockerUpdater)


def test_parse_semver_basic():
    u = make_updater()
    assert u.parse_semver('v1.2.3') == (1, 2, 3, None)
    assert u.parse_semver('release-2.0.0') == (2, 0, 0, None)
    assert u.parse_semver('version-0.1.0') == (0, 1, 0, None)


def test_parse_semver_prerelease():
    u = make_updater()
    assert u.parse_semver('1.0.0-beta') == (1, 0, 0, ['beta'])
    assert u.parse_semver('1.2.3-rc.1') == (1, 2, 3, ['rc', 1])


def test_compare_semver_ordering():
    u = make_updater()
    assert u.compare_semver('1.2.3', '1.2.2') == 1
    assert u.compare_semver('1.2.3', '1.2.3') == 0
    assert u.compare_semver('1.2.2', '1.2.3') == -1


def test_compare_semver_prerelease_vs_stable():
    u = make_updater()
    assert u.compare_semver('1.2.3-alpha', '1.2.3') == -1
    assert u.compare_semver('1.2.3', '1.2.3-alpha') == 1


def test_compare_semver_prerelease_ordering():
    u = make_updater()
    # From SemVer 2.0.0 examples
    order = [
        '1.0.0-alpha',
        '1.0.0-alpha.1',
        '1.0.0-alpha.beta',
        '1.0.0-beta',
        '1.0.0-beta.2',
        '1.0.0-beta.11',
        '1.0.0-rc.1',
        '1.0.0',
    ]
    for i in range(len(order) - 1):
        assert u.compare_semver(order[i], order[i + 1]) == -1


def test_get_compose_command_prefers_docker_compose(monkeypatch):
    u = make_updater()

    calls = {}

    def fake_which(cmd):
        calls[cmd] = True
        if cmd == 'docker':
            return '/usr/bin/docker'
        return None

    monkeypatch.setattr('docker_updater.shutil.which', fake_which)
    assert u.get_compose_command() == ['docker', 'compose']
    assert 'docker' in calls


def test_get_compose_command_falls_back_legacy(monkeypatch):
    u = make_updater()

    def fake_which(cmd):
        if cmd == 'docker-compose':
            return '/usr/local/bin/docker-compose'
        return None

    monkeypatch.setattr('docker_updater.shutil.which', fake_which)
    assert u.get_compose_command() == ['docker-compose']
