from datetime import datetime, timedelta
from docker_updater import DockerUpdater, ServiceConfig


class FakeECRClient:
    def __init__(self, pages):
        self.pages = pages
        self.calls = 0

    def describe_images(self, **kwargs):
        token = kwargs.get('nextToken')
        if token is None:
            self.calls += 1
            page = self.pages[0]
            resp = {'imageDetails': page}
            if len(self.pages) > 1:
                resp['nextToken'] = 'tok1'
            return resp
        else:
            self.calls += 1
            page = self.pages[1]
            return {'imageDetails': page}


def test_get_latest_tag_for_pattern_picks_newest(monkeypatch):
    u = DockerUpdater.__new__(DockerUpdater)
    u.logger = __import__('logging').getLogger('test')

    now = datetime.utcnow()
    older = now - timedelta(days=1)

    pages = [
        [
            {'imageTags': ['staging-a1'], 'imagePushedAt': older},
            {'imageTags': ['other'], 'imagePushedAt': older},
        ],
        [
            {'imageTags': ['staging-a2'], 'imagePushedAt': now},
        ],
    ]

    def fake_client(name, region_name=None, aws_access_key_id=None, aws_secret_access_key=None):
        assert name == 'ecr'
        return FakeECRClient(pages)

    monkeypatch.setattr('docker_updater.boto3.client', fake_client)

    svc = ServiceConfig(
        name='svc',
        image='111111111111.dkr.ecr.us-east-1.amazonaws.com/repo:staging-old',
        compose_file='dc.yml',
        compose_service='web',
        registry_type='ecr',
        tag_pattern='staging-*',
    )

    latest = u.get_latest_tag_for_pattern(svc)
    assert latest == 'staging-a2'


def test_get_latest_semver_tag_picks_highest(monkeypatch):
    u = DockerUpdater.__new__(DockerUpdater)
    u.logger = __import__('logging').getLogger('test')

    now = datetime.utcnow()
    older = now - timedelta(days=2)

    pages = [
        [
            {'imageTags': ['v1.1.0'], 'imagePushedAt': older},
            {'imageTags': ['v1.2.0'], 'imagePushedAt': now},
        ]
    ]

    def fake_client(name, region_name=None, aws_access_key_id=None, aws_secret_access_key=None):
        assert name == 'ecr'
        return FakeECRClient(pages)

    monkeypatch.setattr('docker_updater.boto3.client', fake_client)

    svc = ServiceConfig(
        name='svc',
        image='111111111111.dkr.ecr.us-east-1.amazonaws.com/repo:v1.0.0',
        compose_file='dc.yml',
        compose_service='web',
        registry_type='ecr',
        semver_pattern='v*',
    )

    latest = u.get_latest_semver_tag(svc)
    assert latest == 'v1.2.0'
