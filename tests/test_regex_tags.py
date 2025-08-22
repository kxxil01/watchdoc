from datetime import datetime, timedelta
from docker_updater import DockerUpdater, ServiceConfig


class FakeECRClient:
    def __init__(self, pages):
        self.pages = pages

    def describe_images(self, **kwargs):
        token = kwargs.get('nextToken')
        if token is None:
            resp = {'imageDetails': self.pages[0]}
            if len(self.pages) > 1:
                resp['nextToken'] = 'tok1'
            return resp
        else:
            return {'imageDetails': self.pages[1]}


def test_tag_regex_matching_picks_latest(monkeypatch):
    u = DockerUpdater.__new__(DockerUpdater)
    u.logger = __import__('logging').getLogger('test')

    now = datetime.now()
    older = now - timedelta(hours=1)
    pages = [
        [
            {'imageTags': ['staging-a1b2c3d'], 'imagePushedAt': older},
            {'imageTags': ['other'], 'imagePushedAt': older},
        ],
        [
            {'imageTags': ['staging-abcdef1'], 'imagePushedAt': now},
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
        tag_regex=r'^staging-[a-f0-9]{7}$',
    )

    latest = u.get_latest_tag_for_pattern(svc)
    assert latest == 'staging-abcdef1'

