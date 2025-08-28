import os
import base64
import subprocess
from datetime import datetime, timedelta, timezone

import boto3
from google.auth import default
from google.auth.transport.requests import Request


def authenticate_ecr(
    region: str,
    logger,
    compose_timeout_sec: int,
    ecr_auth_cache: dict,
    retry_func,
    aws_access_key_id: str | None = None,
    aws_secret_access_key: str | None = None,
) -> bool:
    try:
        # Always use timezone-aware UTC datetimes
        now = datetime.now(timezone.utc)

        def to_aware_utc(dt):
            if dt is None:
                return None
            if getattr(dt, 'tzinfo', None) is None:
                # Assume UTC when tzinfo missing (ECR returns UTC)
                return dt.replace(tzinfo=timezone.utc)
            try:
                return dt.astimezone(timezone.utc)
            except Exception:
                # Fallback: treat as UTC
                return dt.replace(tzinfo=timezone.utc)

        cache = ecr_auth_cache.get(region)
        # Normalize cached timestamps to aware UTC if present
        if cache and cache.get('expires'):
            cache['expires'] = to_aware_utc(cache['expires'])
        if cache and cache.get('last_login'):
            cache['last_login'] = to_aware_utc(cache['last_login'])

        if cache and cache.get('expires') and now < cache['expires'] - timedelta(minutes=5):
            # Token valid; re-login only if it's been a while
            username = cache['username']
            password = cache['password']
            endpoint = cache['endpoint']
            last_login = cache.get('last_login')
            if not last_login or (now - last_login) > timedelta(hours=1):
                # Re-login for current user
                login_result = subprocess.run(
                    ['docker', 'login', '--username', username, '--password-stdin', endpoint],
                    input=password,
                    text=True,
                    capture_output=True,
                    timeout=compose_timeout_sec,
                )
                if login_result.returncode != 0:
                    logger.warning(f"ECR re-login failed (cached token): {login_result.stderr}")
                    cache = None  # force refresh
                else:
                    cache['last_login'] = now
                    logger.info(f"ECR re-login succeeded for {region}")
                    # Also re-login under sudo for compose runs that escalate
                    try:
                        root_login = subprocess.run(
                            ['sudo', '-n', 'docker', 'login', '--username', username, '--password-stdin', endpoint],
                            input=password,
                            text=True,
                            capture_output=True,
                            timeout=compose_timeout_sec,
                        )
                        if root_login.returncode != 0:
                            logger.debug(f"Root ECR re-login warning: {root_login.stderr}")
                    except Exception as se:
                        logger.debug(f"Root ECR re-login skipped: {se}")
                    return True
            else:
                return True

        # Need new token
        if aws_access_key_id and aws_secret_access_key:
            ecr_client = boto3.client(
                'ecr',
                region_name=region,
                aws_access_key_id=aws_access_key_id,
                aws_secret_access_key=aws_secret_access_key,
            )
        else:
            ecr_client = boto3.client('ecr', region_name=region)
        response = retry_func(ecr_client.get_authorization_token)
        auth = response['authorizationData'][0]
        token = auth['authorizationToken']
        endpoint = auth['proxyEndpoint']
        expires = to_aware_utc(auth.get('expiresAt')) or (now + timedelta(hours=12))
        username, password = base64.b64decode(token).decode().split(':')
        login_result = subprocess.run(
            ['docker', 'login', '--username', username, '--password-stdin', endpoint],
            input=password,
            text=True,
            capture_output=True,
            timeout=compose_timeout_sec,
        )
        if login_result.returncode == 0:
            ecr_auth_cache[region] = {
                'username': username,
                'password': password,
                'endpoint': endpoint,
                'expires': to_aware_utc(expires),
                'last_login': now,
            }
            logger.info(f"ECR login succeeded for region {region}")
            # Also login under sudo so root has credentials for compose
            try:
                root_login = subprocess.run(
                    ['sudo', '-n', 'docker', 'login', '--username', username, '--password-stdin', endpoint],
                    input=password,
                    text=True,
                    capture_output=True,
                    timeout=compose_timeout_sec,
                )
                if root_login.returncode != 0:
                    logger.debug(f"Root ECR login warning: {root_login.stderr}")
            except Exception as se:
                logger.debug(f"Root ECR login skipped: {se}")
            return True
        else:
            logger.error(f"ECR authentication failed: {login_result.stderr}")
            return False
    except Exception as e:
        logger.error(f"ECR authentication error: {e}")
        return False


def authenticate_gcr(project_id: str | None, service_account_path: str | None, logger) -> bool:
    try:
        if service_account_path:
            os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = service_account_path

        credentials, project = default()
        if project_id:
            project = project_id

        auth_req = Request()
        credentials.refresh(auth_req)
        access_token = credentials.token

        registries = ['gcr.io', 'us.gcr.io', 'eu.gcr.io', 'asia.gcr.io']
        for registry in registries:
            login_result = subprocess.run(
                ['docker', 'login', '-u', '_token', '--password-stdin', registry],
                input=access_token,
                text=True,
                capture_output=True,
            )
            if login_result.returncode != 0:
                logger.warning(f"Failed to login to {registry}: {login_result.stderr}")

        logger.info("Successfully authenticated with Google Container Registry")
        return True
    except Exception as e:
        logger.error(f"GCR authentication error: {e}")
        return False


def authenticate_registry(service, logger, compose_timeout_sec, ecr_auth_cache, retry_func) -> bool:
    if service.registry_type == "ecr":
        region = (service.registry_config or {}).get('region', 'us-east-1')
        aws_access_key_id = (service.registry_config or {}).get('aws_access_key_id')
        aws_secret_access_key = (service.registry_config or {}).get('aws_secret_access_key')
        return authenticate_ecr(
            region,
            logger,
            compose_timeout_sec,
            ecr_auth_cache,
            retry_func,
            aws_access_key_id,
            aws_secret_access_key,
        )
    elif service.registry_type == "gcr":
        project_id = (service.registry_config or {}).get('project_id')
        service_account_path = (service.registry_config or {}).get('service_account_path')
        return authenticate_gcr(project_id, service_account_path, logger)
    elif service.registry_type == "docker_hub":
        username = (service.registry_config or {}).get('username')
        password = (service.registry_config or {}).get('password')
        if username and password:
            login_result = subprocess.run(
                ['docker', 'login', '--username', username, '--password-stdin'],
                input=password,
                text=True,
                capture_output=True,
            )
            if login_result.returncode == 0:
                logger.info("Successfully authenticated with Docker Hub")
                return True
            else:
                logger.error(f"Docker Hub authentication failed: {login_result.stderr}")
                return False
        return True
    return True
