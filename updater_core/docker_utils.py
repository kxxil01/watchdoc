import os
import time
import subprocess
from typing import List, Optional, Any


def get_image_digest(image_name: str, timeout: Optional[int], logger) -> Optional[str]:
    """Return image digest via `docker inspect` or None on failure."""
    try:
        result = subprocess.run(
            ['docker', 'inspect', '--format={{.RepoDigests}}', image_name],
            capture_output=True,
            text=True,
            check=True,
            timeout=timeout,
        )
        digests = result.stdout.strip()
        if digests and digests != '[]':
            digest_start = digests.find('sha256:')
            if digest_start != -1:
                digest_end = digests.find(']', digest_start)
                if digest_end == -1:
                    digest_end = len(digests)
                return digests[digest_start:digest_end]
        return None
    except subprocess.CalledProcessError as e:
        logger.error(f"Failed to get digest for {image_name}: {e}")
        return None


def pull_image(docker_client, image_name: str, logger, attempts: int = 3) -> bool:
    """Pull the latest version of an image with simple retries."""
    for attempt in range(1, attempts + 1):
        try:
            logger.info(f"Pulling image: {image_name}")
            docker_client.images.pull(image_name)
            return True
        except Exception as e:
            if attempt == attempts:
                logger.error(f"Failed to pull image {image_name}: {e}")
                return False
            sleep = 1.0 * (2 ** (attempt - 1))
            logger.warning(f"Pull failed for {image_name}: {e}. Retrying in {sleep:.1f}s")
            time.sleep(sleep)


def find_service_containers(docker_client, service, logger) -> List[Any]:
    try:
        project = os.path.basename(os.path.dirname(os.path.abspath(service.compose_file))).replace(' ', '').lower()
        containers = docker_client.containers.list(all=True)
        matched = []
        for c in containers:
            labels = getattr(c, 'labels', None) or getattr(c, 'attrs', {}).get('Config', {}).get('Labels', {}) or {}
            svc = labels.get('com.docker.compose.service')
            proj = labels.get('com.docker.compose.project')
            if svc == service.compose_service and (not proj or proj == project):
                matched.append(c)
        return matched
    except Exception as e:
        logger.warning(f"Error finding containers for {service.name}: {e}")
        return []


def wait_for_health(docker_client, service, logger, timeout: int, stable_seconds: int) -> bool:
    deadline = time.time() + timeout
    last_healthy = None
    while time.time() < deadline:
        containers = find_service_containers(docker_client, service, logger)
        if not containers:
            time.sleep(2)
            continue
        all_ok = True
        for c in containers:
            try:
                c.reload()
                state = c.attrs.get('State', {})
                health = state.get('Health', {}).get('Status')
                status = state.get('Status')
                if health:
                    if health != 'healthy':
                        all_ok = False
                        break
                else:
                    if status != 'running':
                        all_ok = False
                        break
            except Exception:
                all_ok = False
                break
        if all_ok:
            if last_healthy is None:
                last_healthy = time.time()
            if time.time() - last_healthy >= stable_seconds:
                return True
        else:
            last_healthy = None
        time.sleep(2)
    return False

