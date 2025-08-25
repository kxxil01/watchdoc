import os
import tempfile
import subprocess
from typing import List, Optional, Any
from yaml import safe_load, safe_dump


def update_compose_file(service, new_image: str, logger, compose_timeout_sec: Optional[int] = None) -> bool:
    """Update the docker-compose file with new image tag using YAML mutation.

    Falls back to sudo copy if direct write is not permitted.
    """
    compose_path = service.compose_file
    try:
        with open(compose_path, 'r') as f:
            data = safe_load(f)
    except PermissionError as e:
        # Attempt sudo read via cat if allowed
        try:
            result = subprocess.run(
                ['/bin/cat', compose_path],
                capture_output=True,
                text=True,
                check=True,
            )
        except subprocess.CalledProcessError:
            try:
                result = subprocess.run(
                    ['sudo', '-n', '/bin/cat', compose_path],
                    capture_output=True,
                    text=True,
                    check=True,
                    timeout=compose_timeout_sec,
                )
            except subprocess.CalledProcessError as se:
                logger.error(f"Failed to read compose file {compose_path} with sudo: {se.stderr or se}")
                return False
        try:
            data = safe_load(result.stdout)
            if data is None:
                data = {}
        except Exception as pe:
            logger.error(f"Failed to parse compose YAML from {compose_path}: {pe}")
            return False
    except Exception as e:
        logger.error(f"Failed to read compose file {compose_path}: {e}")
        return False
    try:
        services = data.get('services', {})
        if service.compose_service not in services:
            logger.error(f"Service '{service.compose_service}' not found in {compose_path}")
            return False
        svc = services[service.compose_service]
        old_image = svc.get('image')
        if old_image == new_image:
            logger.debug("Image already up to date; no changes to compose file")
            return False
        svc['image'] = new_image
    except Exception as e:
        logger.error(f"Failed to update YAML structure: {e}")
        return False
    # Capture original ownership and mode to restore later if needed
    try:
        st = os.stat(compose_path)
        orig_uid, orig_gid = st.st_uid, st.st_gid
        orig_mode = st.st_mode & 0o777
    except Exception:
        orig_uid = orig_gid = None
        orig_mode = None
    # Write to a temp file, then move into place (sudo cp if needed)
    tmp = None
    try:
        tmp = tempfile.NamedTemporaryFile('w', delete=False, prefix='docker-compose-', suffix='.yml')
        safe_dump(data, tmp, default_flow_style=False, sort_keys=False)
        tmp_path = tmp.name
        tmp.close()
        if orig_mode is not None:
            try:
                os.chmod(tmp_path, orig_mode)
            except Exception:
                pass
    except Exception as e:
        if tmp and not tmp.closed:
            tmp.close()
        logger.error(f"Failed to write temporary compose file: {e}")
        return False
    try:
        # Try to replace atomically
        os.replace(tmp_path, compose_path)
        logger.info(f"Updated {compose_path} with new image: {new_image}")
        # Restore ownership if known (owner may change with os.replace)
        if orig_uid is not None and orig_gid is not None:
            try:
                os.chown(compose_path, orig_uid, orig_gid)
            except PermissionError:
                try:
                    subprocess.run(
                        ['sudo', '-n', '/bin/chown', f'{orig_uid}:{orig_gid}', compose_path],
                        check=True,
                        capture_output=True,
                        text=True,
                        timeout=compose_timeout_sec,
                    )
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Failed to restore compose file ownership: {e.stderr}")
        return True
    except PermissionError:
        logger.info(f"Permission denied replacing {compose_path}, attempting sudo copy")
        try:
            subprocess.run(['sudo', '/bin/cp', tmp_path, compose_path], check=True, capture_output=True, text=True, timeout=compose_timeout_sec)
            logger.info(f"Updated {compose_path} via sudo with new image: {new_image}")
            # Restore ownership if known
            if orig_uid is not None and orig_gid is not None:
                try:
                    subprocess.run(['sudo', '/bin/chown', f'{orig_uid}:{orig_gid}', compose_path], check=True, capture_output=True, text=True, timeout=compose_timeout_sec)
                except subprocess.CalledProcessError as e:
                    logger.warning(f"Failed to restore compose file ownership: {e.stderr}")
            return True
        except subprocess.CalledProcessError as e:
            logger.error(f"Failed to copy compose file via sudo: {e.stderr}")
            return False
        finally:
            try:
                os.remove(tmp_path)
            except Exception:
                pass
    except Exception as e:
        logger.error(f"Failed to update compose file {compose_path}: {e}")
        try:
            os.remove(tmp_path)
        except Exception:
            pass
        return False


def get_compose_command(shutil_module) -> List[str]:
    """Determine docker compose command (plugin or standalone).

    Accepts the calling module's `shutil` so callers can allow monkeypatching
    on their own imported object.
    """
    if shutil_module.which('docker') is not None:
        return ['docker', 'compose']
    if shutil_module.which('docker-compose') is not None:
        return ['docker-compose']
    return ['docker-compose']


def run_compose(args: List[str], cwd: str, logger, timeout: Optional[int] = None) -> None:
    """Run compose command with fallback to sudo (non-interactive)."""
    try:
        subprocess.run(
            args, cwd=cwd, capture_output=True, text=True, check=True, timeout=timeout
        )
        return
    except subprocess.CalledProcessError as e:
        try:
            logger.info("Retrying compose command with sudo")
            subprocess.run(
                ['sudo', '-n', *args],
                cwd=cwd,
                capture_output=True,
                text=True,
                check=True,
                timeout=timeout,
            )
            return
        except subprocess.CalledProcessError as e2:
            raise RuntimeError(f"Compose command failed: {e2.stderr or e.stderr}")
