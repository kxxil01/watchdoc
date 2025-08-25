import json
import os
import time
import fcntl
from datetime import datetime
from typing import List, Optional


def _prune_state_backups(state_dir: str, keep: int) -> None:
    try:
        backups = [
            os.path.join(state_dir, f)
            for f in os.listdir(state_dir)
            if f.startswith('updater_state-') and f.endswith('.json')
        ]
        backups.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        for p in backups[keep:]:
            try:
                os.remove(p)
            except Exception:
                pass
    except Exception:
        pass


def save_state(
    services: List[object],
    state_file: str,
    state_lock_file: str,
    state_backup_dir: Optional[str],
    state_backup_count: int,
    logger,
) -> Optional[tuple[str, str]]:
    state = {'services': []}
    for svc in services:
        state['services'].append(
            {
                'name': svc.name,
                'image': svc.image,
                'current_digest': svc.current_digest,
                'current_tag': svc.current_tag,
                'last_updated': svc.last_updated.isoformat() if getattr(svc, 'last_updated', None) else None,
            }
        )

    try:
        state_dir = os.path.dirname(state_file) or '.'
        if state_dir and not os.path.exists(state_dir):
            os.makedirs(state_dir, exist_ok=True)

        def write_within_context():
            data = json.dumps(state, indent=2)
            tmp_path = os.path.join(state_dir, f'.tmp_state_{int(time.time()*1000)}.json')
            with open(tmp_path, 'w') as tf:
                tf.write(data)
                tf.flush()
                os.fsync(tf.fileno())
            os.replace(tmp_path, state_file)
            try:
                dir_fd = os.open(state_dir, os.O_DIRECTORY)
                try:
                    os.fsync(dir_fd)
                finally:
                    os.close(dir_fd)
            except Exception:
                pass
            ts = datetime.now().strftime('%Y%m%d%H%M%S')
            backup_root = state_backup_dir or state_dir
            try:
                os.makedirs(backup_root, exist_ok=True)
            except Exception:
                backup_root = state_dir
            backup_path = os.path.join(backup_root, f'updater_state-{ts}.json')
            try:
                with open(backup_path, 'w') as bf:
                    bf.write(data)
                _prune_state_backups(backup_root, state_backup_count)
            except Exception as e:
                logger.debug(f"Unable to write state backup: {e}")

        if state_lock_file:
            with open(state_lock_file, 'w') as lock_fd:
                try:
                    fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
                except Exception:
                    pass
                write_within_context()
        else:
            write_within_context()
    except Exception as e:
        # Fallback to local file
        fallback = './updater_state.json'
        try:
            with open(fallback, 'w') as f:
                json.dump(state, f, indent=2)
            # Caller must update its state_file on success if desired
            logger.warning(f"Could not write state to system path; wrote to {fallback}: {e}")
        except Exception as e2:
            logger.error(f"Failed to write state to fallback path {fallback}: {e2}")
        return (fallback, fallback + '.lock')
    return None


def load_state(
    services: List[object],
    state_file: str,
    state_backup_dir: Optional[str],
    logger,
    counter_state_restored=None,
) -> None:
    def _load_from_path(path: str) -> bool:
        try:
            with open(path, 'r') as f:
                state = json.load(f)
            for service_data in state.get('services', []):
                for service in services:
                    if service.name == service_data['name']:
                        service.current_digest = service_data.get('current_digest')
                        service.current_tag = service_data.get('current_tag')
                        if service_data.get('last_updated'):
                            service.last_updated = datetime.fromisoformat(service_data['last_updated'])
                        break
            return True
        except Exception as e:
            logger.warning(f"Failed loading state from {path}: {e}")
            return False

    if os.path.exists(state_file) and _load_from_path(state_file):
        return
    # Try latest backup
    state_dir = state_backup_dir or (os.path.dirname(state_file) or '.')
    try:
        backups = [
            os.path.join(state_dir, f)
            for f in os.listdir(state_dir)
            if f.startswith('updater_state-') and f.endswith('.json')
        ]
        backups.sort(key=lambda p: os.path.getmtime(p), reverse=True)
        for bp in backups:
            if _load_from_path(bp):
                logger.info(f"Loaded state from backup: {bp}")
                if counter_state_restored is not None:
                    try:
                        counter_state_restored.inc()
                    except Exception:
                        pass
                return
    except Exception:
        pass


def cleanup_old_state(state_file: str, logger) -> None:
    try:
        # Remove old state files older than 30 days
        if os.path.exists(state_file):
            file_age = time.time() - os.path.getmtime(state_file)
            if file_age > 30 * 24 * 3600:  # 30 days
                os.remove(state_file)
                logger.info("Removed old state file")

        # Clean up temporary docker-compose files
        temp_dir = '/tmp'
        for filename in os.listdir(temp_dir):
            if filename.startswith('docker-compose-') and filename.endswith('.yml'):
                filepath = os.path.join(temp_dir, filename)
                try:
                    file_age = time.time() - os.path.getmtime(filepath)
                    if file_age > 3600:  # 1 hour
                        os.remove(filepath)
                        logger.debug(f"Removed old temp file: {filename}")
                except OSError:
                    pass
    except Exception as e:
        logger.warning(f"Error during cleanup: {e}")
