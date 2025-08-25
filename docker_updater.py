#!/usr/bin/env python3
"""
Docker Auto-Updater
A production-ready application that monitors Docker images and automatically updates containers
when new images with the same tag are available.
"""

import os
import sys
import json
import time
import logging
import subprocess
import tempfile
import base64
import re
import argparse
import shutil
import pwd
import grp
import fcntl
from datetime import datetime, timedelta
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
import docker
from docker.errors import DockerException, APIError
import boto3
from google.auth import default
from google.auth.transport.requests import Request
from yaml import safe_load, safe_dump
from updater_core.logging_utils import JSONFormatter
from updater_core.compose_utils import (
    get_compose_command as cu_get_compose_command,
    run_compose as cu_run_compose,
    update_compose_file as cu_update_compose_file,
)
from updater_core.semver_utils import (
    parse_semver as su_parse_semver,
    compare_semver as su_compare_semver,
)
from updater_core import docker_utils as du
from updater_core import state_utils as su
from updater_core import registry_utils as ru
from updater_core import config_utils as cu
from updater_core import metrics_utils as mu
from updater_core import notify_utils as nu

# Optional config validation and metrics
try:
    from jsonschema import validate as jsonschema_validate, ValidationError  # type: ignore
except Exception:  # pragma: no cover
    jsonschema_validate = None
    ValidationError = Exception
try:
    from prometheus_client import Counter, start_http_server  # type: ignore
except Exception:  # pragma: no cover
    Counter = None
    start_http_server = None


# JSONFormatter is provided by updater_core.logging_utils

# Load environment variables from .env file (quietly, no prints)
try:
    from dotenv import load_dotenv  # type: ignore
    env_file = '/etc/docker-auto-updater/.env'
    if os.path.exists(env_file):
        try:
            load_dotenv(env_file)
        except Exception:
            pass
except Exception:
    # python-dotenv not available or other non-fatal issue; continue with system env
    pass


from updater_core.models import ServiceConfig


class DockerUpdater:
    """Main Docker updater class."""
    
    def __init__(self, config_file: str = None):
        # Use environment variable or default to proper config directory
        if config_file is None:
            config_file = os.getenv('CONFIG_FILE', '/etc/docker-auto-updater/updater_config.json')
        self.config_file = config_file
        
        # Set state file path from environment or default
        self.state_file = os.getenv('STATE_FILE', '/var/lib/docker-auto-updater/updater_state.json')
        
        self.docker_client = None
        self.services: List[ServiceConfig] = []
        self.check_interval = 30  # seconds
        # State backup/retention configuration
        try:
            self.state_backup_count = int(os.getenv('STATE_BACKUPS', '5'))
        except Exception:
            self.state_backup_count = 5
        self.state_lock_file = (self.state_file or '') + '.lock'
        # ECR auth cache { region: {username, password, endpoint, expires: datetime, last_login: datetime} }
        self._ecr_auth_cache: Dict[str, Dict[str, Any]] = {}
        # Health and compose tuning
        try:
            self.health_timeout = int(os.getenv('HEALTH_TIMEOUT', '180'))
        except Exception:
            self.health_timeout = 180
        try:
            self.health_stable_seconds = int(os.getenv('HEALTH_STABLE', '10'))
        except Exception:
            self.health_stable_seconds = 10
        try:
            self.compose_timeout_sec = int(os.getenv('COMPOSE_TIMEOUT', '120'))
        except Exception:
            self.compose_timeout_sec = 120
        # Optional separate backup directory
        self.state_backup_dir = os.getenv('STATE_BACKUP_DIR')
        self.setup_logging()
        self.load_config()
        self.init_docker_client()
        self.init_metrics()
    
    def setup_logging(self):
        """Configure logging with proper formatting."""
        # Use environment variable for log level, default to INFO
        log_level = os.getenv('LOG_LEVEL', 'INFO').upper()

        # Use proper log directory that's writable, allow override
        log_dir = os.getenv('LOG_DIR', '/var/log/docker-auto-updater')
        log_file = os.path.join(log_dir, 'docker_updater.log')

        # Ensure log directory exists and is writable; fallback if needed
        try:
            os.makedirs(log_dir, exist_ok=True)
        except Exception:
            try:
                fallback_dir = os.path.abspath('./logs')
                os.makedirs(fallback_dir, exist_ok=True)
                log_dir = fallback_dir
                log_file = os.path.join(log_dir, 'docker_updater.log')
            except Exception:
                fallback_dir = '/tmp/docker-auto-updater'
                os.makedirs(fallback_dir, exist_ok=True)
                log_dir = fallback_dir
                log_file = os.path.join(log_dir, 'docker_updater.log')

        logging.basicConfig(
            level=getattr(logging, log_level, logging.INFO),
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        # Formatter selection
        fmt = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        if os.getenv('LOG_FORMAT', 'plain').lower() == 'json':
            fmt = JSONFormatter()
        for h in logging.getLogger().handlers:
            h.setFormatter(fmt)
        self.logger = logging.getLogger(__name__)

    def init_metrics(self):
        m = mu.init_metrics(self.logger)
        self.metrics_enabled = m['enabled']
        self.counter_updates = m['updates']
        self.counter_rollbacks = m['rollbacks']
        self.counter_failures = m['failures']
        self.counter_state_restored = m['state_restored']
    
    def init_docker_client(self):
        """Initialize Docker client with error handling."""
        try:
            self.docker_client = docker.from_env()
            self.docker_client.ping()
            self.logger.info("Docker client initialized successfully")
        except DockerException as e:
            self.logger.error(f"Failed to initialize Docker client: {e}")
            sys.exit(1)
    
    def resolve_env_vars(self, config_dict: Dict[str, Any]) -> Dict[str, Any]:
        return cu.resolve_env_vars(config_dict)

    def load_config(self):
        """Load configuration from JSON file."""
        if not os.path.exists(self.config_file):
            self.config_file = cu.create_default_config(self.config_file, self.logger)
        try:
            services, check_interval = cu.load_config(self.config_file, self.logger)
            self.services.extend(services)
            self.check_interval = check_interval
        except Exception as e:
            self.logger.error(f"Invalid configuration file: {e}")
            sys.exit(1)
    
    def create_default_config(self):
        self.config_file = cu.create_default_config(self.config_file, self.logger)

    def get_compose_command(self) -> List[str]:
        """Determine docker compose command (plugin or standalone)."""
        return cu_get_compose_command(shutil)
    
    def authenticate_ecr(self, region: str, aws_access_key_id: str = None, aws_secret_access_key: str = None) -> bool:
        return ru.authenticate_ecr(
            region,
            self.logger,
            self.compose_timeout_sec,
            self._ecr_auth_cache,
            self._retry,
            aws_access_key_id,
            aws_secret_access_key,
        )
    
    def authenticate_gcr(self, project_id: str = None, service_account_path: str = None) -> bool:
        return ru.authenticate_gcr(project_id, service_account_path, self.logger)
    
    def authenticate_registry(self, service: ServiceConfig) -> bool:
        """Authenticate with the appropriate registry for a service."""
        return ru.authenticate_registry(
            service,
            self.logger,
            self.compose_timeout_sec,
            self._ecr_auth_cache,
            self._retry,
        )
    
    def parse_semver(self, version: str) -> Tuple[int, int, int, Optional[List[Any]]]:
        return su_parse_semver(version)

    def compare_semver(self, version1: str, version2: str) -> int:
        return su_compare_semver(version1, version2)
    
    def _retry(self, func, *args, **kwargs):
        max_attempts = kwargs.pop('max_attempts', 3)
        base = kwargs.pop('base', 1.0)
        for attempt in range(1, max_attempts + 1):
            try:
                return func(*args, **kwargs)
            except Exception as e:
                if attempt == max_attempts:
                    raise
                sleep = base * (2 ** (attempt - 1)) + (0.1 * attempt)
                self.logger.warning(f"Transient error: {e}. Retrying in {sleep:.1f}s (attempt {attempt}/{max_attempts})")
                time.sleep(sleep)

    def get_latest_semver_tag(self, service: ServiceConfig) -> Optional[str]:
        """Get the latest semantic version tag for a service."""
        if not service.semver_pattern:
            return None
        
        try:
            # Parse ECR repository URL
            image_parts = service.image.split('/')
            if len(image_parts) < 2:
                return None
            
            registry_url = image_parts[0]
            repository_name = image_parts[1].split(':')[0]
            
            # Extract region from ECR URL
            region = registry_url.split('.')[3]
            
            # Create ECR client
            registry_config = service.registry_config or {}
            aws_access_key_id = registry_config.get('aws_access_key_id')
            aws_secret_access_key = registry_config.get('aws_secret_access_key')
            
            if aws_access_key_id and aws_secret_access_key:
                ecr_client = boto3.client(
                    'ecr',
                    region_name=region,
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key
                )
            else:
                ecr_client = boto3.client('ecr', region_name=region)
            
            # List images in repository with pagination
            semver_tags = []
            pattern_prefix = ''
            if service.semver_pattern:
                if service.semver_pattern.endswith('*'):
                    pattern_prefix = service.semver_pattern[:-1]
                else:
                    pattern_prefix = service.semver_pattern
            next_token = None
            while True:
                kwargs = {
                    'repositoryName': repository_name,
                    'maxResults': 100
                }
                if next_token:
                    kwargs['nextToken'] = next_token
                response = self._retry(ecr_client.describe_images, **kwargs)
                for image_detail in response.get('imageDetails', []):
                    if 'imageTags' in image_detail:
                        for tag in image_detail['imageTags']:
                            if not pattern_prefix or tag.startswith(pattern_prefix):
                                version = tag[len(pattern_prefix):] if pattern_prefix else tag
                                try:
                                    self.parse_semver(version)
                                    semver_tags.append({
                                        'tag': tag,
                                        'version': version,
                                        'pushed_at': image_detail.get('imagePushedAt')
                                    })
                                except Exception:
                                    continue
                next_token = response.get('nextToken')
                if not next_token:
                    break
            
            if not semver_tags:
                return None
            
            # Select max by SemVer precedence
            from functools import cmp_to_key
            semver_tags.sort(key=cmp_to_key(lambda a, b: self.compare_semver(a['version'], b['version'])))
            latest_tag = semver_tags[-1]['tag']
            self.logger.info(f"Found latest semver tag for pattern '{service.semver_pattern}': {latest_tag}")
            return latest_tag
            
        except Exception as e:
            self.logger.error(f"Error getting latest semver tag: {e}")
            return None
    
    def get_latest_tag_for_pattern(self, service: ServiceConfig) -> Optional[str]:
        """Get the latest tag matching a pattern/regex for ECR repositories."""
        if service.registry_type != "ecr" or not (service.tag_pattern or service.tag_regex):
            return None
        
        try:
            # Parse ECR repository URL
            image_parts = service.image.split('/')
            if len(image_parts) < 2:
                return None
            
            registry_url = image_parts[0]
            repository_name = image_parts[1].split(':')[0]
            
            # Extract region from ECR URL
            region = registry_url.split('.')[3]
            
            # Create ECR client
            registry_config = service.registry_config or {}
            aws_access_key_id = registry_config.get('aws_access_key_id')
            aws_secret_access_key = registry_config.get('aws_secret_access_key')
            
            if aws_access_key_id and aws_secret_access_key:
                ecr_client = boto3.client(
                    'ecr',
                    region_name=region,
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key
                )
            else:
                ecr_client = boto3.client('ecr', region_name=region)
            
            # List images in repository with pagination
            matching_images = []
            pattern_prefix = ''
            use_glob = False
            regex = None
            if service.tag_regex:
                try:
                    regex = re.compile(service.tag_regex)
                except re.error as e:
                    self.logger.error(f"Invalid tag_regex for {service.name}: {e}")
                    return None
            elif service.tag_pattern:
                # Determine if glob is needed
                if any(ch in service.tag_pattern for ch in ['*', '?', '[']):
                    use_glob = True
                else:
                    pattern_prefix = service.tag_pattern
            next_token = None
            while True:
                kwargs = {
                    'repositoryName': repository_name,
                    'maxResults': 100
                }
                if next_token:
                    kwargs['nextToken'] = next_token
                response = self._retry(ecr_client.describe_images, **kwargs)
                for image_detail in response.get('imageDetails', []):
                    if 'imageTags' in image_detail:
                        for tag in image_detail['imageTags']:
                            matched = False
                            if regex is not None:
                                matched = bool(regex.match(tag))
                            elif use_glob:
                                import fnmatch
                                matched = fnmatch.fnmatch(tag, service.tag_pattern)
                            else:
                                matched = tag.startswith(pattern_prefix)
                            if matched:
                                matching_images.append({
                                    'tag': tag,
                                    'pushed_at': image_detail.get('imagePushedAt')
                                })
                next_token = response.get('nextToken')
                if not next_token:
                    break
            
            if not matching_images:
                return None
            
            # Sort by push date (newest first)
            matching_images.sort(key=lambda x: x['pushed_at'], reverse=True)
            latest_tag = matching_images[0]['tag']
            
            self.logger.info(f"Found latest tag for pattern '{service.tag_pattern}': {latest_tag}")
            return latest_tag
            
        except Exception as e:
            self.logger.error(f"Error getting latest tag for pattern: {e}")
            return None
    
    def get_image_digest(self, image_name: str) -> Optional[str]:
        """Get the digest of a Docker image from the registry."""
        return du.get_image_digest(image_name, self.compose_timeout_sec, self.logger)
    
    def pull_image(self, image_name: str) -> bool:
        """Pull the latest version of an image."""
        return du.pull_image(self.docker_client, image_name, self.logger, attempts=3)
    
    def _run_compose(self, args: List[str], cwd: str, timeout: Optional[int] = None) -> None:
        """Run compose command with fallback to sudo (non-interactive)."""
        cu_run_compose(args, cwd, self.logger, timeout or self.compose_timeout_sec)

    def restart_service(self, service: ServiceConfig) -> bool:
        """Restart a service using docker-compose."""
        try:
            compose_path = os.path.abspath(service.compose_file)
            # Use a safe working directory to avoid directory execute permission issues
            safe_cwd = '/'
            cmd = self.get_compose_command()

            # Determine compose file owner for context/logging
            try:
                st = os.stat(compose_path)
                owner = pwd.getpwuid(st.st_uid).pw_name
                group = grp.getgrgid(st.st_gid).gr_name
                self.logger.info(f"Restarting service: {service.name} as current user; compose owned by {owner}:{group}")
            except Exception:
                self.logger.info(f"Restarting service: {service.name}")
            
            # Ensure image is pulled with compose (pull-then-up)
            self._run_compose([*cmd, '-f', compose_path, 'pull', service.compose_service], safe_cwd)
            # Stop the service (with fallback)
            self._run_compose([*cmd, '-f', compose_path, 'stop', service.compose_service], safe_cwd)
            # Start the service (with fallback)
            self._run_compose([*cmd, '-f', compose_path, 'up', '-d', service.compose_service], safe_cwd)
            
            self.logger.info(f"Successfully restarted service: {service.name}")
            return True
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to restart service {service.name}: {e}")
            self.logger.error(f"Error output: {e.stderr}")
            return False
    
    def check_for_updates(self, service: ServiceConfig) -> bool:
        """Check if a service needs to be updated."""
        # Authenticate with registry first
        if not self.authenticate_registry(service):
            self.logger.error(f"Failed to authenticate with registry for {service.name}")
            return False
        
        # Handle dynamic tag patterns and semver
        current_image = service.image
        latest_tag = None
        
        if service.semver_pattern:
            latest_tag = self.get_latest_semver_tag(service)
            if latest_tag:
                # Update image with latest semver tag
                image_base = service.image.split(':')[0]
                current_image = f"{image_base}:{latest_tag}"
                
                # Check if this is a newer version
                if service.current_tag:
                    current_version = service.current_tag.replace(service.semver_pattern.replace('*', ''), '')
                    new_version = latest_tag.replace(service.semver_pattern.replace('*', ''), '')
                    
                    if self.compare_semver(new_version, current_version) <= 0:
                        self.logger.debug(f"No newer semver found for {service.name}, current: {service.current_tag}")
                        return False
                
                self.logger.info(f"New semver tag found for {service.name}: {latest_tag}")
            else:
                self.logger.warning(f"No semver tags found matching pattern '{service.semver_pattern}' for {service.name}")
                return False
        elif service.tag_pattern:
            latest_tag = self.get_latest_tag_for_pattern(service)
            if latest_tag:
                # Update image with latest tag
                image_base = service.image.split(':')[0]
                current_image = f"{image_base}:{latest_tag}"
                
                # Check if this is a new tag
                if service.current_tag and service.current_tag == latest_tag:
                    self.logger.debug(f"No new tag found for {service.name}, current: {latest_tag}")
                    return False
                
                self.logger.info(f"New tag found for {service.name}: {latest_tag}")
            else:
                self.logger.warning(f"No tags found matching pattern '{service.tag_pattern}' for {service.name}")
                return False
        
        # Pull the latest image
        if not self.pull_image(current_image):
            return False
        
        # Get the new digest
        new_digest = self.get_image_digest(current_image)
        if not new_digest:
            self.logger.warning(f"Could not get digest for {current_image}")
            return False
        
        # For tag patterns or semver patterns, check if we have a new tag
        if service.tag_pattern or service.semver_pattern:
            latest_tag = current_image.split(':')[1]
            
            # If we have a new tag, update with rollback safeguards
            if service.current_tag != latest_tag:
                self.logger.info(f"New tag detected for {service.name}: {latest_tag}")
                base_image = service.image.split(':')[0]
                old_tag = service.current_tag or (service.image.split(':')[1] if ':' in service.image else 'latest')
                old_image = f"{base_image}:{old_tag}"
                if self.perform_update_with_rollback(service, old_image, current_image, new_digest):
                    old_digest_short = (service.current_digest[:12] + '...') if service.current_digest else 'none'
                    new_digest_short = (new_digest[:12] + '...') if new_digest else 'unknown'
                    self.logger.info(
                        f"Updated {service.name} ({service.compose_service}) @ {service.compose_file}: "
                        f"{old_image} -> {current_image} | digest {old_digest_short} -> {new_digest_short}"
                    )
                    service.current_digest = new_digest
                    service.current_tag = latest_tag
                    service.last_updated = datetime.now()
                    self.save_state()
                    return True
                else:
                    return False
            else:
                self.logger.debug(f"No new tag for {service.name}, current: {latest_tag}")
                return False
        else:
            # Standard digest-based comparison for fixed tags
            if service.current_digest is None:
                # First run, just store the digest
                service.current_digest = new_digest
                self.logger.info(f"Initial digest stored for {service.name}: {new_digest[:12]}...")
                return False
            
            if new_digest != service.current_digest:
                self.logger.info(f"New image detected for {service.name}")
                self.logger.info(f"Old digest: {service.current_digest[:12]}...")
                self.logger.info(f"New digest: {new_digest[:12]}...")
                
                # Update the service
                if self.restart_service(service):
                    base_image = service.image.split(':')[0]
                    current_tag = service.current_tag or (service.image.split(':')[1] if ':' in service.image else 'latest')
                    old_digest_short = (service.current_digest[:12] + '...') if service.current_digest else 'none'
                    new_digest_short = (new_digest[:12] + '...') if new_digest else 'unknown'
                    self.logger.info(
                        f"Updated {service.name} ({service.compose_service}) @ {service.compose_file}: "
                        f"image {base_image}:{current_tag} unchanged | digest {old_digest_short} -> {new_digest_short}"
                    )
                    service.current_digest = new_digest
                    service.last_updated = datetime.now()
                    self.save_state()
                    return True
                else:
                    self.logger.error(f"Failed to update service: {service.name}")
                    return False
        
        return False
    
    def update_compose_file(self, service: ServiceConfig, new_image: str) -> bool:
        """Delegate compose file image update to helper utility."""
        return cu_update_compose_file(service, new_image, self.logger, getattr(self, 'compose_timeout_sec', None))

    def _find_service_containers(self, service: ServiceConfig) -> List[Any]:
        return du.find_service_containers(self.docker_client, service, self.logger)

    def wait_for_health(self, service: ServiceConfig, timeout: Optional[int] = None, stable_seconds: Optional[int] = None) -> bool:
        return du.wait_for_health(
            self.docker_client,
            service,
            self.logger,
            timeout or self.health_timeout,
            stable_seconds or self.health_stable_seconds,
        )

    def _notify_event(self, event_type: str, payload: Dict[str, Any]):
        nu.notify_event(event_type, payload, self.logger)

    def perform_update_with_rollback(self, service: ServiceConfig, old_image: str, new_image: str, new_digest: str) -> bool:
        # Acquire a per-compose lock, falling back to a writable locks dir if needed
        lock_fd = None
        lock_path = service.compose_file + '.lock'
        try:
            lock_fd = open(lock_path, 'w')
        except PermissionError:
            # Fallback to a central locks directory
            alt_dirs = ['/var/run/docker-auto-updater/locks', '/tmp/docker-auto-updater/locks']
            safe_name = service.compose_file.replace('/', '_').replace(':', '_') + '.lock'
            for d in alt_dirs:
                try:
                    os.makedirs(d, exist_ok=True)
                    lock_path = os.path.join(d, safe_name)
                    lock_fd = open(lock_path, 'w')
                    self.logger.info(f"Using fallback lock path for {service.name}: {lock_path}")
                    break
                except Exception:
                    lock_fd = None
                    continue
        except Exception:
            lock_fd = None

        try:
            if lock_fd is not None:
                try:
                    fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
                except Exception:
                    pass

            # Update to new image
            if not self.update_compose_file(service, new_image):
                return False
            if not self.restart_service(service):
                return False
            # Health gate
            if not self.wait_for_health(service):
                self.logger.error(f"Health check failed after update for {service.name}, rolling back")
                if getattr(self, 'counter_failures', None):
                    self.counter_failures.inc()
                # rollback
                if self.update_compose_file(service, old_image) and self.restart_service(service):
                    if getattr(self, 'counter_rollbacks', None):
                        self.counter_rollbacks.inc()
                    self._notify_event('rollback', {
                        'service': service.name,
                        'compose_service': service.compose_service,
                        'compose_file': service.compose_file,
                        'old_image': old_image,
                        'failed_image': new_image,
                    })
                    return False
                else:
                    self.logger.error(f"Rollback failed for {service.name}")
                    return False
            # Post-update verification: running digest should match
            containers = self._find_service_containers(service)
            mismatch = False
            for c in containers:
                try:
                    c.reload()
                    img_id = c.image.id  # e.g., 'sha256:...'
                    if new_digest and not img_id.endswith(new_digest.split(':')[-1]):
                        mismatch = True
                        break
                except Exception:
                    pass
            if mismatch:
                self.logger.error(f"Digest mismatch detected after update for {service.name}, rolling back")
                if getattr(self, 'counter_failures', None):
                    self.counter_failures.inc()
                if self.update_compose_file(service, old_image) and self.restart_service(service):
                    if getattr(self, 'counter_rollbacks', None):
                        self.counter_rollbacks.inc()
                    self._notify_event('rollback', {
                        'service': service.name,
                        'compose_service': service.compose_service,
                        'compose_file': service.compose_file,
                        'old_image': old_image,
                        'failed_image': new_image,
                    })
                    return False
                else:
                    self.logger.error(f"Rollback failed for {service.name}")
                    return False
            # success
            if getattr(self, 'counter_updates', None):
                self.counter_updates.inc()
            self._notify_event('update', {
                'service': service.name,
                'compose_service': service.compose_service,
                'compose_file': service.compose_file,
                'old_image': old_image,
                'new_image': new_image,
            })
            return True
        finally:
            try:
                if lock_fd is not None:
                    lock_fd.close()
            except Exception:
                pass
    # Second definition kept historically; delegate to helper for clarity
    def update_compose_file(self, service: ServiceConfig, new_image: str) -> bool:  # type: ignore[no-redef]
        return cu_update_compose_file(service, new_image, self.logger, getattr(self, 'compose_timeout_sec', None))

    def save_state(self):
        result = su.save_state(
            self.services,
            self.state_file,
            self.state_lock_file,
            self.state_backup_dir,
            self.state_backup_count,
            self.logger,
        )
        if result is not None:
            self.state_file, self.state_lock_file = result

    def _prune_state_backups(self, state_dir: str):
        # kept for backwards compatibility; state pruning is handled within save_state
        pass
    
    def load_state(self):
        su.load_state(
            self.services,
            self.state_file,
            self.state_backup_dir,
            self.logger,
            getattr(self, 'counter_state_restored', None),
        )
    
    def cleanup_old_state(self):
        su.cleanup_old_state(self.state_file, self.logger)
    
    def run(self):
        """Main execution loop."""
        self.logger.info("Docker Auto-Updater starting...")
        # Global single-instance lock
        app_lock_paths = ['/var/run/docker-auto-updater/app.lock', '/tmp/docker-auto-updater-app.lock']
        self._app_lock_fd = None
        for path in app_lock_paths:
            try:
                os.makedirs(os.path.dirname(path), exist_ok=True)
                self._app_lock_fd = open(path, 'w')
                fcntl.flock(self._app_lock_fd.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                break
            except Exception:
                self._app_lock_fd = None
        if not self._app_lock_fd:
            self.logger.error("Another instance appears to be running; exiting")
            sys.exit(1)
        
        enabled_services = [s for s in self.services if s.enabled]
        disabled_services = [s for s in self.services if not s.enabled]
        
        self.logger.info(f"Total services configured: {len(self.services)}")
        self.logger.info(f"Enabled services: {len(enabled_services)}")
        if disabled_services:
            self.logger.info(f"Disabled services: {len(disabled_services)} ({', '.join(s.name for s in disabled_services)})")
        self.logger.info(f"Check interval: {self.check_interval} seconds")
        
        # Load previous state
        self.load_state()
        
        try:
            while True:
                # Respect pause and maintenance window
                if os.getenv('PAUSE_UPDATES', '0') in ('1', 'true', 'TRUE', 'yes', 'YES'):
                    self.logger.info("Updates paused via PAUSE_UPDATES; sleeping")
                    time.sleep(self.check_interval)
                    continue
                window = os.getenv('MAINTENANCE_WINDOW')  # e.g., "02:00-04:00,14:00-15:00"
                if window and not self._in_maintenance_window(window):
                    self.logger.debug("Outside maintenance window; skipping this cycle")
                    time.sleep(self.check_interval)
                    continue
                self.logger.info("Checking for updates...")
                
                for service in self.services:
                    if not service.enabled:
                        self.logger.debug(f"Service {service.name} is disabled, skipping")
                        continue
                        
                    try:
                        updated = self.check_for_updates(service)
                        if updated:
                            self.logger.info(f"Service {service.name} updated successfully")
                        else:
                            self.logger.debug(f"No updates for {service.name}")
                    except Exception as e:
                        self.logger.error(f"Error checking service {service.name}: {e}")
                
                self.logger.info(f"Check complete. Sleeping for {self.check_interval} seconds...")
                # Periodic cleanup
                self.cleanup_old_state()
                time.sleep(self.check_interval)
                
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal. Shutting down...")
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            raise

    def _in_maintenance_window(self, window_spec: str) -> bool:
        """Return True if current local time falls within any given window.

        window_spec: comma-separated list of HH:MM-HH:MM (24h) ranges.
        Crossing midnight supported (e.g., 23:00-01:00).
        """
        try:
            now = datetime.now().time()
            for token in [w.strip() for w in window_spec.split(',') if w.strip()]:
                try:
                    start_s, end_s = token.split('-')
                    sh, sm = map(int, start_s.split(':'))
                    eh, em = map(int, end_s.split(':'))
                    start = datetime.now().replace(hour=sh, minute=sm, second=0, microsecond=0).time()
                    end = datetime.now().replace(hour=eh, minute=em, second=0, microsecond=0).time()
                    if start <= end:
                        if start <= now <= end:
                            return True
                    else:
                        # window crosses midnight
                        if now >= start or now <= end:
                            return True
                except Exception:
                    continue
        except Exception:
            return True
        return False


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(description='Docker Auto-Updater')
    parser.add_argument('--config', dest='config', help='Path to updater_config.json')
    parser.add_argument('--once', action='store_true', help='Run a single update check and exit')
    parser.add_argument('--test', action='store_true', help='Test environment (Docker connectivity and registry auth) and exit')
    args = parser.parse_args()

    updater = DockerUpdater(config_file=args.config)

    if args.test:
        # Basic test: Docker ping and registry auth attempts
        ok = True
        try:
            updater.docker_client.ping()
            print('Docker connectivity: OK')
        except Exception as e:
            print(f'Docker connectivity: FAIL - {e}')
            ok = False
        for svc in updater.services:
            try:
                auth_ok = updater.authenticate_registry(svc)
                print(f'Registry auth for {svc.name}: {"OK" if auth_ok else "FAIL"}')
                ok = ok and auth_ok
            except Exception as e:
                print(f'Registry auth for {svc.name}: FAIL - {e}')
                ok = False
        sys.exit(0 if ok else 1)

    if args.once:
        for svc in updater.services:
            try:
                updater.check_for_updates(svc)
            except Exception as e:
                updater.logger.error(f"Error during single-run update for {svc.name}: {e}")
        sys.exit(0)

    updater.run()


if __name__ == "__main__":
    main()
