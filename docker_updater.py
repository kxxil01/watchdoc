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


class JSONFormatter(logging.Formatter):
    def format(self, record):
        payload = {
            'ts': datetime.utcnow().isoformat() + 'Z',
            'level': record.levelname,
            'msg': record.getMessage(),
            'logger': record.name,
        }
        if record.exc_info:
            payload['exc_info'] = self.formatException(record.exc_info)
        return json.dumps(payload)

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


@dataclass
class ServiceConfig:
    """Configuration for a monitored service."""
    name: str
    image: str
    compose_file: str
    compose_service: str
    registry_type: str = "docker_hub"  # docker_hub, ecr, gcr
    enabled: bool = True  # Enable/disable monitoring for this service
    registry_config: Optional[Dict] = None
    tag_pattern: Optional[str] = None  # Glob-like pattern, e.g., "staging-*"
    tag_regex: Optional[str] = None    # Python regex for tags, e.g., r"^staging-[a-f0-9]{7}$"
    semver_pattern: Optional[str] = None  # e.g., "v*", "release-*"
    current_digest: Optional[str] = None
    current_tag: Optional[str] = None
    last_updated: Optional[datetime] = None


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
        self.metrics_enabled = False
        self.counter_updates = None
        self.counter_rollbacks = None
        self.counter_failures = None
        self.counter_state_restored = None
        port = os.getenv('METRICS_PORT')
        if port and start_http_server and Counter:
            try:
                start_http_server(int(port), addr=os.getenv('METRICS_ADDR', '0.0.0.0'))
                self.counter_updates = Counter('updater_updates_total', 'Number of updates performed')
                self.counter_rollbacks = Counter('updater_rollbacks_total', 'Number of rollbacks performed')
                self.counter_failures = Counter('updater_failures_total', 'Number of update failures')
                self.counter_state_restored = Counter('updater_state_restored_total', 'State restored from backup')
                self.metrics_enabled = True
                self.logger.info(f"Prometheus metrics server on {os.getenv('METRICS_ADDR','0.0.0.0')}:{port}")
            except Exception as e:
                self.logger.warning(f"Failed to start metrics: {e}")
    
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
        """Recursively resolve environment variables in configuration values."""
        resolved = {}
        for key, value in config_dict.items():
            if isinstance(value, str):
                # Replace ${VAR_NAME} with environment variable value
                import re
                def replace_env_var(match):
                    var_name = match.group(1)
                    return os.getenv(var_name, match.group(0))  # Return original if not found
                
                resolved[key] = re.sub(r'\$\{([^}]+)\}', replace_env_var, value)
            elif isinstance(value, dict):
                resolved[key] = self.resolve_env_vars(value)
            elif isinstance(value, list):
                resolved[key] = [self.resolve_env_vars(item) if isinstance(item, dict) else item for item in value]
            else:
                resolved[key] = value
        return resolved

    def load_config(self):
        """Load configuration from JSON file."""
        if not os.path.exists(self.config_file):
            self.create_default_config()
        
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)

            self.check_interval = config.get('check_interval', 30)
            # Allow environment variable to override check interval
            try:
                env_ci = os.getenv('CHECK_INTERVAL')
                if env_ci is not None:
                    self.check_interval = int(env_ci)
            except Exception:
                pass

            # Validate configuration if jsonschema is available
            schema = {
                'type': 'object',
                'properties': {
                    'check_interval': {'type': 'integer', 'minimum': 1},
                    'services': {
                        'type': 'array',
                        'items': {
                            'type': 'object',
                            'required': ['name', 'image', 'compose_file', 'compose_service'],
                            'properties': {
                                'name': {'type': 'string'},
                                'image': {'type': 'string'},
                                'compose_file': {'type': 'string'},
                                'compose_service': {'type': 'string'},
                                'registry_type': {'type': 'string'},
                                'enabled': {'type': 'boolean'},
                                'tag_pattern': {'type': 'string'},
                                'tag_regex': {'type': 'string'},
                                'semver_pattern': {'type': 'string'},
                                'registry_config': {'type': 'object'},
                            }
                        }
                    }
                },
                'required': ['services']
            }
            if jsonschema_validate:
                try:
                    jsonschema_validate(config, schema)
                except ValidationError as e:
                    self.logger.error(f"Configuration validation error: {e.message}")
                    sys.exit(1)
            
            for service_config in config.get('services', []):
                # Resolve environment variables in registry_config
                registry_config = service_config.get('registry_config', {})
                resolved_registry_config = self.resolve_env_vars(registry_config)
                
                service = ServiceConfig(
                    name=service_config['name'],
                    image=service_config['image'],
                    compose_file=service_config['compose_file'],
                    compose_service=service_config['compose_service'],
                    registry_type=service_config.get('registry_type', 'docker_hub'),
                    registry_config=resolved_registry_config,
                    tag_pattern=service_config.get('tag_pattern'),
                    tag_regex=service_config.get('tag_regex'),
                    semver_pattern=service_config.get('semver_pattern')
                )
                self.services.append(service)
            
            self.logger.info(f"Loaded configuration for {len(self.services)} services")
            
        except (json.JSONDecodeError, KeyError) as e:
            self.logger.error(f"Invalid configuration file: {e}")
            sys.exit(1)
    
    def create_default_config(self):
        """Create a default configuration file."""
        default_config = {
            "check_interval": 30,
            "services": [
                {
                    "name": "example-web-app",
                    "image": "nginx:latest",
                    "compose_file": "./docker-compose.yml",
                    "compose_service": "web"
                }
            ]
        }

        # Ensure directory exists; handle permission issues by falling back locally
        try:
            config_dir = os.path.dirname(self.config_file) or '.'
            if config_dir and not os.path.exists(config_dir):
                os.makedirs(config_dir, exist_ok=True)
            with open(self.config_file, 'w') as f:
                json.dump(default_config, f, indent=2)
            self.logger.info(f"Created default configuration file: {self.config_file}")
        except Exception:
            local_path = './updater_config.json'
            with open(local_path, 'w') as f:
                json.dump(default_config, f, indent=2)
            self.config_file = local_path
            self.logger.info(f"Created local configuration file: {self.config_file}")
        self.logger.info("Please update the configuration with your services")

    def get_compose_command(self) -> List[str]:
        """Determine docker compose command (plugin or standalone)."""
        # Prefer Docker CLI plugin if available
        if shutil.which('docker') is not None:
            # We assume modern Docker supports 'compose'; fallback tested next
            return ['docker', 'compose']
        # Fallback to legacy docker-compose binary
        if shutil.which('docker-compose') is not None:
            return ['docker-compose']
        # Last resort: try docker-compose anyway
        return ['docker-compose']
    
    def authenticate_ecr(self, region: str, aws_access_key_id: str = None, aws_secret_access_key: str = None) -> bool:
        """Authenticate with AWS ECR."""
        try:
            now = datetime.utcnow()
            cache = self._ecr_auth_cache.get(region)
            if cache and cache.get('expires') and now < cache['expires'] - timedelta(minutes=5):
                # Token valid; re-login only if it's been a while
                username = cache['username']
                password = cache['password']
                endpoint = cache['endpoint']
                last_login = cache.get('last_login')
                if not last_login or (now - last_login) > timedelta(hours=1):
                    login_result = subprocess.run([
                        'docker', 'login', '--username', username, '--password-stdin', endpoint
                    ], input=password, text=True, capture_output=True, timeout=self.compose_timeout_sec)
                    if login_result.returncode != 0:
                        self.logger.warning(f"ECR re-login failed (cached token): {login_result.stderr}")
                        cache = None  # force refresh
                    else:
                        cache['last_login'] = now
                        self.logger.info(f"ECR re-login succeeded for {region}")
                        return True
                else:
                    return True

            # Need new token
            if aws_access_key_id and aws_secret_access_key:
                ecr_client = boto3.client(
                    'ecr',
                    region_name=region,
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key
                )
            else:
                ecr_client = boto3.client('ecr', region_name=region)
            response = self._retry(ecr_client.get_authorization_token)
            auth = response['authorizationData'][0]
            token = auth['authorizationToken']
            endpoint = auth['proxyEndpoint']
            expires = auth.get('expiresAt') or (datetime.utcnow() + timedelta(hours=12))
            username, password = base64.b64decode(token).decode().split(':')
            login_result = subprocess.run([
                'docker', 'login', '--username', username, '--password-stdin', endpoint
            ], input=password, text=True, capture_output=True, timeout=self.compose_timeout_sec)
            if login_result.returncode == 0:
                self._ecr_auth_cache[region] = {
                    'username': username,
                    'password': password,
                    'endpoint': endpoint,
                    'expires': expires,
                    'last_login': now,
                }
                self.logger.info(f"ECR login succeeded for region {region}")
                return True
            else:
                self.logger.error(f"ECR authentication failed: {login_result.stderr}")
                return False
        except Exception as e:
            self.logger.error(f"ECR authentication error: {e}")
            return False
    
    def authenticate_gcr(self, project_id: str = None, service_account_path: str = None) -> bool:
        """Authenticate with Google Container Registry."""
        try:
            # Set up authentication
            if service_account_path:
                os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = service_account_path
            
            # Get default credentials
            credentials, project = default()
            if project_id:
                project = project_id
            
            # Refresh credentials
            auth_req = Request()
            credentials.refresh(auth_req)
            
            # Get access token
            access_token = credentials.token
            
            # Login to Docker registry for GCR
            registries = [
                'gcr.io',
                'us.gcr.io',
                'eu.gcr.io',
                'asia.gcr.io'
            ]
            
            for registry in registries:
                login_result = subprocess.run([
                    'docker', 'login', '-u', '_token', '--password-stdin', registry
                ], input=access_token, text=True, capture_output=True)
                
                if login_result.returncode != 0:
                    self.logger.warning(f"Failed to login to {registry}: {login_result.stderr}")
            
            self.logger.info("Successfully authenticated with Google Container Registry")
            return True
            
        except Exception as e:
            self.logger.error(f"GCR authentication error: {e}")
            return False
    
    def authenticate_registry(self, service: ServiceConfig) -> bool:
        """Authenticate with the appropriate registry for a service."""
        if service.registry_type == "ecr":
            region = service.registry_config.get('region', 'us-east-1')
            aws_access_key_id = service.registry_config.get('aws_access_key_id')
            aws_secret_access_key = service.registry_config.get('aws_secret_access_key')
            return self.authenticate_ecr(region, aws_access_key_id, aws_secret_access_key)
        
        elif service.registry_type == "gcr":
            project_id = service.registry_config.get('project_id')
            service_account_path = service.registry_config.get('service_account_path')
            return self.authenticate_gcr(project_id, service_account_path)
        
        elif service.registry_type == "docker_hub":
            # Docker Hub authentication (if credentials provided)
            username = service.registry_config.get('username')
            password = service.registry_config.get('password')
            if username and password:
                login_result = subprocess.run([
                    'docker', 'login', '--username', username, '--password-stdin'
                ], input=password, text=True, capture_output=True)
                
                if login_result.returncode == 0:
                    self.logger.info("Successfully authenticated with Docker Hub")
                    return True
                else:
                    self.logger.error(f"Docker Hub authentication failed: {login_result.stderr}")
                    return False
            return True  # No authentication needed for public images
        
        return True
    
    def parse_semver(self, version: str) -> Tuple[int, int, int, Optional[List[Any]]]:
        """Parse a semantic version string into components.

        Returns a tuple: (major, minor, patch, prerelease_identifiers or None)
        prerelease_identifiers is a list of ints/strings following SemVer 2.0 rules.
        """
        # Remove common prefixes (multi-char prefixes first)
        for prefix in ('release-', 'version-'):
            if version.startswith(prefix):
                version = version[len(prefix):]
        if version.startswith(('v', 'V')):
            version = version[1:]

        semver_pattern = r'^(0|[1-9]\d*)\.(0|[1-9]\d*)\.(0|[1-9]\d*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?$'
        m = re.match(semver_pattern, version)
        if not m:
            # Fallback: best effort
            parts = re.split(r'\.|-', version)
            try:
                major = int(parts[0]) if len(parts) > 0 else 0
                minor = int(parts[1]) if len(parts) > 1 else 0
                patch = int(parts[2]) if len(parts) > 2 else 0
            except ValueError:
                return (0, 0, 0, None)
            return (major, minor, patch, None)

        major, minor, patch, prerelease, _build = m.groups()
        pre_list: Optional[List[Any]] = None
        if prerelease:
            pre_list = []
            for ident in prerelease.split('.'):
                if ident.isdigit():
                    # Numeric identifiers MUST NOT include leading zeroes
                    if len(ident) > 1 and ident[0] == '0':
                        # treat as string to avoid numeric precedence with leading zero
                        pre_list.append(ident)
                    else:
                        pre_list.append(int(ident))
                else:
                    pre_list.append(ident)
        return (int(major), int(minor), int(patch), pre_list)

    def compare_semver(self, version1: str, version2: str) -> int:
        """Compare two semantic versions per SemVer 2.0.0.

        Returns 1 if v1 > v2, -1 if v1 < v2, 0 if equal.
        """
        m1 = self.parse_semver(version1)
        m2 = self.parse_semver(version2)

        for a, b in zip(m1[:3], m2[:3]):
            if a != b:
                return 1 if a > b else -1

        pre1, pre2 = m1[3], m2[3]
        if pre1 is None and pre2 is None:
            return 0
        if pre1 is None:
            return 1  # stable > prerelease
        if pre2 is None:
            return -1  # prerelease < stable

        # Compare prerelease identifiers
        for i in range(min(len(pre1), len(pre2))):
            a, b = pre1[i], pre2[i]
            if a == b:
                continue
            # Numeric identifiers have lower precedence than non-numeric
            a_is_int = isinstance(a, int)
            b_is_int = isinstance(b, int)
            if a_is_int and b_is_int:
                return 1 if a > b else -1
            if a_is_int and not b_is_int:
                return -1
            if not a_is_int and b_is_int:
                return 1
            # Both strings
            return 1 if str(a) > str(b) else -1

        # If all shared identifiers equal, longer prerelease list has higher precedence
        if len(pre1) == len(pre2):
            return 0
        return 1 if len(pre1) > len(pre2) else -1
    
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
        try:
            # Pull the latest image to get current digest
            self.logger.debug(f"Checking digest for image: {image_name}")
            
            # Use docker inspect to get the current digest
            result = subprocess.run(
                ['docker', 'inspect', '--format={{.RepoDigests}}', image_name],
                capture_output=True,
                text=True,
                check=True,
                timeout=self.compose_timeout_sec
            )
            
            # Parse the digest from the output
            digests = result.stdout.strip()
            if digests and digests != '[]':
                # Extract digest from format like [registry/image@sha256:...]
                digest_start = digests.find('sha256:')
                if digest_start != -1:
                    digest_end = digests.find(']', digest_start)
                    if digest_end == -1:
                        digest_end = len(digests)
                    return digests[digest_start:digest_end]
            
            return None
            
        except subprocess.CalledProcessError as e:
            self.logger.error(f"Failed to get digest for {image_name}: {e}")
            return None
    
    def pull_image(self, image_name: str) -> bool:
        """Pull the latest version of an image."""
        for attempt in range(1, 4):
            try:
                self.logger.info(f"Pulling image: {image_name}")
                self.docker_client.images.pull(image_name)
                return True
            except APIError as e:
                if attempt == 3:
                    self.logger.error(f"Failed to pull image {image_name}: {e}")
                    return False
                sleep = 1.0 * (2 ** (attempt - 1))
                self.logger.warning(f"Pull failed for {image_name}: {e}. Retrying in {sleep:.1f}s")
                time.sleep(sleep)
    
    def _run_compose(self, args: List[str], cwd: str, timeout: Optional[int] = None) -> None:
        """Run compose command with fallback to sudo (non-interactive)."""
        try:
            subprocess.run(args, cwd=cwd, capture_output=True, text=True, check=True, timeout=timeout or self.compose_timeout_sec)
            return
        except subprocess.CalledProcessError as e:
            try:
                self.logger.info("Retrying compose command with sudo")
                subprocess.run(['sudo', '-n', *args], cwd=cwd, capture_output=True, text=True, check=True, timeout=timeout or self.compose_timeout_sec)
                return
            except subprocess.CalledProcessError as e2:
                raise RuntimeError(f"Compose command failed: {e2.stderr or e.stderr}")

    def restart_service(self, service: ServiceConfig) -> bool:
        """Restart a service using docker-compose."""
        try:
            compose_dir = os.path.dirname(os.path.abspath(service.compose_file))
            compose_file = os.path.basename(service.compose_file)
            cmd = self.get_compose_command()

            # Determine compose file owner for context/logging
            try:
                st = os.stat(service.compose_file)
                owner = pwd.getpwuid(st.st_uid).pw_name
                group = grp.getgrgid(st.st_gid).gr_name
                self.logger.info(f"Restarting service: {service.name} as current user; compose owned by {owner}:{group}")
            except Exception:
                self.logger.info(f"Restarting service: {service.name}")
            
            # Ensure image is pulled with compose (pull-then-up)
            self._run_compose([*cmd, '-f', compose_file, 'pull', service.compose_service], compose_dir)
            # Stop the service (with fallback)
            self._run_compose([*cmd, '-f', compose_file, 'stop', service.compose_service], compose_dir)
            # Start the service (with fallback)
            self._run_compose([*cmd, '-f', compose_file, 'up', '-d', service.compose_service], compose_dir)
            
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
        """Update the docker-compose file with new image tag using YAML mutation.

        Falls back to sudo copy if direct write is not permitted.
        """
        compose_path = service.compose_file
        try:
            with open(compose_path, 'r') as f:
                data = safe_load(f)
        except Exception as e:
            self.logger.error(f"Failed to read compose file {compose_path}: {e}")
            return False

    def _find_service_containers(self, service: ServiceConfig) -> List[Any]:
        try:
            project = os.path.basename(os.path.dirname(os.path.abspath(service.compose_file))).replace(' ', '').lower()
            containers = self.docker_client.containers.list(all=True)
            matched = []
            for c in containers:
                labels = getattr(c, 'labels', None) or getattr(c, 'attrs', {}).get('Config', {}).get('Labels', {}) or {}
                svc = labels.get('com.docker.compose.service')
                proj = labels.get('com.docker.compose.project')
                if svc == service.compose_service and (not proj or proj == project):
                    matched.append(c)
            return matched
        except Exception as e:
            self.logger.warning(f"Error finding containers for {service.name}: {e}")
            return []

    def wait_for_health(self, service: ServiceConfig, timeout: Optional[int] = None, stable_seconds: Optional[int] = None) -> bool:
        deadline = time.time() + (timeout or self.health_timeout)
        last_healthy = None
        while time.time() < deadline:
            containers = self._find_service_containers(service)
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
                if time.time() - last_healthy >= (stable_seconds or self.health_stable_seconds):
                    return True
            else:
                last_healthy = None
            time.sleep(2)
        return False

    def _notify_event(self, event_type: str, payload: Dict[str, Any]):
        url = os.getenv('WEBHOOK_URL')
        if not url:
            return
        try:
            import requests  # lazy import
            headers = {'Content-Type': 'application/json'}
            data = json.dumps({'event': event_type, **payload})
            requests.post(url, headers=headers, data=data, timeout=5)
        except Exception as e:
            self.logger.warning(f"Webhook notify failed: {e}")

    def perform_update_with_rollback(self, service: ServiceConfig, old_image: str, new_image: str, new_digest: str) -> bool:
        lock_path = service.compose_file + '.lock'
        with open(lock_path, 'w') as lock_fd:
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

        try:
            services = data.get('services', {})
            if service.compose_service not in services:
                self.logger.error(f"Service '{service.compose_service}' not found in {compose_path}")
                return False
            svc = services[service.compose_service]
            old_image = svc.get('image')
            if old_image == new_image:
                self.logger.debug("Image already up to date; no changes to compose file")
                return False
            svc['image'] = new_image
        except Exception as e:
            self.logger.error(f"Failed to update YAML structure: {e}")
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
            self.logger.error(f"Failed to write temporary compose file: {e}")
            return False

        try:
            # Try to replace atomically
            os.replace(tmp_path, compose_path)
            self.logger.info(f"Updated {compose_path} with new image: {new_image}")
            return True
        except PermissionError:
            self.logger.info(f"Permission denied replacing {compose_path}, attempting sudo copy")
            try:
                subprocess.run(['sudo', '/bin/cp', tmp_path, compose_path], check=True, capture_output=True, text=True, timeout=self.compose_timeout_sec)
                self.logger.info(f"Updated {compose_path} via sudo with new image: {new_image}")
                # Restore ownership if known
                if orig_uid is not None and orig_gid is not None:
                    try:
                        subprocess.run(['sudo', '/bin/chown', f'{orig_uid}:{orig_gid}', compose_path], check=True, capture_output=True, text=True, timeout=self.compose_timeout_sec)
                    except subprocess.CalledProcessError as e:
                        self.logger.warning(f"Failed to restore compose file ownership: {e.stderr}")
                return True
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to copy compose file via sudo: {e.stderr}")
                return False
            finally:
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
        except Exception as e:
            self.logger.error(f"Failed to update compose file {compose_path}: {e}")
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            return False

        try:
            services = data.get('services', {})
            if service.compose_service not in services:
                self.logger.error(f"Service '{service.compose_service}' not found in {compose_path}")
                return False
            svc = services[service.compose_service]
            old_image = svc.get('image')
            if old_image == new_image:
                self.logger.debug("Image already up to date; no changes to compose file")
                return False
            svc['image'] = new_image
        except Exception as e:
            self.logger.error(f"Failed to update YAML structure: {e}")
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
            self.logger.error(f"Failed to write temporary compose file: {e}")
            return False

        try:
            # Try to replace atomically
            os.replace(tmp_path, compose_path)
            self.logger.info(f"Updated {compose_path} with new image: {new_image}")
            return True
        except PermissionError:
            self.logger.info(f"Permission denied replacing {compose_path}, attempting sudo copy")
            try:
                subprocess.run(['sudo', '/bin/cp', tmp_path, compose_path], check=True, capture_output=True, text=True)
                self.logger.info(f"Updated {compose_path} via sudo with new image: {new_image}")
                # Restore ownership if known
                if orig_uid is not None and orig_gid is not None:
                    try:
                        subprocess.run(['sudo', '/bin/chown', f'{orig_uid}:{orig_gid}', compose_path], check=True, capture_output=True, text=True)
                    except subprocess.CalledProcessError as e:
                        self.logger.warning(f"Failed to restore compose file ownership: {e.stderr}")
                return True
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to copy compose file via sudo: {e.stderr}")
                return False
            finally:
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
        except Exception as e:
            self.logger.error(f"Failed to update compose file {compose_path}: {e}")
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            return False

    # Override with a clean implementation to avoid earlier patching artifacts
    def update_compose_file(self, service: ServiceConfig, new_image: str) -> bool:
        compose_path = service.compose_file
        try:
            with open(compose_path, 'r') as f:
                data = safe_load(f)
        except Exception as e:
            self.logger.error(f"Failed to read compose file {compose_path}: {e}")
            return False
        try:
            services = data.get('services', {})
            if service.compose_service not in services:
                self.logger.error(f"Service '{service.compose_service}' not found in {compose_path}")
                return False
            svc = services[service.compose_service]
            old_image = svc.get('image')
            if old_image == new_image:
                self.logger.debug("Image already up to date; no changes to compose file")
                return False
            svc['image'] = new_image
        except Exception as e:
            self.logger.error(f"Failed to update YAML structure: {e}")
            return False
        try:
            st = os.stat(compose_path)
            orig_uid, orig_gid = st.st_uid, st.st_gid
            orig_mode = st.st_mode & 0o777
        except Exception:
            orig_uid = orig_gid = None
            orig_mode = None
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
            self.logger.error(f"Failed to write temporary compose file: {e}")
            return False
        try:
            os.replace(tmp_path, compose_path)
            self.logger.info(f"Updated {compose_path} with new image: {new_image}")
            return True
        except PermissionError:
            self.logger.info(f"Permission denied replacing {compose_path}, attempting sudo copy")
            try:
                subprocess.run(['sudo', '/bin/cp', tmp_path, compose_path], check=True, capture_output=True, text=True)
                self.logger.info(f"Updated {compose_path} via sudo with new image: {new_image}")
                if orig_uid is not None and orig_gid is not None:
                    try:
                        subprocess.run(['sudo', '/bin/chown', f'{orig_uid}:{orig_gid}', compose_path], check=True, capture_output=True, text=True)
                    except subprocess.CalledProcessError as e:
                        self.logger.warning(f"Failed to restore compose file ownership: {e.stderr}")
                return True
            except subprocess.CalledProcessError as e:
                self.logger.error(f"Failed to copy compose file via sudo: {e.stderr}")
                return False
            finally:
                try:
                    os.remove(tmp_path)
                except Exception:
                    pass
        except Exception as e:
            self.logger.error(f"Failed to update compose file {compose_path}: {e}")
            try:
                os.remove(tmp_path)
            except Exception:
                pass
            return False

    def save_state(self):
        """Save current state to a file for persistence."""
        state = {
            'services': []
        }
        
        for service in self.services:
            service_state = {
                'name': service.name,
                'image': service.image,
                'current_digest': service.current_digest,
                'current_tag': service.current_tag,
                'last_updated': service.last_updated.isoformat() if service.last_updated else None
            }
            state['services'].append(service_state)
        # Ensure state directory exists, handle permissions, atomic write with backup
        try:
            state_dir = os.path.dirname(self.state_file) or '.'
            if state_dir and not os.path.exists(state_dir):
                os.makedirs(state_dir, exist_ok=True)

            # Acquire exclusive lock to avoid concurrent writers
            with open(self.state_lock_file, 'w') as lock_fd:
                try:
                    fcntl.flock(lock_fd.fileno(), fcntl.LOCK_EX)
                except Exception:
                    pass

                data = json.dumps(state, indent=2)
                tmp_path = os.path.join(state_dir, f'.tmp_state_{int(time.time()*1000)}.json')
                # Write tmp then replace atomically
                with open(tmp_path, 'w') as tf:
                    tf.write(data)
                    tf.flush()
                    os.fsync(tf.fileno())
                os.replace(tmp_path, self.state_file)
                # fsync directory to persist rename
                try:
                    dir_fd = os.open(state_dir, os.O_DIRECTORY)
                    try:
                        os.fsync(dir_fd)
                    finally:
                        os.close(dir_fd)
                except Exception:
                    pass

                # Write timestamped backup and prune old ones
                ts = datetime.now().strftime('%Y%m%d%H%M%S')
                backup_root = self.state_backup_dir or state_dir
                try:
                    os.makedirs(backup_root, exist_ok=True)
                except Exception:
                    backup_root = state_dir
                backup_path = os.path.join(backup_root, f'updater_state-{ts}.json')
                try:
                    with open(backup_path, 'w') as bf:
                        bf.write(data)
                    self._prune_state_backups(backup_root)
                except Exception as e:
                    self.logger.debug(f"Unable to write state backup: {e}")
        except Exception as e:
            # Fallback to local file
            fallback = './updater_state.json'
            try:
                with open(fallback, 'w') as f:
                    json.dump(state, f, indent=2)
                self.state_file = fallback
                self.state_lock_file = fallback + '.lock'
                self.logger.warning(f"Could not write state to system path; wrote to {fallback}: {e}")
            except Exception as e2:
                self.logger.error(f"Failed to write state to fallback path {fallback}: {e2}")

    def _prune_state_backups(self, state_dir: str):
        try:
            backups = [
                os.path.join(state_dir, f) for f in os.listdir(state_dir)
                if f.startswith('updater_state-') and f.endswith('.json')
            ]
            backups.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            for p in backups[self.state_backup_count:]:
                try:
                    os.remove(p)
                except Exception:
                    pass
        except Exception:
            pass
    
    def load_state(self):
        """Load previous state from file."""
        def _load_from_path(path: str) -> bool:
            try:
                with open(path, 'r') as f:
                    state = json.load(f)
                for service_data in state.get('services', []):
                    for service in self.services:
                        if service.name == service_data['name']:
                            service.current_digest = service_data.get('current_digest')
                            service.current_tag = service_data.get('current_tag')
                            if service_data.get('last_updated'):
                                service.last_updated = datetime.fromisoformat(service_data['last_updated'])
                            break
                return True
            except Exception as e:
                self.logger.warning(f"Failed loading state from {path}: {e}")
                return False

        if os.path.exists(self.state_file) and _load_from_path(self.state_file):
            return
        # Try latest backup
        state_dir = self.state_backup_dir or (os.path.dirname(self.state_file) or '.')
        try:
            backups = [
                os.path.join(state_dir, f) for f in os.listdir(state_dir)
                if f.startswith('updater_state-') and f.endswith('.json')
            ]
            backups.sort(key=lambda p: os.path.getmtime(p), reverse=True)
            for bp in backups:
                if _load_from_path(bp):
                    self.logger.info(f"Loaded state from backup: {bp}")
                    if getattr(self, 'counter_state_restored', None):
                        self.counter_state_restored.inc()
                    return
        except Exception:
            pass
    
    def cleanup_old_state(self):
        """Clean up old state files and temporary files."""
        try:
            # Remove old state files older than 30 days
            state_file = self.state_file
            if os.path.exists(state_file):
                file_age = time.time() - os.path.getmtime(state_file)
                if file_age > 30 * 24 * 3600:  # 30 days
                    os.remove(state_file)
                    self.logger.info("Removed old state file")
            
            # Clean up temporary docker-compose files
            temp_dir = '/tmp'
            for filename in os.listdir(temp_dir):
                if filename.startswith('docker-compose-') and filename.endswith('.yml'):
                    filepath = os.path.join(temp_dir, filename)
                    try:
                        file_age = time.time() - os.path.getmtime(filepath)
                        if file_age > 3600:  # 1 hour
                            os.remove(filepath)
                            self.logger.debug(f"Removed old temp file: {filename}")
                    except OSError:
                        pass
                        
        except Exception as e:
            self.logger.warning(f"Error during cleanup: {e}")
    
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
