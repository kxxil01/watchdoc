#!/usr/bin/env python3
"""
Watchdoc
A production-ready agent that monitors Docker images and automatically updates containers
when new images that match your update rules are available.
"""

import os
import sys
import json
import time
import logging
import subprocess
import base64
import re
from datetime import datetime, timezone
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any, Tuple
import docker
from docker.errors import DockerException
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from google.cloud import storage as gcs
from google.auth.exceptions import DefaultCredentialsError
from google.auth import default
from google.auth.transport.requests import Request
import requests
import shutil
from docker.types import EndpointConfig

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    # Load from the config directory
    env_file = '/etc/watchdoc/.env'
    if os.path.exists(env_file):
        # Check if we can read the file
        try:
            with open(env_file, 'r') as f:
                content = f.read()
            load_dotenv(env_file)
            print(f"Loaded environment variables from {env_file}")
            # Debug: Show what AWS credentials we loaded
            aws_key = os.getenv('AWS_ACCESS_KEY_ID', 'NOT_SET')
            print(f"AWS_ACCESS_KEY_ID: {aws_key[:10]}..." if aws_key != 'NOT_SET' else "AWS_ACCESS_KEY_ID: NOT_SET")
        except PermissionError:
            print(f"Permission denied reading {env_file}")
        except Exception as e:
            print(f"Error loading {env_file}: {e}")
    else:
        print(f"Warning: {env_file} not found, using system environment variables")
except ImportError:
    print("python-dotenv not installed, using system environment variables only")


@dataclass
class ServiceConfig:
    """Configuration for a monitored service."""
    name: str
    image: str
    container_id: Optional[str] = None  # For label-based discovery
    registry_type: str = "docker_hub"  # docker_hub, ecr, gcr
    registry_config: Optional[Dict] = None
    tag_pattern: Optional[str] = None  # e.g., "staging-*", "prod-*"
    semver_pattern: Optional[str] = None  # e.g., "v*", "release-*"
    current_digest: Optional[str] = None
    current_tag: Optional[str] = None
    last_updated: Optional[datetime] = None
    auto_discovered: bool = False  # True if discovered via labels
    detected_strategy: Optional[str] = None  # Tracks automatic tag detection mode
    compose_project: Optional[str] = None
    compose_service: Optional[str] = None
    compose_workdir: Optional[str] = None
    compose_files: List[str] = field(default_factory=list)


class Watchdoc:
    """Main Watchdoc agent."""
    
    def __init__(self, config_file: str = None):
        # Use environment variable or default to proper config directory
        if config_file is None:
            config_file = os.getenv('CONFIG_FILE', '/etc/watchdoc/watchdoc_config.json')
        self.config_file = config_file
        
        # Set state file path from environment or default
        self.state_file = os.getenv('STATE_FILE', '/var/lib/watchdoc/watchdoc_state.json')
        
        # Enable/disable auto-discovery via labels
        self.auto_discovery = os.getenv('AUTO_DISCOVERY', 'true').lower() == 'true'
        
        self.docker_client = None
        self.services: List[ServiceConfig] = []
        self.service_state_cache: Dict[str, Any] = {}
        self.check_interval = 30  # seconds
        self.setup_logging()
        
        if not self.auto_discovery:
            logging.getLogger(__name__).warning(
                "AUTO_DISCOVERY is disabled. Watchdoc will not manage any containers unless discovery is enabled."
            )
        self.init_docker_client()
        self.load_config()
        if self.auto_discovery:
            self.discover_containers()
    
    def setup_logging(self):
        """Configure logging with proper formatting."""
        # Use environment variable for log level, default to INFO
        log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
        
        # Use proper log directory that's writable
        log_dir = '/var/log/watchdoc'
        log_file = os.path.join(log_dir, 'watchdoc.log')
        
        # Ensure log directory exists and is writable
        os.makedirs(log_dir, exist_ok=True)
        
        logging.basicConfig(
            level=getattr(logging, log_level, logging.INFO),
            format='%(asctime)s - %(levelname)s - %(message)s',
            handlers=[
                logging.FileHandler(log_file),
                logging.StreamHandler(sys.stdout)
            ]
        )
        self.logger = logging.getLogger(__name__)
    
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
            self.logger.info(f"Configuration loaded. Check interval set to {self.check_interval} seconds.")
            
        except (json.JSONDecodeError, KeyError) as e:
            self.logger.error(f"Invalid configuration file: {e}")
            sys.exit(1)
    
    def create_default_config(self):
        """Create a default configuration file."""
        default_config = {
            "check_interval": 30
        }
        
        with open(self.config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        
        self.logger.info(f"Created default configuration file: {self.config_file}")
        self.logger.info("Adjust 'check_interval' if you need a different polling cadence")
    
    def authenticate_ecr(self, region: str, aws_access_key_id: str = None, aws_secret_access_key: str = None) -> bool:
        """Authenticate with AWS ECR."""
        try:
            # Debug: Log what credentials we're using
            if aws_access_key_id and aws_secret_access_key:
                self.logger.info(f"Using provided ECR credentials for region {region}: {aws_access_key_id[:10]}...")
                ecr_client = boto3.client(
                    'ecr',
                    region_name=region,
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key
                )
            else:
                self.logger.info(f"Using default AWS credentials for ECR in region {region}")
                ecr_client = boto3.client('ecr', region_name=region)
            
            # Get authorization token
            response = ecr_client.get_authorization_token()
            token = response['authorizationData'][0]['authorizationToken']
            endpoint = response['authorizationData'][0]['proxyEndpoint']
            
            # Decode the token
            username, password = base64.b64decode(token).decode().split(':')
            
            # Login to Docker registry
            login_result = subprocess.run([
                'docker', 'login', '--username', username, '--password-stdin', endpoint
            ], input=password, text=True, capture_output=True)
            
            if login_result.returncode == 0:
                self.logger.info(f"Successfully authenticated with ECR in region {region}")
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
        registry_config = service.registry_config or {}
        
        if service.registry_type == "ecr":
            region = registry_config.get('region', 'us-east-1')
            aws_access_key_id = registry_config.get('aws_access_key_id')
            aws_secret_access_key = registry_config.get('aws_secret_access_key')
            return self.authenticate_ecr(region, aws_access_key_id, aws_secret_access_key)
        
        elif service.registry_type == "gcr":
            project_id = registry_config.get('project_id')
            service_account_path = registry_config.get('service_account_path')
            return self.authenticate_gcr(project_id, service_account_path)
        
        elif service.registry_type == "docker_hub":
            # Docker Hub authentication (if credentials provided)
            username = registry_config.get('username')
            password = registry_config.get('password')
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
    
    def parse_semver(self, version: str) -> Tuple[int, int, int, str]:
        """Parse a semantic version string into components."""
        # Remove common prefixes such as v, release-, version-
        version = re.sub(r'^(?:v|release-|version-)', '', version)
        
        # Match semver pattern: major.minor.patch[-prerelease][+build]
        semver_pattern = r'^(\d+)\.(\d+)\.(\d+)(?:-([a-zA-Z0-9\-\.]+))?(?:\+([a-zA-Z0-9\-\.]+))?$'
        match = re.match(semver_pattern, version)
        
        if match:
            major, minor, patch, prerelease = match.groups()[:4]
            return (int(major), int(minor), int(patch), prerelease or "")
        
        # Fallback for non-standard versions
        parts = version.split('.')
        try:
            major = int(parts[0]) if len(parts) > 0 else 0
            minor = int(parts[1]) if len(parts) > 1 else 0
            patch = int(parts[2]) if len(parts) > 2 else 0
            return (major, minor, patch, "")
        except ValueError:
            return (0, 0, 0, version)
    
    def compare_semver(self, version1: str, version2: str) -> int:
        """Compare two semantic versions. Returns 1 if v1 > v2, -1 if v1 < v2, 0 if equal."""
        v1_parts = self.parse_semver(version1)
        v2_parts = self.parse_semver(version2)
        
        # Compare major, minor, patch
        for i in range(3):
            if v1_parts[i] > v2_parts[i]:
                return 1
            elif v1_parts[i] < v2_parts[i]:
                return -1
        
        # Compare prerelease (empty string means stable release)
        v1_pre, v2_pre = v1_parts[3], v2_parts[3]
        
        if not v1_pre and not v2_pre:
            return 0  # Both stable
        elif not v1_pre and v2_pre:
            return 1  # v1 is stable, v2 is prerelease
        elif v1_pre and not v2_pre:
            return -1  # v1 is prerelease, v2 is stable
        else:
            # Both are prerelease, compare lexicographically
            if v1_pre > v2_pre:
                return 1
            elif v1_pre < v2_pre:
                return -1
            else:
                return 0
    
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
            
            # List images in repository
            response = ecr_client.describe_images(
                repositoryName=repository_name,
                maxResults=100
            )
            
            # Filter tags matching semver pattern
            semver_tags = []
            pattern_prefix = service.semver_pattern.replace('*', '')
            
            for image_detail in response['imageDetails']:
                if 'imageTags' in image_detail:
                    for tag in image_detail['imageTags']:
                        if tag.startswith(pattern_prefix):
                            # Extract version part
                            version = tag[len(pattern_prefix):] if pattern_prefix else tag
                            
                            # Validate it's a semver
                            try:
                                self.parse_semver(version)
                                semver_tags.append({
                                    'tag': tag,
                                    'version': version,
                                    'pushed_at': image_detail['imagePushedAt']
                                })
                            except:
                                continue
            
            if not semver_tags:
                return None
            
            # Sort by semantic version (newest first)
            semver_tags.sort(key=lambda x: (
                self.parse_semver(x['version'])[0],  # major
                self.parse_semver(x['version'])[1],  # minor
                self.parse_semver(x['version'])[2],  # patch
                x['version'] if not self.parse_semver(x['version'])[3] else f"~{self.parse_semver(x['version'])[3]}"  # prerelease
            ), reverse=True)
            
            latest_tag = semver_tags[0]['tag']
            self.logger.info(f"Found latest semver tag for pattern '{service.semver_pattern}': {latest_tag}")
            return latest_tag
            
        except Exception as e:
            self.logger.error(f"Error getting latest semver tag: {e}")
            return None
    
    def get_latest_tag_for_pattern(self, service: ServiceConfig) -> Optional[str]:
        """Get the latest tag matching the pattern for ECR repositories."""
        if service.registry_type != "ecr" or not service.tag_pattern:
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
            
            # List images in repository
            response = ecr_client.describe_images(
                repositoryName=repository_name,
                maxResults=100
            )
            
            # Filter tags matching pattern and sort by push date
            matching_images = []
            pattern_prefix = service.tag_pattern.replace('*', '')
            
            for image_detail in response['imageDetails']:
                if 'imageTags' in image_detail:
                    for tag in image_detail['imageTags']:
                        if tag.startswith(pattern_prefix):
                            matching_images.append({
                                'tag': tag,
                                'pushed_at': image_detail['imagePushedAt']
                            })
            
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

    def fetch_available_tags(self, service: ServiceConfig) -> List[Dict[str, Any]]:
        """Fetch available tags for a service across supported registries."""
        try:
            if service.registry_type == 'ecr':
                return self._fetch_ecr_tags(service)
            if service.registry_type == 'docker_hub':
                return self._fetch_docker_hub_tags(service)
            if service.registry_type == 'gcr':
                return self._fetch_gcr_tags(service)
        except Exception as exc:
            self.logger.error(f"Failed to fetch tags for {service.name}: {exc}")
        return []

    def _fetch_ecr_tags(self, service: ServiceConfig) -> List[Dict[str, Any]]:
        """Fetch tags and metadata from AWS ECR."""
        image_parts = service.image.split('/')
        if len(image_parts) < 2:
            return []
        registry_url = image_parts[0]
        repository_name = image_parts[1].split(':')[0]
        region = registry_url.split('.')[3]

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

        tags: List[Dict[str, Any]] = []
        params: Dict[str, Any] = {
            'repositoryName': repository_name,
            'maxResults': 100
        }

        while True:
            response = ecr_client.describe_images(**params)
            for image_detail in response.get('imageDetails', []):
                pushed_at = image_detail.get('imagePushedAt')
                for tag in image_detail.get('imageTags', []):
                    tags.append({'tag': tag, 'pushed_at': pushed_at})
            next_token = response.get('nextToken')
            if not next_token:
                break
            params['nextToken'] = next_token
        return tags

    def _docker_hub_login_token(self, username: Optional[str], password: Optional[str]) -> Optional[str]:
        if not username or not password:
            return None
        try:
            resp = requests.post(
                'https://hub.docker.com/v2/users/login/',
                json={'username': username, 'password': password},
                timeout=10
            )
            if resp.status_code == 200:
                return resp.json().get('token')
            self.logger.warning(f"Docker Hub login failed: {resp.status_code} {resp.text}")
        except Exception as exc:
            self.logger.warning(f"Docker Hub login error: {exc}")
        return None

    def _fetch_docker_hub_tags(self, service: ServiceConfig) -> List[Dict[str, Any]]:
        """Fetch tags from Docker Hub registry."""
        image_path = service.image.split(':')[0]
        namespace, repo = ('library', image_path)
        if '/' in image_path:
            namespace, repo = image_path.split('/', 1)

        token = self._docker_hub_login_token(
            (service.registry_config or {}).get('username'),
            (service.registry_config or {}).get('password')
        )

        headers = {'Accept': 'application/json'}
        if token:
            headers['Authorization'] = f'JWT {token}'

        tags: List[Dict[str, Any]] = []
        url = f"https://registry.hub.docker.com/v2/repositories/{namespace}/{repo}/tags?page_size=100"
        while url:
            resp = requests.get(url, headers=headers, timeout=10)
            if resp.status_code != 200:
                self.logger.warning(f"Failed to fetch Docker Hub tags: {resp.status_code} {resp.text}")
                break
            data = resp.json()
            for item in data.get('results', []):
                name = item.get('name')
                if not name:
                    continue
                last_updated = item.get('last_updated')
                pushed_at = None
                if last_updated:
                    try:
                        pushed_at = datetime.fromisoformat(last_updated.replace('Z', '+00:00'))
                    except ValueError:
                        pushed_at = None
                tags.append({'tag': name, 'pushed_at': pushed_at})
            url = data.get('next')
        return tags

    def _fetch_gcr_tags(self, service: ServiceConfig) -> List[Dict[str, Any]]:
        """Fetch tags from Google Container Registry / Artifact Registry."""
        image_parts = service.image.split(':')[0].split('/')
        if len(image_parts) < 2:
            return []

        registry_host = image_parts[0]
        repository = '/'.join(image_parts[1:])

        registry_config = service.registry_config or {}
        service_account_path = registry_config.get('service_account_path')
        if service_account_path:
            os.environ['GOOGLE_APPLICATION_CREDENTIALS'] = service_account_path

        scopes = ['https://www.googleapis.com/auth/cloud-platform']
        credentials, _ = default(scopes=scopes)
        credentials.refresh(Request())
        token = credentials.token

        headers = {
            'Authorization': f'Bearer {token}',
            'Accept': 'application/json'
        }

        url = f"https://{registry_host}/v2/{repository}/tags/list"
        resp = requests.get(url, headers=headers, timeout=10)
        if resp.status_code != 200:
            self.logger.warning(f"Failed to fetch GCR tags: {resp.status_code} {resp.text}")
            return []

        data = resp.json()
        manifests = data.get('manifest', {})
        tags: List[Dict[str, Any]] = []
        for manifest in manifests.values():
            uploaded = manifest.get('timeUploadedMs')
            pushed_at = None
            if uploaded:
                try:
                    pushed_at = datetime.fromtimestamp(int(uploaded) / 1000, tz=timezone.utc)
                except Exception:
                    pushed_at = None
            for tag in manifest.get('tag', []):
                tags.append({'tag': tag, 'pushed_at': pushed_at})
        return tags

    def is_semver_tag(self, tag: str) -> bool:
        cleaned = tag
        for prefix in ('release-', 'version-'):
            if cleaned.startswith(prefix):
                cleaned = cleaned[len(prefix):]
        cleaned = cleaned.lstrip('v')
        pattern = r'^(\d+)\.(\d+)\.(\d+)(?:-[0-9A-Za-z.-]+)?(?:\+[0-9A-Za-z.-]+)?$'
        return re.match(pattern, cleaned) is not None
    
    def _time_sort_key(self, value: Optional[datetime]) -> datetime:
        if isinstance(value, datetime):
            if value.tzinfo is None:
                return value.replace(tzinfo=timezone.utc)
            return value
        return datetime.min.replace(tzinfo=timezone.utc)

    def detect_registry_type(self, image: str) -> str:
        """Infer registry type from the image reference when no label is provided."""
        try:
            host = image.split('/')[0]
        except Exception:
            return 'docker_hub'
        host = host.lower()
        if host.endswith('.amazonaws.com'):
            return 'ecr'
        if host.endswith('gcr.io') or host.endswith('.gcr.io') or 'pkg.dev' in host:
            return 'gcr'
        return 'docker_hub'

    def _build_host_config(self, host_config: Dict[str, Any]) -> Optional[Any]:
        if not host_config:
            return None
        params: Dict[str, Any] = {}

        def set_param(key: str, docker_key: str, transform=None, allow_false=False):
            value = host_config.get(key)
            if value is None:
                return
            if not allow_false and not value:
                return
            params[docker_key] = transform(value) if transform else value

        set_param('Binds', 'binds')
        set_param('Links', 'links')
        set_param('PortBindings', 'port_bindings')
        set_param('RestartPolicy', 'restart_policy')
        set_param('NetworkMode', 'network_mode', allow_false=True)
        set_param('Devices', 'devices')
        set_param('Tmpfs', 'tmpfs')
        set_param('ExtraHosts', 'extra_hosts')
        set_param('VolumesFrom', 'volumes_from')
        set_param('CapAdd', 'cap_add')
        set_param('CapDrop', 'cap_drop')
        set_param('SecurityOpt', 'security_opt')
        set_param('Sysctls', 'sysctls')
        set_param('Dns', 'dns')
        set_param('DnsOptions', 'dns_opt')
        set_param('DnsSearch', 'dns_search')
        set_param('Ulimits', 'ulimits')
        set_param('IpcMode', 'ipc_mode')
        set_param('PidMode', 'pid_mode')
        set_param('CgroupnsMode', 'cgroupns')
        set_param('CgroupParent', 'cgroup_parent')
        set_param('ShmSize', 'shm_size', allow_false=True)
        set_param('CpuShares', 'cpu_shares', allow_false=True)
        set_param('CpuPeriod', 'cpu_period', allow_false=True)
        set_param('CpuQuota', 'cpu_quota', allow_false=True)
        set_param('CpusetCpus', 'cpuset_cpus')
        set_param('CpusetMems', 'cpuset_mems')
        set_param('Memory', 'mem_limit', allow_false=True)
        set_param('MemoryReservation', 'mem_reservation', allow_false=True)
        set_param('MemorySwap', 'memswap_limit', allow_false=True)
        set_param('NanoCpus', 'nano_cpus', allow_false=True)
        set_param('BlkioWeight', 'blkio_weight', allow_false=True)
        set_param('BlkioWeightDevice', 'blkio_weight_device')
        set_param('BlkioDeviceReadBps', 'device_read_bps')
        set_param('BlkioDeviceWriteBps', 'device_write_bps')
        set_param('BlkioDeviceReadIOps', 'device_read_iops')
        set_param('BlkioDeviceWriteIOps', 'device_write_iops')
        set_param('DeviceRequests', 'device_requests')
        set_param('DeviceReadBps', 'device_read_bps')
        set_param('DeviceWriteBps', 'device_write_bps')
        set_param('DeviceReadIOps', 'device_read_iops')
        set_param('DeviceWriteIOps', 'device_write_iops')

        if host_config.get('Privileged') is not None:
            params['privileged'] = host_config['Privileged']

        log_config = host_config.get('LogConfig')
        if log_config:
            params['log_config'] = {
                'type': log_config.get('Type'),
                'config': log_config.get('Config') or {}
            }

        if not params:
            return None
        return self.docker_client.api.create_host_config(**params)

    def _build_networking_config(self, networks: Dict[str, Any]):
        if not networks:
            return None
        endpoints: Dict[str, EndpointConfig] = {}
        for net_name, details in networks.items():
            kwargs: Dict[str, Any] = {}
            aliases = details.get('Aliases')
            if aliases:
                kwargs['aliases'] = aliases
            ipam = details.get('IPAMConfig') or {}
            if ipam:
                if ipam.get('IPv4Address'):
                    kwargs['ipv4_address'] = ipam.get('IPv4Address')
                if ipam.get('IPv6Address'):
                    kwargs['ipv6_address'] = ipam.get('IPv6Address')
                if ipam.get('LinkLocalIPs'):
                    kwargs['link_local_ips'] = ipam.get('LinkLocalIPs')
            links = details.get('Links')
            if links:
                kwargs['links'] = links
            driver_opts = details.get('DriverOpts')
            if driver_opts:
                kwargs['driver_opt'] = driver_opts
            endpoints[net_name] = EndpointConfig(**kwargs)

        if not endpoints:
            return None
        return self.docker_client.api.create_networking_config(endpoints)

    def _refresh_service_container(self, service: ServiceConfig) -> None:
        try:
            container = self.docker_client.containers.get(service.name)
            service.container_id = container.id
        except Exception:
            pass

    def auto_detect_latest_tag(self, service: ServiceConfig) -> Tuple[Optional[str], Optional[str]]:
        """Automatically detect the most appropriate newer tag for a service."""
        available_tags = self.fetch_available_tags(service)
        if not available_tags:
            return None, None

        current_tag = service.current_tag
        if not current_tag and ':' in service.image:
            current_tag = service.image.split(':', 1)[1]

        # Deduplicate tags (keep latest pushed info)
        tag_map: Dict[str, Dict[str, Any]] = {}
        for entry in available_tags:
            tag_map[entry['tag']] = entry
        tags = list(tag_map.values())

        # Try semantic versioning first
        semver_candidates = [t for t in tags if self.is_semver_tag(t['tag'])]
        if semver_candidates:
            semver_candidates.sort(
                key=lambda x: self.parse_semver(x['tag']),
                reverse=True
            )
            candidate = semver_candidates[0]['tag']
            if candidate != current_tag:
                return candidate, 'semver'

        # Try prefix matching based on current tag (e.g., staging-)
        if current_tag:
            for delimiter in ['-', '_']:
                if delimiter in current_tag:
                    prefix = current_tag.split(delimiter)[0] + delimiter
                    prefix_candidates = [t for t in tags if t['tag'].startswith(prefix)]
                    if prefix_candidates:
                        prefix_candidates.sort(
                            key=lambda x: self._time_sort_key(x.get('pushed_at')),
                            reverse=True
                        )
                        for item in prefix_candidates:
                            if item['tag'] != current_tag:
                                return item['tag'], f'prefix:{prefix}'

        # Fallback to most recently pushed tag
        time_sorted = [t for t in tags if t['tag'] != current_tag]
        time_sorted.sort(key=lambda x: self._time_sort_key(x.get('pushed_at')), reverse=True)
        if time_sorted:
            return time_sorted[0]['tag'], 'latest'

        # Final fallback: different lexicographic tag
        for item in sorted(tags, key=lambda x: x['tag'], reverse=True):
            if item['tag'] != current_tag:
                return item['tag'], 'lexicographic'

        return None, None
    
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
                check=True
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
    
    def discover_containers(self):
        """Discover containers with watchdoc labels."""
        try:
            containers = self.docker_client.containers.list(filters={'label': 'watchdoc.enable=true'})
            current_names = {container.name for container in containers}
            
            # Remove services that are no longer running with the required label
            removed_services = [s for s in self.services if s.name not in current_names]
            if removed_services:
                self.logger.info(
                    f"Removing {len(removed_services)} stale entries: {', '.join(s.name for s in removed_services)}"
                )
                self.services = [s for s in self.services if s.name in current_names]
            
            for container in containers:
                labels = container.labels
                container_name = container.name
                image_name = container.image.tags[0] if container.image.tags else str(container.image.id)
                
                # Extract configuration from labels
                registry_type_label = labels.get('watchdoc.registry')
                registry_type = registry_type_label or self.detect_registry_type(image_name)
                tag_pattern = labels.get('watchdoc.tag-pattern')
                semver_pattern = labels.get('watchdoc.semver-pattern')

                compose_project = labels.get('com.docker.compose.project')
                compose_service = labels.get('com.docker.compose.service')
                compose_workdir = labels.get('com.docker.compose.project.working_dir')
                compose_files_raw = labels.get('com.docker.compose.project.config_files')
                compose_files: List[str] = []
                if compose_files_raw:
                    for part in re.split(r'[:;,]', compose_files_raw):
                        part = part.strip()
                        if part:
                            compose_files.append(part)
                
                # Parse registry config from labels
                registry_config = {}
                if registry_type == 'ecr':
                    ecr_region = labels.get('watchdoc.ecr.region')
                    if not ecr_region:
                        host = image_name.split('/')[0].lower()
                        host_parts = host.split('.')
                        if len(host_parts) >= 4 and host_parts[2] == 'ecr':
                            ecr_region = host_parts[3]
                    registry_config['region'] = ecr_region
                    registry_config['aws_access_key_id'] = labels.get('watchdoc.ecr.access-key-id')
                    registry_config['aws_secret_access_key'] = labels.get('watchdoc.ecr.secret-access-key')
                elif registry_type == 'gcr':
                    registry_config['project_id'] = labels.get('watchdoc.gcr.project-id')
                    registry_config['service_account_path'] = labels.get('watchdoc.gcr.service-account-path')
                elif registry_type == 'docker_hub':
                    registry_config['username'] = labels.get('watchdoc.dockerhub.username')
                    registry_config['password'] = labels.get('watchdoc.dockerhub.password')
                
                # Check if already tracked
                existing = next((s for s in self.services if s.name == container_name), None)
                if existing:
                    existing.container_id = container.id
                    existing.image = image_name
                    existing.registry_type = registry_type
                    existing.registry_config = registry_config if any(registry_config.values()) else None
                    existing.tag_pattern = tag_pattern
                    existing.semver_pattern = semver_pattern
                    existing.auto_discovered = True
                    existing.compose_project = compose_project
                    existing.compose_service = compose_service
                    existing.compose_workdir = compose_workdir
                    existing.compose_files = compose_files
                    
                    if ':' in image_name:
                        existing.current_tag = image_name.split(':', 1)[1]
                    continue
                
                current_tag = image_name.split(':', 1)[1] if ':' in image_name else None
                
                service = ServiceConfig(
                    name=container_name,
                    image=image_name,
                    container_id=container.id,
                    registry_type=registry_type,
                    registry_config=registry_config if any(registry_config.values()) else None,
                    tag_pattern=tag_pattern,
                    semver_pattern=semver_pattern,
                    auto_discovered=True,
                    current_tag=current_tag,
                    compose_project=compose_project,
                    compose_service=compose_service,
                    compose_workdir=compose_workdir,
                    compose_files=compose_files
                )
                
                self.services.append(service)
                
                state_data = self.service_state_cache.get(container_name)
                if state_data:
                    service.current_digest = state_data.get('current_digest')
                    if state_data.get('last_updated'):
                        service.last_updated = datetime.fromisoformat(state_data['last_updated'])
                
                self.logger.info(f"Auto-discovered container: {container_name} (image: {image_name})")
            
            if containers:
                self.logger.info(f"Auto-discovered {len(containers)} containers via labels")
            
        except Exception as e:
            self.logger.error(f"Error during container discovery: {e}")
    
    def pull_image(self, image_name: str) -> bool:
        """Pull the latest version of an image."""
        try:
            self.logger.info(f"Pulling image: {image_name}")
            self.docker_client.images.pull(image_name)
            return True
        except Exception as e:
            self.logger.error(f"Failed to pull image {image_name}: {e}")
            return False
    
    def restart_service(self, service: ServiceConfig, new_image: str) -> bool:
        """Restart a service, preferring docker compose metadata when available."""
        if service.compose_service:
            if self.restart_via_compose(service, new_image):
                self._refresh_service_container(service)
                return True
            self.logger.warning(f"Falling back to container recreation for {service.name}")
        
        if self.recreate_container(service, new_image):
            self._refresh_service_container(service)
            return True
        return False

    def restart_via_compose(self, service: ServiceConfig, new_image: str) -> bool:
        """Restart the service using docker compose metadata if available."""
        if shutil.which('docker') is None:
            self.logger.debug("'docker' CLI not found; cannot use docker compose")
            return False
        compose_files = service.compose_files or []
        workdir = service.compose_workdir
        if not workdir and compose_files:
            workdir = os.path.dirname(compose_files[0])
        if not workdir:
            self.logger.debug(f"No compose working directory for {service.name}")
            return False
        if not os.path.isdir(workdir):
            self.logger.warning(f"Compose working directory '{workdir}' not accessible for {service.name}")
            return False

        base_cmd = ['docker', 'compose']
        if service.compose_project:
            base_cmd += ['-p', service.compose_project]
        for compose_file in compose_files:
            base_cmd += ['-f', compose_file]
        up_cmd = base_cmd + ['up', '-d', '--no-deps', service.compose_service]

        try:
            self.logger.info(
                f"Restarting compose service {service.compose_service} (project: {service.compose_project or 'default'})"
            )
            environ = os.environ.copy()
            environ['WATCHDOC_NEW_IMAGE'] = new_image
            self._merge_compose_env(workdir, compose_files, environ)

            pull_cmd = base_cmd + ['pull', service.compose_service]
            subprocess.run(
                pull_cmd,
                cwd=workdir,
                env=environ,
                capture_output=True,
                text=True,
                check=False
            )

            result = subprocess.run(
                up_cmd + ['--pull', 'always', '--force-recreate'],
                cwd=workdir,
                env=environ,
                capture_output=True,
                text=True,
                check=True
            )
            if result.stdout:
                self.logger.debug(result.stdout.strip())
            if result.stderr:
                self.logger.debug(result.stderr.strip())

            self._refresh_service_container(service)
            if not service.container_id:
                self.logger.warning(f"Compose restart did not expose container ID for {service.name}")
                return False

            try:
                container = self.docker_client.containers.get(service.container_id)
                cfg_image = container.attrs.get('Config', {}).get('Image')
                tags = []
                try:
                    tags = container.image.tags or []
                except Exception:
                    tags = []
                if cfg_image == new_image or new_image in tags:
                    self.logger.info(f"Successfully refreshed compose service: {service.name}")
                    return True
                self.logger.warning(
                    f"Compose restart kept {service.name} on {cfg_image}, expected {new_image}; falling back"
                )
                return False
            except Exception as exc:
                self.logger.error(f"Failed to verify compose restart for {service.name}: {exc}")
                return False
        except subprocess.CalledProcessError as e:
            self.logger.error(
                f"docker compose failed for {service.name}: return code {e.returncode}. stderr: {e.stderr.strip()}"
            )
            return False
        except Exception as e:
            self.logger.error(f"Unexpected error using docker compose for {service.name}: {e}")
            return False
    
    def recreate_container(self, service: ServiceConfig, new_image: str) -> bool:
        if not service.container_id:
            self.logger.error(f"No container ID recorded for {service.name}")
            return False
        try:
            container = self.docker_client.containers.get(service.container_id)
        except Exception as e:
            self.logger.error(f"Unable to inspect container {service.name}: {e}")
            return False

        attrs = container.attrs
        config = attrs.get('Config', {})
        host_config_dict = attrs.get('HostConfig', {})
        networking = attrs.get('NetworkSettings', {}).get('Networks', {})
        name = attrs.get('Name', '').lstrip('/') or service.name

        exposed_ports = None
        if config.get('ExposedPorts'):
            exposed_ports = list(config['ExposedPorts'].keys())
        volumes = None
        if config.get('Volumes'):
            volumes = list(config['Volumes'].keys())

        env = config.get('Env')
        command = config.get('Cmd')
        entrypoint = config.get('Entrypoint')
        user = config.get('User')
        working_dir = config.get('WorkingDir')
        labels = config.get('Labels')
        hostname = config.get('Hostname')
        domainname = config.get('Domainname')
        stop_signal = config.get('StopSignal')
        tty = config.get('Tty')
        stdin_open = config.get('OpenStdin')

        host_config = self._build_host_config(host_config_dict)
        networking_config = self._build_networking_config(networking)

        self.logger.info(f"Recreating container {name} with image {new_image}")

        try:
            container.stop(timeout=attrs.get('StopTimeout') or 10)
        except Exception as e:
            self.logger.warning(f"Failed to stop container {name}: {e}")
        try:
            container.remove(force=True)
        except Exception as e:
            self.logger.error(f"Failed to remove container {name}: {e}")
            return False

        create_kwargs = {
            'image': new_image,
            'name': name,
            'command': command,
            'environment': env,
            'hostname': hostname,
            'user': user,
            'stdin_open': stdin_open,
            'tty': tty,
            'ports': exposed_ports,
            'labels': labels,
            'entrypoint': entrypoint,
            'working_dir': working_dir,
            'domainname': domainname,
            'stop_signal': stop_signal,
            'volumes': volumes,
        }
        create_kwargs = {k: v for k, v in create_kwargs.items() if v}

        if host_config is not None:
            create_kwargs['host_config'] = host_config
        if networking_config is not None:
            create_kwargs['networking_config'] = networking_config

        try:
            new_container = self.docker_client.api.create_container(**create_kwargs)
            new_id = new_container.get('Id') or new_container.get('id')
            self.docker_client.api.start(new_id)
            service.container_id = new_id
            self.logger.info(f"Successfully recreated container {name}")
            return True
        except Exception as e:
            self.logger.error(f"Failed to recreate container {name}: {e}")
            return False

    def _merge_compose_env(self, workdir: str, compose_files: List[str], environ: Dict[str, str]) -> None:
        candidate_dirs: List[str] = []
        if workdir:
            candidate_dirs.append(workdir)
        for compose_file in compose_files or []:
            dirpath = os.path.dirname(compose_file) or '.'
            if workdir and not os.path.isabs(dirpath):
                dirpath = os.path.normpath(os.path.join(workdir, dirpath))
            candidate_dirs.append(dirpath)

        seen: set = set()
        for dirpath in candidate_dirs:
            if not dirpath or dirpath in seen:
                continue
            seen.add(dirpath)
            env_path = os.path.join(dirpath, '.env')
            if not os.path.isfile(env_path):
                continue
            try:
                with open(env_path, 'r') as env_file:
                    for line in env_file:
                        line = line.strip()
                        if not line or line.startswith('#'):
                            continue
                        key, sep, value = line.partition('=')
                        if not sep:
                            continue
                        key = key.strip()
                        if not key or key in environ:
                            continue
                        value = value.strip().strip('"').strip("'")
                        environ[key] = value
            except Exception as exc:
                self.logger.warning(f"Failed to read compose .env at {env_path}: {exc}")
        return
    
    def check_for_updates(self, service: ServiceConfig) -> bool:
        """Check if a service needs to be updated."""
        if not self.authenticate_registry(service):
            self.logger.error(f"Failed to authenticate with registry for {service.name}")
            return False
        
        current_image = service.image
        latest_tag = None
        
        if service.semver_pattern:
            latest_tag = self.get_latest_semver_tag(service)
            if not latest_tag:
                self.logger.warning(f"No semver tags found matching pattern '{service.semver_pattern}' for {service.name}")
                return False
            
            image_base = service.image.split(':')[0]
            current_image = f"{image_base}:{latest_tag}"
            
            if service.current_tag:
                current_version = service.current_tag.replace(service.semver_pattern.replace('*', ''), '')
                new_version = latest_tag.replace(service.semver_pattern.replace('*', ''), '')
                if self.compare_semver(new_version, current_version) <= 0:
                    self.logger.debug(f"No newer semver found for {service.name}, current: {service.current_tag}")
                    return False
            
            self.logger.info(f"Latest semver tag for {service.name}: {latest_tag}")
        
        elif service.tag_pattern:
            latest_tag = self.get_latest_tag_for_pattern(service)
            if not latest_tag:
                self.logger.warning(f"No tags found matching pattern '{service.tag_pattern}' for {service.name}")
                return False
            
            image_base = service.image.split(':')[0]
            current_image = f"{image_base}:{latest_tag}"
            
            if service.current_tag and service.current_tag == latest_tag:
                self.logger.debug(f"No new tag found for {service.name}, current: {latest_tag}")
                return False
            
            self.logger.info(f"Latest tag for {service.name}: {latest_tag}")
        
        else:
            latest_tag, detected_strategy = self.auto_detect_latest_tag(service)
            if latest_tag:
                image_base = service.image.split(':')[0]
                current_image = f"{image_base}:{latest_tag}"
                if service.current_tag and service.current_tag == latest_tag:
                    self.logger.debug(f"No new auto-detected tag for {service.name}, current: {latest_tag}")
                    return False
                service.detected_strategy = detected_strategy
                self.logger.info(
                    f"Auto-detected latest tag for {service.name}: {latest_tag}"
                    + (f" (strategy: {detected_strategy})" if detected_strategy else "")
                )
            else:
                self.logger.debug(f"No auto-detected tags available for {service.name}")
                latest_tag = None
                current_image = service.image
                service.detected_strategy = None
        
        if not self.pull_image(current_image):
            return False

        new_digest = self.get_image_digest(current_image)
        if not new_digest:
            self.logger.warning(f"Could not get digest for {current_image}")
            return False
        
        if latest_tag:
            target_tag = latest_tag
            
            if service.current_tag == target_tag and service.current_digest == new_digest:
                self.logger.debug(f"No changes detected for {service.name} (tag {target_tag})")
                return False
            
            if self.restart_service(service, current_image):
                service.image = current_image
                service.current_digest = new_digest
                service.current_tag = target_tag
                service.last_updated = datetime.now()
                self.save_state()
                return True
            
            self.logger.error(f"Failed to restart container for {service.name}")
            return False
        
        # Digest-based comparison for fixed tags
        if service.current_digest is None:
            service.current_digest = new_digest
            self.logger.info(f"Initial digest stored for {service.name}: {new_digest[:12]}...")
            return False
        
        if new_digest != service.current_digest:
            self.logger.info(f"New digest detected for {service.name}")
            self.logger.info(f"Old digest: {service.current_digest[:12]}...")
            self.logger.info(f"New digest: {new_digest[:12]}...")
            
            if self.restart_service(service, current_image):
                service.current_digest = new_digest
                service.last_updated = datetime.now()
                self.save_state()
                return True
            
            self.logger.error(f"Failed to restart container for {service.name}")
            return False
        
        self.logger.debug(f"No digest change for {service.name}")
        return False
    
    def save_state(self):
        """Save current state to a file for persistence."""
        state = {'services': []}
        self.service_state_cache = {}
        
        for service in self.services:
            service_state = {
                'name': service.name,
                'image': service.image,
                'current_digest': service.current_digest,
                'current_tag': service.current_tag,
                'detected_strategy': service.detected_strategy,
                'last_updated': service.last_updated.isoformat() if service.last_updated else None
            }
            state['services'].append(service_state)
            self.service_state_cache[service.name] = service_state
        
        with open(self.state_file, 'w') as f:
            json.dump(state, f, indent=2)
    
    def load_state(self):
        """Load previous state from file."""
        if not os.path.exists(self.state_file):
            return
        
        try:
            with open(self.state_file, 'r') as f:
                state = json.load(f)
            
            self.service_state_cache = {
                entry['name']: entry
                for entry in state.get('services', [])
                if entry.get('name')
            }
            
            for service in self.services:
                service_data = self.service_state_cache.get(service.name)
                if not service_data:
                    continue
                
                service.current_digest = service_data.get('current_digest')
                service.current_tag = service_data.get('current_tag')
                service.detected_strategy = service_data.get('detected_strategy')
                if service_data.get('last_updated'):
                    service.last_updated = datetime.fromisoformat(service_data['last_updated'])
        except Exception as e:
            self.logger.error(f"Error loading state: {e}")
    
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
            
        except Exception as e:
            self.logger.warning(f"Error during cleanup: {e}")
    
    def run(self):
        """Main execution loop."""
        self.logger.info("Watchdoc starting...")
        self.logger.info(f"Containers discovered: {len(self.services)}")
        self.logger.info(f"Check interval: {self.check_interval} seconds")
        
        # Load previous state
        self.load_state()
        
        try:
            while True:
                # Refresh discovery each loop to capture new containers
                if self.auto_discovery:
                    self.discover_containers()
                else:
                    self.logger.debug("AUTO_DISCOVERY disabled; skipping discovery")
                
                self.logger.info(f"Checking for updates across {len(self.services)} containers...")
                
                for service in self.services:
                    try:
                        updated = self.check_for_updates(service)
                        if updated:
                            self.logger.info(f"Service {service.name} updated successfully")
                        else:
                            self.logger.debug(f"No updates for {service.name}")
                    except Exception as e:
                        self.logger.error(f"Error checking service {service.name}: {e}")
                
                self.logger.info(f"Check complete. Sleeping for {self.check_interval} seconds...")
                time.sleep(self.check_interval)
                
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal. Shutting down...")
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            raise


def main():
    """Main entry point."""
    agent = Watchdoc()
    agent.run()


if __name__ == "__main__":
    main()
