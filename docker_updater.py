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
import hashlib
import re
from datetime import datetime
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any
import docker
from docker.errors import DockerException
import requests
import boto3
from botocore.exceptions import ClientError, NoCredentialsError
from google.cloud import storage as gcs
from google.auth.exceptions import DefaultCredentialsError
from google.auth import default
from google.auth.transport.requests import Request

# Load environment variables from .env file
try:
    from dotenv import load_dotenv
    # Load from the config directory
    env_file = '/etc/docker-auto-updater/.env'
    if os.path.exists(env_file):
        load_dotenv(env_file)
        print(f"Loaded environment variables from {env_file}")
    else:
        print(f"Warning: {env_file} not found, using system environment variables")
except ImportError:
    print("python-dotenv not installed, using system environment variables only")


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
    tag_pattern: Optional[str] = None  # e.g., "staging-*", "prod-*"
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
        self.setup_logging()
        self.load_config()
        self.init_docker_client()
    
    def setup_logging(self):
        """Configure logging with proper formatting."""
        # Use environment variable for log level, default to INFO
        log_level = os.getenv('LOG_LEVEL', 'INFO').upper()
        
        # Use proper log directory that's writable
        log_dir = '/var/log/docker-auto-updater'
        log_file = os.path.join(log_dir, 'docker_updater.log')
        
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
    
    def load_config(self):
        """Load configuration from JSON file."""
        if not os.path.exists(self.config_file):
            self.create_default_config()
        
        try:
            with open(self.config_file, 'r') as f:
                config = json.load(f)
            
            self.check_interval = config.get('check_interval', 30)
            
            for service_config in config.get('services', []):
                service = ServiceConfig(
                    name=service_config['name'],
                    image=service_config['image'],
                    compose_file=service_config['compose_file'],
                    compose_service=service_config['compose_service'],
                    registry_type=service_config.get('registry_type', 'docker_hub'),
                    registry_config=service_config.get('registry_config', {}),
                    tag_pattern=service_config.get('tag_pattern'),
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
        
        with open(self.config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        
        self.logger.info(f"Created default configuration file: {self.config_file}")
        self.logger.info("Please update the configuration with your services")
    
    def authenticate_ecr(self, region: str, aws_access_key_id: str = None, aws_secret_access_key: str = None) -> bool:
        """Authenticate with AWS ECR."""
        try:
            # Use provided credentials or default AWS credentials
            if aws_access_key_id and aws_secret_access_key:
                ecr_client = boto3.client(
                    'ecr',
                    region_name=region,
                    aws_access_key_id=aws_access_key_id,
                    aws_secret_access_key=aws_secret_access_key
                )
            else:
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
    
    def parse_semver(self, version: str) -> Tuple[int, int, int, str]:
        """Parse a semantic version string into components."""
        # Remove common prefixes
        version = version.lstrip('v').lstrip('release-').lstrip('version-')
        
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
    
    def pull_image(self, image_name: str) -> bool:
        """Pull the latest version of an image."""
        try:
            self.logger.info(f"Pulling image: {image_name}")
            self.docker_client.images.pull(image_name)
            return True
        except APIError as e:
            self.logger.error(f"Failed to pull image {image_name}: {e}")
            return False
    
    def restart_service(self, service: ServiceConfig) -> bool:
        """Restart a service using docker-compose."""
        try:
            compose_dir = os.path.dirname(os.path.abspath(service.compose_file))
            compose_file = os.path.basename(service.compose_file)
            
            self.logger.info(f"Restarting service: {service.name}")
            
            # Stop the service
            stop_result = subprocess.run(
                ['docker-compose', '-f', compose_file, 'stop', service.compose_service],
                cwd=compose_dir,
                capture_output=True,
                text=True,
                check=True
            )
            
            # Start the service
            start_result = subprocess.run(
                ['docker-compose', '-f', compose_file, 'up', '-d', service.compose_service],
                cwd=compose_dir,
                capture_output=True,
                text=True,
                check=True
            )
            
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
        
        # For tag patterns, check if we have a new tag or new digest
        if service.tag_pattern:
            latest_tag = current_image.split(':')[1]
            
            # If we have a new tag, update regardless of digest
            if service.current_tag != latest_tag:
                self.logger.info(f"New tag detected for {service.name}: {latest_tag}")
                
                # Update docker-compose file with new image
                if self.update_compose_file(service, current_image):
                    if self.restart_service(service):
                        service.current_digest = new_digest
                        service.current_tag = latest_tag
                        service.last_updated = datetime.now()
                        self.save_state()
                        return True
                    else:
                        self.logger.error(f"Failed to restart service: {service.name}")
                        return False
                else:
                    self.logger.error(f"Failed to update compose file for: {service.name}")
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
                    service.current_digest = new_digest
                    service.last_updated = datetime.now()
                    self.save_state()
                    return True
                else:
                    self.logger.error(f"Failed to update service: {service.name}")
                    return False
        
        return False
    
    def update_compose_file(self, service: ServiceConfig, new_image: str) -> bool:
        """Update the docker-compose file with new image tag, handling root permission conflicts."""
        try:
            import yaml
            import tempfile
            import os
            
            # First, try to read the compose file directly
            try:
                with open(service.compose_file, 'r') as f:
                    compose_data = yaml.safe_load(f)
            except PermissionError:
                # If permission denied, try with sudo
                self.logger.info(f"Permission denied reading {service.compose_file}, trying with sudo")
                result = subprocess.run(['sudo', 'cat', service.compose_file], 
                                      capture_output=True, text=True, check=True)
                compose_data = yaml.safe_load(result.stdout)
            
            # Find and update the service
            if 'services' in compose_data and service.compose_service in compose_data['services']:
                old_image = compose_data['services'][service.compose_service].get('image', '')
                compose_data['services'][service.compose_service]['image'] = new_image
                
                # Try to write directly first
                try:
                    with open(service.compose_file, 'w') as f:
                        yaml.dump(compose_data, f, default_flow_style=False, sort_keys=False)
                    self.logger.info(f"Updated {service.compose_file}: {old_image} -> {new_image}")
                    return True
                except PermissionError:
                    # If permission denied, use sudo with temporary file
                    self.logger.info(f"Permission denied writing {service.compose_file}, using sudo")
                    
                    # Create temporary file
                    temp_fd, temp_path = tempfile.mkstemp(suffix='.yml', prefix='docker-compose-')
                    try:
                        with os.fdopen(temp_fd, 'w') as temp_file:
                            yaml.dump(compose_data, temp_file, default_flow_style=False, sort_keys=False)
                        
                        # Use sudo to copy temp file to target location
                        subprocess.run(['sudo', 'cp', temp_path, service.compose_file], check=True)
                        self.logger.info(f"Updated {service.compose_file} via sudo: {old_image} -> {new_image}")
                        return True
                        
                    finally:
                        # Clean up temp file
                        try:
                            os.unlink(temp_path)
                        except:
                            pass
            else:
                self.logger.error(f"Service {service.compose_service} not found in {service.compose_file}")
                return False
                
        except Exception as e:
            self.logger.error(f"Failed to update compose file {service.compose_file}: {e}")
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
                'last_updated': service.last_updated.isoformat() if service.last_updated else None
            }
            state['services'].append(service_state)
        
        with open(self.state_file, 'w') as f:
            json.dump(state, f, indent=2)
    
    def load_state(self):
        """Load previous state from file."""
        if not os.path.exists(self.state_file):
            return
        
        try:
            with open(self.state_file, 'r') as f:
                state = json.load(f)
            
            for service_data in state.get('services', []):
                for service in self.services:
                    if service.name == service_data['name']:
                        service.current_digest = service_data.get('current_digest')
                        if service_data.get('last_updated'):
                            service.last_updated = datetime.fromisoformat(service_data['last_updated'])
                        break
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
                time.sleep(self.check_interval)
                
        except KeyboardInterrupt:
            self.logger.info("Received interrupt signal. Shutting down...")
        except Exception as e:
            self.logger.error(f"Unexpected error: {e}")
            raise


def main():
    """Main entry point."""
    updater = DockerUpdater()
    updater.run()


if __name__ == "__main__":
    main()
