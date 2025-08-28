from dataclasses import dataclass
from datetime import datetime
from typing import Optional, Dict


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

