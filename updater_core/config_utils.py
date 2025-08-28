import json
import os
from typing import Any, Dict, List, Tuple

from updater_core.models import ServiceConfig

# Optional jsonschema
try:
    from jsonschema import validate as jsonschema_validate, ValidationError  # type: ignore
except Exception:  # pragma: no cover
    jsonschema_validate = None
    ValidationError = Exception


def resolve_env_vars(config_dict: Dict[str, Any]) -> Dict[str, Any]:
    """Recursively resolve ${VAR} environment variables in a dict."""
    resolved: Dict[str, Any] = {}
    import re

    def replace_env_var(match):
        var_name = match.group(1)
        return os.getenv(var_name, match.group(0))

    for key, value in config_dict.items():
        if isinstance(value, str):
            resolved[key] = re.sub(r"\$\{([^}]+)\}", replace_env_var, value)
        elif isinstance(value, dict):
            resolved[key] = resolve_env_vars(value)
        elif isinstance(value, list):
            resolved[key] = [resolve_env_vars(item) if isinstance(item, dict) else item for item in value]
        else:
            resolved[key] = value
    return resolved


def load_config(config_file: str, logger) -> Tuple[List[ServiceConfig], int]:
    """Load and validate configuration, return (services, check_interval)."""
    with open(config_file, 'r') as f:
        config = json.load(f)

    check_interval = config.get('check_interval', 30)
    env_ci = os.getenv('CHECK_INTERVAL')
    if env_ci is not None:
        try:
            check_interval = int(env_ci)
        except Exception:
            pass

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
                    },
                },
            },
        },
        'required': ['services'],
    }
    if jsonschema_validate:
        try:
            jsonschema_validate(config, schema)
        except ValidationError as e:
            logger.error(f"Configuration validation error: {e.message}")
            raise

    services: List[ServiceConfig] = []
    for service_config in config.get('services', []):
        registry_config = service_config.get('registry_config', {})
        resolved_registry_config = resolve_env_vars(registry_config)

        service = ServiceConfig(
            name=service_config['name'],
            image=service_config['image'],
            compose_file=service_config['compose_file'],
            compose_service=service_config['compose_service'],
            registry_type=service_config.get('registry_type', 'docker_hub'),
            registry_config=resolved_registry_config,
            tag_pattern=service_config.get('tag_pattern'),
            tag_regex=service_config.get('tag_regex'),
            semver_pattern=service_config.get('semver_pattern'),
        )
        services.append(service)
    logger.info(f"Loaded configuration for {len(services)} services")
    return services, check_interval


def create_default_config(config_file: str, logger) -> str:
    """Create a default config file. Returns the path written."""
    default_config = {
        "check_interval": 30,
        "services": [
            {
                "name": "example-web-app",
                "image": "nginx:latest",
                "compose_file": "./docker-compose.yml",
                "compose_service": "web",
            }
        ],
    }
    try:
        config_dir = os.path.dirname(config_file) or '.'
        if config_dir and not os.path.exists(config_dir):
            os.makedirs(config_dir, exist_ok=True)
        with open(config_file, 'w') as f:
            json.dump(default_config, f, indent=2)
        logger.info(f"Created default configuration file: {config_file}")
        logger.info("Please update the configuration with your services")
        return config_file
    except Exception:
        local_path = './updater_config.json'
        with open(local_path, 'w') as f:
            json.dump(default_config, f, indent=2)
        logger.info(f"Created local configuration file: {local_path}")
        logger.info("Please update the configuration with your services")
        return local_path

