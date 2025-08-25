# Docker Auto‑Updater

Production‑ready service that monitors container registries (Docker Hub, AWS ECR, Google Container Registry) and automatically updates docker‑compose services when new images are available. Supports dynamic tags, SemVer selection, rollbacks, metrics, and webhooks.

## Features

- Multi‑registry: Docker Hub, AWS ECR, Google Container Registry
- Dynamic tags: glob (`staging-*`) and regex (`^staging-[a-f0-9]{7}$`) with newest push detection
- SemVer selection: Full SemVer 2.0 precedence (e.g., `v1.2.3`, prerelease ordering)
- Compose integration: Mutates `docker-compose.yml` and restarts services
- Reliability: Health‑gated restarts, rollback on failure, digest verification
- State safety: Atomic state writes, rotating backups, auto‑recovery
- Metrics & webhooks: Prometheus counters and optional outbound webhook
- Systemd service: Easy install via `install.sh`; clean uninstall

## Architecture

- `docker_updater.py`: Main entrypoint, orchestrates checks and updates
- `updater_core/` helpers:
  - `compose_utils.py`: Compose command detection, exec, YAML mutation
  - `docker_utils.py`: Image pulls, digests, container lookup, health wait
  - `registry_utils.py`: Registry authentication (ECR/GCR/Docker Hub)
  - `semver_utils.py`: SemVer parse/compare
  - `state_utils.py`: Save/load state, backups, cleanup
  - `config_utils.py`: Env var resolution, config load/validate, defaults
  - `metrics_utils.py`: Prometheus counters wiring
  - `logging_utils.py`: JSON log formatter
  - `models.py`: `ServiceConfig` dataclass

## Quick Start

### Install as systemd service (recommended)

```bash
git clone <repository-url>
cd docker-auto-updater
sudo ./install.sh

# Edit config and env
sudo nano /etc/docker-auto-updater/updater_config.json
sudo nano /etc/docker-auto-updater/.env

# Start / status
sudo systemctl enable docker-updater
sudo systemctl start docker-updater
sudo systemctl status docker-updater
```

### Run locally

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt

# Copy and edit local config
cp .env.example .env
cp updater_config.json ./local_updater_config.json

# Run once with debug logs
CONFIG_FILE=./local_updater_config.json LOG_LEVEL=DEBUG python3 docker_updater.py --once
```

## Configuration

- Config file: `/etc/docker-auto-updater/updater_config.json`
- Env file: `/etc/docker-auto-updater/.env`
- State: `/var/lib/docker-auto-updater/updater_state.json`
- Logs: `/var/log/docker-auto-updater/docker_updater.log`

### Example `updater_config.json`

```json
{
  "check_interval": 30,
  "services": [
    {
      "name": "webapp",
      "image": "myregistry/webapp:latest",
      "compose_file": "/opt/apps/webapp/docker-compose.yml",
      "compose_service": "web",
      "registry_type": "docker_hub"
    },
    {
      "name": "api-staging",
      "image": "111111111111.dkr.ecr.us-east-1.amazonaws.com/api:staging-old",
      "compose_file": "/opt/apps/api/docker-compose.yml",
      "compose_service": "api",
      "registry_type": "ecr",
      "tag_pattern": "staging-*",
      "registry_config": { "region": "us-east-1" }
    },
    {
      "name": "release-app",
      "image": "111111111111.dkr.ecr.us-east-1.amazonaws.com/app:v1.0.0",
      "compose_file": "/opt/apps/release-app/docker-compose.yml",
      "compose_service": "app",
      "registry_type": "ecr",
      "semver_pattern": "v*",
      "registry_config": { "region": "us-east-1" }
    }
  ]
}
```

### `.env` options

```bash
# Logging
LOG_LEVEL=INFO         # DEBUG|INFO|WARN|ERROR
LOG_FORMAT=plain       # or json

# Intervals / timeouts
CHECK_INTERVAL=3600
HEALTH_TIMEOUT=180
HEALTH_STABLE=10
COMPOSE_TIMEOUT=120

# State backups
STATE_BACKUPS=5
#STATE_BACKUP_DIR=/var/backups/docker-auto-updater

# Observability
#METRICS_PORT=9100
#WEBHOOK_URL=https://example.com/webhook

# Controls
#MAINTENANCE_WINDOW=02:00-04:00,14:00-15:30
#PAUSE_UPDATES=0

# Registry credentials (optional: prefer IAM/ADC where possible)
# AWS
#AWS_ACCESS_KEY_ID=...
#AWS_SECRET_ACCESS_KEY=...
#AWS_DEFAULT_REGION=us-east-1
# Docker Hub
#DOCKER_HUB_USERNAME=...
#DOCKER_HUB_PASSWORD=...
# GCP
#GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
```

## Dynamic Tags and SemVer

- `tag_pattern`: Glob pattern (e.g., `staging-*`); newest pushed tag wins
- `tag_regex`: Regex filter (e.g., `^staging-[a-f0-9]{7}$`)
- `semver_pattern`: Prefix for SemVer tags (e.g., `v*`); highest SemVer wins

How selection works (ECR examples):
- List repository tags via ECR API
- Filter to pattern/regex or SemVer‑prefixed values
- For `tag_pattern`/`tag_regex`: pick most recent by `imagePushedAt`
- For `semver_pattern`: compare per SemVer 2.0 precedence

Example dynamic tag service:

```json
{
  "name": "accounting-staging",
  "image": "111111111111.dkr.ecr.us-east-1.amazonaws.com/accounting:staging-a1b2c3d",
  "compose_file": "/apps/accounting/docker-compose.yml",
  "compose_service": "app",
  "registry_type": "ecr",
  "tag_pattern": "staging-*",
  "registry_config": { "region": "us-east-1" }
}
```

## Registry Setup

### AWS ECR

Minimal IAM policy permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken",
        "ecr:DescribeImages",
        "ecr:DescribeRepositories",
        "ecr:BatchGetImage",
        "ecr:GetDownloadUrlForLayer"
      ],
      "Resource": "*"
    }
  ]
}
```

Per‑service `registry_config` example:

```json
{
  "registry_type": "ecr",
  "registry_config": {
    "region": "us-east-1",
    "aws_access_key_id": "${AWS_ACCESS_KEY_ID}",
    "aws_secret_access_key": "${AWS_SECRET_ACCESS_KEY}"
  }
}
```

Manual auth test:

```bash
aws ecr get-login-password --region us-east-1 \
 | docker login --username AWS --password-stdin 111111111111.dkr.ecr.us-east-1.amazonaws.com
```

### Google Container Registry (GCR)

Set `GOOGLE_APPLICATION_CREDENTIALS` to a service account JSON (or use default credentials) and optionally pass `project_id`/`service_account_path` in a service’s `registry_config`.

Manual auth test:

```bash
gcloud auth configure-docker
docker pull gcr.io/my-project/my-app:latest
```

### Docker Hub

For private repos, set `DOCKER_HUB_USERNAME`/`DOCKER_HUB_PASSWORD` (or put `username`/`password` under a service’s `registry_config`).

## How It Works

Each cycle for enabled services:

1. Authenticate to registry (if needed)
2. Compute latest image (digest or dynamic tag/SemVer)
3. Pull image; compute digest; compare with last state
4. If update needed: update compose YAML → restart → health‑gate → verify digest
5. On failure: rollback to prior image and restart
6. Persist state atomically and write a timestamped backup

## Operations

- Single run: `python3 docker_updater.py --once`
- Environment test: `python3 docker_updater.py --test`
- Logs: `journalctl -u docker-updater -f` or `/var/log/docker-auto-updater/docker_updater.log`
- Pause: `PAUSE_UPDATES=1`
- Maintenance window: `MAINTENANCE_WINDOW=HH:MM-HH:MM[, ...]`

## Observability

- Enable metrics with `METRICS_PORT`; counters include updates, rollbacks, failures, state restores
- Set `WEBHOOK_URL` to send JSON events: `update` and `rollback`
- JSON logs via `LOG_FORMAT=json`

## Security & Best Practices

- Don’t commit secrets; use `.env` and per‑service `registry_config` with env var substitution
- Prefer IAM roles / Workload Identity over static keys
- Scope registry credentials to required repos; rotate regularly

## Testing

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt -r dev-requirements.txt
python -m pytest -q
```

## Troubleshooting

- Docker permissions: add the service user to the `docker` group
- Compose not found: install Docker Compose plugin or `docker-compose` binary
- Auth errors: validate credentials; try the manual auth tests above
- State fallback: if system path isn’t writable, state is written to `./updater_state.json`

## Production Notes

- CPU: 0.1–0.5 cores; RAM: 128–512 MB; small disk for logs/state
- Configure log rotation and monitoring alerts
- Use maintenance windows in busy environments; prefer IAM/ADC over static keys

## License

MIT License — see `LICENSE`

