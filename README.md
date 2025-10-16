# Watchdoc

Watchdoc is a production-ready agent that watches your running containers and keeps them on the freshest image that matches your rules—without brittle per-app configuration. Watchdoc supports Docker Hub, AWS ECR, and Google Container Registry, and the default experience relies on **container labels** instead of hard-coded compose paths.

## Core Workflow

1. Install Watchdoc on the host.
2. Add a couple of labels to any container you want auto-updated.
3. Watchdoc discovers, tracks, and refreshes those containers automatically.

## 🚀 Label-Based Auto-Discovery (Default)

**No more manual configuration!** Just add labels to your containers and Watchdoc takes it from there. Most registry details are optional—Watchdoc infers the provider from the image host (`*.amazonaws.com` → ECR, `gcr.io` → GCR, everything else defaults to Docker Hub) and falls back to credentials in `/etc/watchdoc/.env` or the instance profile. Add labels only when you need overrides:

```yaml
services:
  my-app:
    image: 123456789012.dkr.ecr.us-east-1.amazonaws.com/example-service:staging-latest
    labels:
      - "watchdoc.enable=true"
```

✅ **No sudo required** - Uses Docker API directly  
✅ **Zero configuration** - Automatic container discovery  
✅ **Works anywhere** - No compose file path needed  

See the [Label-Based Discovery Reference](#label-based-discovery-reference) below for more examples.

## Features

- **🎯 Label-Based Auto-Discovery**: Automatically discover and monitor containers with labels (default behavior)
- **Multi-Registry Support**: Docker Hub, AWS ECR, Google Container Registry
- **Dynamic Tag Patterns**: Support for `staging-*`, `prod-*` style tags with automatic latest selection  
- **Semantic Versioning**: Intelligent semver parsing and comparison (`v1.2.3`, `release-2.0.0`)
- **Smart Tag Detection**: Auto-identifies semver or prefix-based patterns when no labels are provided and tracks the freshest image automatically
- **Docker Compose Aware**: Detects compose-managed services via Docker's built-in labels and refreshes them with `docker compose`—no file edits or sudo tricks required
- **Automatic Service Restart**: Direct Docker API restart (no sudo needed!)
- **State Persistence**: Tracks current tags and digests to avoid redundant updates
- **Systemd Integration**: Native systemd service with automatic startup and logging
- **Security**: Dedicated user, minimal privileges, secure credential management
- **Health Checks**: Docker connectivity and service health monitoring
- **Production Ready**: Robust error handling, comprehensive logging, monitoring support

## Quick Start

### Automated Installation (Recommended)

1. **Clone and Install**:

```bash
git clone <repository-url>
cd watchdoc
sudo ./install.sh
```

> The systemd service runs as the non-root user that invoked `sudo ./install.sh`, so it inherits the same access to compose files, `.env`, and other resources.
> When Watchdoc rolls a compose service, it updates the discovered compose YAML with the new image tag before calling `docker compose`. You’ll see `.yaml` diffs reflecting each upgrade.

2. **Label Your Containers**:

```yaml
# docker-compose.yml
services:
  watchdoc-demo:
    image: nginx:latest
    labels:
      - "watchdoc.enable=true"
      # Optional registry hints, tag patterns, etc.
      # - "watchdoc.registry=ecr"
      # - "watchdoc.tag-pattern=staging-*"
```

3. **Start the Service**:

```bash
sudo systemctl enable watchdoc
sudo systemctl start watchdoc
sudo systemctl status watchdoc
```

### Manual Installation

1. **Install Dependencies**:

```bash
python3 -m venv watchdoc-env
source watchdoc-env/bin/activate
pip install -r requirements.txt
```

2. **Configure and Run**:

```bash
cat <<'EOF' > .env
LOG_LEVEL=INFO
AUTO_DISCOVERY=true
# Add registry credentials here if needed
EOF
python watchdoc.py
```

### Environment Variables (`/etc/watchdoc/.env`)

```bash
# AWS ECR Configuration
AWS_ACCESS_KEY_ID=your_access_key
AWS_SECRET_ACCESS_KEY=your_secret_key
AWS_DEFAULT_REGION=us-east-2

# Google Container Registry
GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
GCP_PROJECT_ID=your-project-id

# Docker Hub
DOCKER_HUB_USERNAME=your_username
DOCKER_HUB_PASSWORD=your_password

# Application Settings
LOG_LEVEL=INFO
CHECK_INTERVAL=30
```

`watchdoc_config.json` only controls global settings such as `check_interval`. You no longer need to list individual applications—labels on the containers themselves drive discovery.

## Service Management

### Method 1: Docker Compose (Recommended)
```bash
# 1. Update volume mounts in docker-compose.yml
# 2. Start the service
docker-compose up -d

# View logs
docker-compose logs -f
```

> Once the containers are running, Watchdoc automatically recognises them via Docker's compose labels and will run `docker compose up -d --no-deps <service>` after pulling a newer image. No manual file editing or sudo configuration required.

Watchdoc stores its Docker credentials under `/var/lib/watchdoc/docker-config` (override with `DOCKER_CONFIG`) so registry logins succeed even for non-root service accounts.

### Method 2: Systemd Service
```bash
# 1. Copy files to /opt/watchdoc
sudo cp -r . /opt/watchdoc

### Start/Stop Service

```bash
# Start service
sudo systemctl start watchdoc

# Stop service
sudo systemctl stop watchdoc

# Restart service
sudo systemctl restart watchdoc

# Enable auto-start on boot
sudo systemctl enable watchdoc
```

### Monitor Service

```bash
# Check service status
sudo systemctl status watchdoc

# View real-time logs
sudo journalctl -u watchdoc -f

# View recent logs
sudo journalctl -u watchdoc -n 50
```

### Test Configuration

```bash
# Test Docker access
sudo -u "$USER" docker ps

# Validate configuration
python3 -c "import json; print('Valid JSON' if json.load(open('/etc/watchdoc/watchdoc_config.json')) else 'Invalid')" 

# Test registry connectivity
sudo -u "$USER" python3 /opt/watchdoc/watchdoc.py --test
```

### Method 3: Direct Python Execution
```bash
# Install dependencies
pip install -r requirements.txt

# Run directly
python3 watchdoc.py
```

## Security Considerations

- **Docker Socket Access**: The updater requires access to the Docker socket
- **Non-root User**: Container runs as non-root user (UID 1000)
- **Read-only Mounts**: Configuration files are mounted read-only
- **Resource Limits**: Configure appropriate CPU/memory limits in production

## Monitoring and Logging

### Log Files

- `watchdoc.log`: Application logs
- `watchdoc_state.json`: Persistent state (image digests, last update times)

### Health Checks
The Docker container includes health checks that verify Docker connectivity.

### Monitoring Integration
The application logs structured information suitable for:
- Prometheus metrics collection
- ELK stack integration
- Grafana dashboards

## Advanced Configuration

### Customize Check Interval
`/etc/watchdoc/watchdoc_config.json`
```json
{
  "check_interval": 60
}
```

## Smart Tag Detection (Default)

Watchdoc analyses the tags that already exist in your registry and automatically chooses the freshest image when no tag-related labels are set:

- If tags follow semantic versioning, Watchdoc promotes the highest version.
- If tags share a prefix (e.g. `staging-abc123`), Watchdoc tracks the newest push that matches the current prefix.
- Otherwise, Watchdoc falls back to the image with the most recent push timestamp.

Add `watchdoc.tag-pattern` or `watchdoc.semver-pattern` only when you need to override this automatic behaviour.

## Advanced Features

### Dynamic Tag Patterns

Watchdoc auto-detects tag strategies (semver, prefix, or latest push) when no label is supplied. Add a label only when you need to pin the behaviour to a specific pattern:

```yaml
services:
  accounting:
    image: 285065797661.dkr.ecr.us-east-2.amazonaws.com/accounting:staging-abc123
    labels:
      - "watchdoc.enable=true"
      - "watchdoc.registry=ecr"
      - "watchdoc.ecr.region=us-east-2"
      - "watchdoc.tag-pattern=staging-*"
```

### Semantic Versioning Support

Watchdoc already detects semver tags automatically. Use the label below if you want to enforce a custom pattern (for example, ignore prerelease tags):

```yaml
services:
  release-api:
    image: myregistry/api:v1.2.3
    labels:
      - "watchdoc.enable=true"
      - "watchdoc.registry=ecr"
      - "watchdoc.semver-pattern=v*"
```

### Multi-Registry Support

- **Docker Hub**: Public and private repositories
- **AWS ECR**: With IAM role or access key authentication
- **Google Container Registry**: With service account authentication

### Health Checks

Built-in monitoring:

- Docker daemon connectivity
- Registry accessibility
- Service status verification

## Troubleshooting

### Common Issues

1. **Permission Denied on Docker Socket**
   ```bash
   # Add user to docker group
   sudo usermod -aG docker $USER
   ```

2. **Docker Compose Not Found**
   ```bash
   # Install docker-compose
   sudo curl -L "https://github.com/docker/compose/releases/download/v2.20.0/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
   sudo chmod +x /usr/local/bin/docker-compose
   ```

3. **Image Digest Not Found**

   - Ensure the image exists in the registry
   - Check network connectivity to the registry
   - Verify image tag is correct

### Debug Mode

Enable debug logging by modifying the logging level in `watchdoc.py`:

```python
logging.basicConfig(level=logging.DEBUG, ...)
```

## Production Deployment

### Resource Requirements
- **CPU**: 0.1-0.5 cores
- **Memory**: 128-512 MB
- **Storage**: 100 MB for logs and state

### Recommended Setup
1. Use Docker Compose with restart policies
2. Configure log rotation
3. Set up monitoring alerts
4. Regular backup of state files
5. Network isolation using Docker networks

### High Availability
For critical environments:
- Run multiple instances with different check intervals
- Use external state storage (Redis/Database)
- Implement leader election for coordination

## API Integration

The updater can be extended with a REST API for:
- Manual trigger updates
- Status monitoring
- Configuration management
- Webhook integration

## License

MIT License - see LICENSE file for details.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Add tests for new functionality
4. Submit a pull request

## Support

For issues and questions:
- Check the troubleshooting section
- Review application logs
- Open an issue with detailed information

---

## Label-Based Discovery Reference

### Overview

Watchdoc supports **automatic container discovery** using Docker labels. This eliminates the need to manually configure compose paths and avoids editing YAML files during updates.

### How It Works

1. Add labels to your services in `docker-compose.yml` or `compose.yml`.
2. Watchdoc automatically discovers and monitors these containers.
3. Updates happen via the Docker API or `docker compose` (no sudo required).
4. No static configuration files are needed.

### Examples

```yaml
version: '3.8'

services:
  my-app:
    image: nginx:latest
    labels:
      - "watchdoc.enable=true"
```

```yaml
services:
  accounting:
    image: 285065797661.dkr.ecr.us-east-2.amazonaws.com/accounting:staging-latest
    labels:
      - "watchdoc.enable=true"
      - "watchdoc.registry=ecr"
      - "watchdoc.ecr.region=us-east-2"
      - "watchdoc.ecr.access-key-id=${AWS_ACCESS_KEY_ID}"
      - "watchdoc.ecr.secret-access-key=${AWS_SECRET_ACCESS_KEY}"
```

### Labels

| Label | Description | Example |
|-------|-------------|---------|
| `watchdoc.enable` | Enable auto-update for this container | `true` |
| `watchdoc.registry` | Registry type (auto-detected from image host when omitted) | `docker_hub`, `ecr`, `gcr` |
| `.env` alongside compose files | Automatically merged for compose restarts | `DATABASE_URL=...` |
| `watchdoc.tag-pattern` | Override auto-detected prefixes | `staging-*` |
| `watchdoc.semver-pattern` | Override auto-detected semver | `v*` |
| `watchdoc.ecr.region` | AWS region | `us-east-2` |
| `watchdoc.ecr.access-key-id` | AWS access key | `${AWS_ACCESS_KEY_ID}` |
| `watchdoc.ecr.secret-access-key` | AWS secret key | `${AWS_SECRET_ACCESS_KEY}` |
| `watchdoc.gcr.project-id` | GCP project ID | `my-project` |
| `watchdoc.gcr.service-account-path` | Service account JSON path | `/path/to/sa.json` |
| `watchdoc.dockerhub.username` | Docker Hub username | `${DOCKER_HUB_USERNAME}` |
| `watchdoc.dockerhub.password` | Docker Hub password | `${DOCKER_HUB_PASSWORD}` |

> Leave tag-related labels blank to let Watchdoc auto-detect the smartest strategy. Registry type is inferred from the image host (e.g., `*.amazonaws.com` → ECR), and credentials fall back to environment variables in `/etc/watchdoc/.env` or instance metadata if not provided via labels.

### Troubleshooting

- Inspect labels: `docker inspect <container> | grep -A 10 Labels`
- Verify container is running: `docker ps | grep <container>`
- Confirm auto-discovery: `grep AUTO_DISCOVERY /etc/watchdoc/.env`


## Dynamic Tag Patterns Deep Dive

Watchdoc analyses the tags already present in your registry and automatically chooses the freshest image.

1. Labels enable the container and provide any registry credentials.
2. Each scan downloads tag metadata (semver, prefix-based, or push timestamp).
3. When a newer tag is detected, Watchdoc pulls the image and restarts the service.

```yaml
services:
  accounting:
    image: 285065797661.dkr.ecr.us-east-2.amazonaws.com/accounting:staging-latest
    labels:
      - "watchdoc.enable=true"
      - "watchdoc.registry=ecr"
      - "watchdoc.ecr.region=us-east-2"
      - "watchdoc.ecr.access-key-id=${AWS_ACCESS_KEY_ID}"
      - "watchdoc.ecr.secret-access-key=${AWS_SECRET_ACCESS_KEY}"
```

Need tighter control? Add `watchdoc.tag-pattern` or `watchdoc.semver-pattern` to pin the behaviour.

**Logging cues**

```
INFO - Auto-detected latest tag for accounting: staging-a1b2c3d (strategy: prefix:staging-)
INFO - Pulling image: 285065797661.dkr.ecr.us-east-2.amazonaws.com/accounting:staging-a1b2c3d
INFO - Restarting compose service accounting (project: accounting)
INFO - Successfully refreshed compose service: accounting
```

**Common hiccups**

- `WARNING - No tags found ...` → verify the repository contains matching tags.
- `ERROR - Failed to authenticate ...` → check credentials/region labels.
- `ERROR - docker compose failed ...` → confirm labels include compose metadata and the files are accessible.


## Registry Setup Reference

### AWS ECR

1. `aws ecr create-repository --repository-name my-app --region us-east-1`
2. Grant permissions using `ecr:GetAuthorizationToken`, `ecr:DescribeImages`, etc.
3. Labels:
   ```yaml
   labels:
     - "watchdoc.enable=true"
     - "watchdoc.registry=ecr"
     - "watchdoc.ecr.region=us-east-1"
     - "watchdoc.ecr.access-key-id=${AWS_ACCESS_KEY_ID}"   # optional with IAM role
     - "watchdoc.ecr.secret-access-key=${AWS_SECRET_ACCESS_KEY}" # optional
   ```
4. Optional env vars: export `AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`, `AWS_DEFAULT_REGION`.

### Google Container Registry / Artifact Registry

1. `gcloud services enable containerregistry.googleapis.com`
2. Create a service account and key.
3. Labels:
   ```yaml
   labels:
     - "watchdoc.enable=true"
     - "watchdoc.registry=gcr"
     - "watchdoc.gcr.project-id=YOUR_PROJECT_ID"
     - "watchdoc.gcr.service-account-path=/secrets/watchdoc-key.json"
   ```
4. Optional env vars: `GOOGLE_APPLICATION_CREDENTIALS`, `GOOGLE_CLOUD_PROJECT`.

### Docker Hub (private)

1. Create a read-only access token.
2. Labels:
   ```yaml
   labels:
     - "watchdoc.enable=true"
     - "watchdoc.registry=docker_hub"
     - "watchdoc.dockerhub.username=${DOCKER_HUB_USERNAME}"
     - "watchdoc.dockerhub.password=${DOCKER_HUB_TOKEN}"
   ```
3. Optional env vars: `DOCKER_HUB_USERNAME`, `DOCKER_HUB_TOKEN`.

| Registry | Label | Env fallback |
|----------|-------|--------------|
| ECR | `watchdoc.ecr.access-key-id` | `AWS_ACCESS_KEY_ID` |
| ECR | `watchdoc.ecr.secret-access-key` | `AWS_SECRET_ACCESS_KEY` |
| ECR | `watchdoc.ecr.region` | `AWS_DEFAULT_REGION` |
| GCR | `watchdoc.gcr.service-account-path` | `GOOGLE_APPLICATION_CREDENTIALS` |
| GCR | `watchdoc.gcr.project-id` | `GOOGLE_CLOUD_PROJECT` |
| Docker Hub | `watchdoc.dockerhub.username` | `DOCKER_HUB_USERNAME` |
| Docker Hub | `watchdoc.dockerhub.password` | `DOCKER_HUB_PASSWORD` / `DOCKER_HUB_TOKEN` |


## Quick Fix Playbook

**Problem:** `sudo: a password is required` when updating compose-managed services.

**Solution:** Add Watchdoc labels, keep compose metadata intact, and let Watchdoc run `docker compose up -d --no-deps <service>` automatically.

```yaml
services:
  accounting:
    image: 285065797661.dkr.ecr.us-east-2.amazonaws.com/accounting:staging-latest
    labels:
      - "watchdoc.enable=true"
      - "watchdoc.registry=ecr"
      - "watchdoc.tag-pattern=staging-*"  # Optional override
      - "watchdoc.ecr.region=us-east-2"
      - "watchdoc.ecr.access-key-id=${AWS_ACCESS_KEY_ID}"
      - "watchdoc.ecr.secret-access-key=${AWS_SECRET_ACCESS_KEY}"
```

> Skip `watchdoc.tag-pattern` if Watchdoc’s automatic tag detection works for you.

**After updating labels:**

```bash
docker-compose up -d
sudo systemctl restart watchdoc
sudo journalctl -u watchdoc -f
```

You should see messages about auto-discovery and compose restarts instead of permission errors.

**Optional cleanup:**

- Remove legacy entries from `/etc/watchdoc/watchdoc_config.json` (only `check_interval` is required).
- Toggle discovery via `/etc/watchdoc/.env` if needed (`AUTO_DISCOVERY=false`).
