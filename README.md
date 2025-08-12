# Docker Auto-Updater

A production-ready Docker container auto-updater that runs on the host system and monitors multiple registries (Docker Hub, AWS ECR, Google Container Registry) for image updates. Automatically restarts services using docker-compose with support for dynamic tag patterns, semantic versioning, and comprehensive logging.

## Features

- **Multi-Registry Support**: Docker Hub, AWS ECR, Google Container Registry
- **Dynamic Tag Patterns**: Support for `staging-*`, `prod-*` style tags with automatic latest selection  
- **Semantic Versioning**: Intelligent semver parsing and comparison (`v1.2.3`, `release-2.0.0`)
- **Automatic Service Restart**: Updates docker-compose files and restarts services
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
cd docker-auto-updater
sudo ./install.sh
```

2. **Configure Services**:

```bash
sudo nano /etc/docker-updater/updater_config.json
sudo nano /etc/docker-updater/.env
```

3. **Start the Service**:

```bash
sudo systemctl enable docker-updater
sudo systemctl start docker-updater
sudo systemctl status docker-updater
```

### Manual Installation

1. **Install Dependencies**:

```bash
python3 -m venv docker-updater-env
source docker-updater-env/bin/activate
pip install -r requirements.txt
```

2. **Configure and Run**:

```bash
cp .env.example .env
cp updater_config.json /path/to/config/
# Edit configuration files
python docker_updater.py
```

## Configuration

### Service Configuration (`/etc/docker-updater/updater_config.json`)

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
      "name": "api-service",
      "image": "285065797661.dkr.ecr.us-east-2.amazonaws.com/api:staging-abc123",
      "compose_file": "/opt/apps/api/docker-compose.yml",
      "compose_service": "api",
      "registry_type": "ecr",
      "tag_pattern": "staging-*",
      "registry_config": {
        "region": "us-east-2"
      }
    },
    {
      "name": "release-app",
      "image": "285065797661.dkr.ecr.us-east-2.amazonaws.com/app:v1.2.3",
      "compose_file": "/opt/apps/release-app/docker-compose.yml",
      "compose_service": "app",
      "registry_type": "ecr",
      "semver_pattern": "v*",
      "registry_config": {
        "region": "us-east-2"
      }
    }
  ]
}
```

### Environment Variables (`/etc/docker-updater/.env`)

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

## Service Management

### Method 1: Docker Compose (Recommended)
```bash
# 1. Update volume mounts in docker-compose.yml
# 2. Start the service
docker-compose up -d

# View logs
docker-compose logs -f
```

### Method 2: Systemd Service
```bash
# 1. Copy files to /opt/docker-auto-updater
sudo cp -r . /opt/docker-auto-updater

### Start/Stop Service

```bash
# Start service
sudo systemctl start docker-updater

# Stop service
sudo systemctl stop docker-updater

# Restart service
sudo systemctl restart docker-updater

# Enable auto-start on boot
sudo systemctl enable docker-updater
```

### Monitor Service

```bash
# Check service status
sudo systemctl status docker-updater

# View real-time logs
sudo journalctl -u docker-updater -f

# View recent logs
sudo journalctl -u docker-updater -n 50
```

### Test Configuration

```bash
# Test Docker access
sudo -u docker-updater docker ps

# Validate configuration
python3 -c "import json; print('Valid JSON' if json.load(open('/etc/docker-updater/updater_config.json')) else 'Invalid')" 

# Test registry connectivity
sudo -u docker-updater python3 /opt/docker-updater/docker_updater.py --test
```

### Method 3: Direct Python Execution
```bash
# Install dependencies
pip install -r requirements.txt

# Run directly
python3 docker_updater.py
```

## Security Considerations

- **Docker Socket Access**: The updater requires access to the Docker socket
- **Non-root User**: Container runs as non-root user (UID 1000)
- **Read-only Mounts**: Configuration files are mounted read-only
- **Resource Limits**: Configure appropriate CPU/memory limits in production

## Monitoring and Logging

### Log Files

- `docker_updater.log`: Application logs
- `updater_state.json`: Persistent state (image digests, last update times)

### Health Checks
The Docker container includes health checks that verify Docker connectivity.

### Monitoring Integration
The application logs structured information suitable for:
- Prometheus metrics collection
- ELK stack integration
- Grafana dashboards

## Advanced Configuration

### Custom Check Intervals
```json
{
  "check_interval": 60,  // Check every 60 seconds
  "services": [...]
}
```

### Multiple Compose Files
```json
{
  "services": [
    {
      "name": "frontend",
      "image": "myapp/frontend:latest",
      "compose_file": "/apps/frontend/docker-compose.yml",
      "compose_service": "web"
    },
    {
      "name": "backend",
      "image": "myapp/backend:latest", 
      "compose_file": "/apps/backend/docker-compose.yml",
      "compose_service": "api"
    }
  ]
}
```

## Advanced Features

### Dynamic Tag Patterns

Automatically update to the latest tag matching a pattern:

```json
{
  "name": "staging-app",
  "image": "myregistry/app:staging-abc123",
  "tag_pattern": "staging-*",
  "registry_type": "ecr"
}
```

### Semantic Versioning Support

Intelligently update to the latest semantic version:

```json
{
  "name": "release-app", 
  "image": "myregistry/app:v1.2.3",
  "semver_pattern": "v*",
  "registry_type": "ecr"
}
```

### Multi-Registry Support

- **Docker Hub**: Public and private repositories
- **AWS ECR**: With IAM role or access key authentication
- **Google Container Registry**: With service account authentication

### Health Checks

Built-in monitoring:

- Docker daemon connectivity
- Registry accessibility
- Compose file validation
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

Enable debug logging by modifying the logging level in `docker_updater.py`:

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
