# Registry Setup Guide

This guide explains how to configure the Docker Auto-Updater with AWS ECR, Google Container Registry, and Docker Hub.

## AWS ECR Setup

### 1. Create ECR Repository
```bash
aws ecr create-repository --repository-name my-app --region us-east-1
```

### 2. Configure IAM Permissions
Create an IAM user with the following policy:
```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "ecr:GetAuthorizationToken",
                "ecr:BatchCheckLayerAvailability",
                "ecr:GetDownloadUrlForLayer",
                "ecr:BatchGetImage",
                "ecr:DescribeRepositories",
                "ecr:DescribeImages"
            ],
            "Resource": "*"
        }
    ]
}
```

### 3. Configuration Example
```json
{
  "name": "my-ecr-app",
  "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-app:latest",
  "compose_file": "/path/to/docker-compose.yml",
  "compose_service": "app",
  "registry_type": "ecr",
  "registry_config": {
    "region": "us-east-1",
    "aws_access_key_id": "${AWS_ACCESS_KEY_ID}",
    "aws_secret_access_key": "${AWS_SECRET_ACCESS_KEY}"
  }
}
```

### 4. Environment Variables
```bash
export AWS_ACCESS_KEY_ID=your_access_key
export AWS_SECRET_ACCESS_KEY=your_secret_key
export AWS_DEFAULT_REGION=us-east-1
```

## Google Container Registry Setup

### 1. Enable Container Registry API
```bash
gcloud services enable containerregistry.googleapis.com
```

### 2. Create Service Account
```bash
gcloud iam service-accounts create docker-updater \
    --description="Docker Auto-Updater Service Account" \
    --display-name="Docker Updater"

gcloud projects add-iam-policy-binding YOUR_PROJECT_ID \
    --member="serviceAccount:docker-updater@YOUR_PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/storage.objectViewer"

gcloud iam service-accounts keys create ~/docker-updater-key.json \
    --iam-account=docker-updater@YOUR_PROJECT_ID.iam.gserviceaccount.com
```

### 3. Configuration Example
```json
{
  "name": "my-gcr-app",
  "image": "gcr.io/my-project/my-app:latest",
  "compose_file": "/path/to/docker-compose.yml",
  "compose_service": "app",
  "registry_type": "gcr",
  "registry_config": {
    "project_id": "my-project",
    "service_account_path": "/path/to/service-account.json"
  }
}
```

### 4. Environment Variables
```bash
export GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
export GOOGLE_CLOUD_PROJECT=your-project-id
```

## Docker Hub Private Repository Setup

### 1. Create Access Token
1. Go to Docker Hub → Account Settings → Security
2. Create a new access token with read permissions
3. Use the token as password

### 2. Configuration Example
```json
{
  "name": "my-private-app",
  "image": "mycompany/private-app:latest",
  "compose_file": "/path/to/docker-compose.yml",
  "compose_service": "app",
  "registry_type": "docker_hub",
  "registry_config": {
    "username": "${DOCKER_HUB_USERNAME}",
    "password": "${DOCKER_HUB_TOKEN}"
  }
}
```

### 3. Environment Variables
```bash
export DOCKER_HUB_USERNAME=your_username
export DOCKER_HUB_TOKEN=your_access_token
```

## Complete Configuration Example

```json
{
  "check_interval": 30,
  "services": [
    {
      "name": "public-nginx",
      "image": "nginx:latest",
      "compose_file": "/apps/nginx/docker-compose.yml",
      "compose_service": "web",
      "registry_type": "docker_hub"
    },
    {
      "name": "ecr-backend",
      "image": "123456789012.dkr.ecr.us-east-1.amazonaws.com/backend:production",
      "compose_file": "/apps/backend/docker-compose.yml",
      "compose_service": "api",
      "registry_type": "ecr",
      "registry_config": {
        "region": "us-east-1"
      }
    },
    {
      "name": "gcr-frontend",
      "image": "gcr.io/my-project/frontend:latest",
      "compose_file": "/apps/frontend/docker-compose.yml",
      "compose_service": "web",
      "registry_type": "gcr",
      "registry_config": {
        "project_id": "my-project"
      }
    },
    {
      "name": "private-microservice",
      "image": "mycompany/microservice:stable",
      "compose_file": "/apps/microservice/docker-compose.yml",
      "compose_service": "service",
      "registry_type": "docker_hub",
      "registry_config": {
        "username": "${DOCKER_HUB_USERNAME}",
        "password": "${DOCKER_HUB_TOKEN}"
      }
    }
  ]
}
```

## Security Best Practices

### 1. Use IAM Roles (Recommended for AWS)
Instead of access keys, use IAM roles when running on EC2:
```json
{
  "registry_config": {
    "region": "us-east-1"
  }
}
```

### 2. Use Workload Identity (Recommended for GCP)
When running on GKE, use Workload Identity instead of service account keys.

### 3. Environment Variable Substitution
The updater supports environment variable substitution in configuration:
```json
{
  "registry_config": {
    "aws_access_key_id": "${AWS_ACCESS_KEY_ID}",
    "aws_secret_access_key": "${AWS_SECRET_ACCESS_KEY}"
  }
}
```

### 4. Secrets Management
For production deployments, use:
- AWS Secrets Manager
- Google Secret Manager
- Kubernetes Secrets
- HashiCorp Vault

## Troubleshooting

### ECR Authentication Issues
```bash
# Test ECR authentication manually
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com
```

### GCR Authentication Issues
```bash
# Test GCR authentication manually
gcloud auth configure-docker
docker pull gcr.io/my-project/my-app:latest
```

### Docker Hub Rate Limits
- Use authentication to increase rate limits
- Consider using Docker Hub Pro/Team accounts
- Implement retry logic with exponential backoff

## Monitoring and Alerts

### CloudWatch Integration (AWS)
```python
# Add to docker_updater.py for CloudWatch metrics
import boto3

cloudwatch = boto3.client('cloudwatch')
cloudwatch.put_metric_data(
    Namespace='DockerUpdater',
    MetricData=[
        {
            'MetricName': 'UpdatesPerformed',
            'Value': 1,
            'Unit': 'Count'
        }
    ]
)
```

### Stackdriver Integration (GCP)
```python
# Add to docker_updater.py for Stackdriver metrics
from google.cloud import monitoring_v3

client = monitoring_v3.MetricServiceClient()
project_name = f"projects/{project_id}"
```

This setup ensures your Docker Auto-Updater works seamlessly with all major container registries while maintaining security best practices.
