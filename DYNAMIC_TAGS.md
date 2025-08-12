# Dynamic Tag Pattern Support

The Docker Auto-Updater now supports dynamic tag patterns for ECR repositories, perfect for CI/CD workflows that generate tags like `staging-f930fb4`, `prod-f930921`, etc.

## How It Works

### Tag Pattern Detection

- Uses AWS ECR API to list all tags in a repository
- Filters tags matching your specified pattern (e.g., `staging-*`)
- Sorts by push date to find the newest image
- Automatically updates your docker-compose file with the latest tag

### Configuration Example

```json
{
  "name": "accounting-staging",
  "image": "285065797661.dkr.ecr.us-east-2.amazonaws.com/accounting:staging-f930fb4",
  "compose_file": "/apps/accounting/docker-compose.yml",
  "compose_service": "app",
  "registry_type": "ecr",
  "tag_pattern": "staging-*",
  "registry_config": {
    "region": "us-east-2"
  }
}
```

## Key Features

### Automatic Tag Discovery

- Scans ECR repository for tags matching pattern
- Identifies newest image by push timestamp
- Handles multiple environments (staging, prod, dev)

### Smart Updates

- Only updates when a newer tag is found
- Updates docker-compose.yml automatically
- Restarts services with zero-downtime rolling updates

### State Tracking

- Remembers current tag to avoid unnecessary updates
- Persists state across restarts
- Logs all tag changes for audit trail

## Supported Tag Patterns

### Environment-Based Tags

```text
staging-*     → staging-f930fb4, staging-a1b2c3d
prod-*        → prod-f930fb4, prod-a1b2c3d
dev-*         → dev-f930fb4, dev-a1b2c3d
```

### Version-Based Tags

```text
v1.*          → v1.0.1, v1.0.2, v1.1.0
release-*     → release-2024.1, release-2024.2
```

### Custom Patterns

```text
feature-*     → feature-auth, feature-payments
hotfix-*      → hotfix-security, hotfix-bug123
```

## Example Workflow

1. **CI/CD Pipeline** pushes new image:
   ```text
   285065797661.dkr.ecr.us-east-2.amazonaws.com/accounting:staging-a1b2c3d
   ```

2. **Auto-Updater** detects new tag (every 30 seconds)

3. **Updates docker-compose.yml**:
   ```yaml
   services:
     app:
       image: 285065797661.dkr.ecr.us-east-2.amazonaws.com/accounting:staging-a1b2c3d
   ```

4. **Restarts service** with new image

## Configuration Details

### Required Fields
- `tag_pattern`: Pattern to match (e.g., "staging-*")
- `registry_type`: Must be "ecr" for dynamic tags
- `image`: Base image URL with any tag (will be updated)

### Optional Fields
- `registry_config`: AWS credentials (uses IAM role if not provided)

## Logging and Monitoring

### Log Messages
```
INFO - Found latest tag for pattern 'staging-*': staging-a1b2c3d
INFO - New tag detected for accounting-staging: staging-a1b2c3d
INFO - Updated app image to: 285065797661.dkr.ecr.us-east-2.amazonaws.com/accounting:staging-a1b2c3d
INFO - Successfully restarted service: accounting-staging
```

### State Persistence
```json
{
  "services": [
    {
      "name": "accounting-staging",
      "current_tag": "staging-a1b2c3d",
      "current_digest": "sha256:abc123...",
      "last_updated": "2024-01-15T10:30:00"
    }
  ]
}
```

## Security Considerations

### IAM Permissions
Required ECR permissions:
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

### Best Practices
- Use IAM roles instead of access keys when possible
- Limit ECR permissions to specific repositories
- Monitor update logs for security auditing
- Use separate patterns for different environments

## Troubleshooting

### Common Issues

**No tags found matching pattern**
```
WARNING - No tags found matching pattern 'staging-*' for accounting-staging
```
- Verify the tag pattern syntax
- Check if images exist in ECR repository
- Ensure AWS credentials have ECR permissions

**Failed to update compose file**
```
ERROR - Failed to update compose file: [Errno 2] No such file or directory
```
- Verify docker-compose.yml path is correct
- Ensure file permissions allow writing
- Check if service name exists in compose file

**Authentication failures**
```
ERROR - ECR authentication error: Unable to locate credentials
```
- Set AWS credentials in environment variables
- Use IAM roles for EC2/ECS deployments
- Verify region configuration

## Performance Optimization

### Caching Strategy
- ECR API calls are made only when checking for updates
- Results cached between update cycles
- Minimal impact on ECR API rate limits

### Resource Usage
- Low memory footprint (~50MB)
- Minimal CPU usage during checks
- Network usage only for ECR API calls

This dynamic tag support makes the Docker Auto-Updater perfect for modern CI/CD workflows where image tags change frequently based on git commits or build numbers.
