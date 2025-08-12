#!/bin/bash

# Quick Install Script for Docker Auto-Updater
# This bypasses the directory detection issue

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Docker Auto-Updater Quick Install${NC}"
echo "=================================="

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Please run: sudo ./quick_install.sh"
    exit 1
fi

# Variables
SERVICE_USER="docker-updater"
SERVICE_GROUP="docker-updater"
INSTALL_DIR="/opt/docker-auto-updater"
CONFIG_DIR="/etc/docker-auto-updater"
STATE_DIR="/var/lib/docker-auto-updater"
LOG_DIR="/var/log/docker-auto-updater"

# Get current directory (where script is run from)
CURRENT_DIR="$(pwd)"
echo "Installing from: $CURRENT_DIR"

# Verify required files exist
echo -e "${YELLOW}Checking required files...${NC}"
REQUIRED_FILES=("docker_updater.py" "updater_config.json" "docker-updater.service" "docker-updater-sudoers" "requirements.txt")

for file in "${REQUIRED_FILES[@]}"; do
    if [ ! -f "$CURRENT_DIR/$file" ]; then
        echo -e "${RED}Error: Required file $file not found in current directory${NC}"
        echo "Current directory: $CURRENT_DIR"
        echo "Files present:"
        ls -la "$CURRENT_DIR"
        exit 1
    fi
    echo "✅ Found: $file"
done

# Create directories
echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR"

# Create user and group
echo -e "${YELLOW}Creating service user...${NC}"
if ! id "$SERVICE_USER" &>/dev/null; then
    useradd -r -s /bin/false -d "$INSTALL_DIR" "$SERVICE_USER"
    echo "Created user: $SERVICE_USER"
else
    echo "User $SERVICE_USER already exists"
fi

# Add user to docker group
if getent group docker > /dev/null 2>&1; then
    usermod -a -G docker "$SERVICE_USER"
    echo "Added $SERVICE_USER to docker group"
fi

# Copy files
echo -e "${YELLOW}Copying files...${NC}"
cp "$CURRENT_DIR/docker_updater.py" "$INSTALL_DIR/"
cp "$CURRENT_DIR/requirements.txt" "$INSTALL_DIR/"
cp "$CURRENT_DIR/updater_config.json" "$CONFIG_DIR/"
cp "$CURRENT_DIR/docker-updater.service" /etc/systemd/system/
echo "✅ Application files copied"

# Handle environment file
if [ -f "$CURRENT_DIR/.env.example" ]; then
    cp "$CURRENT_DIR/.env.example" "$CONFIG_DIR/.env"
    echo "✅ Environment template copied"
else
    echo -e "${YELLOW}Creating default environment file...${NC}"
    cat > "$CONFIG_DIR/.env" << 'EOF'
# Docker Auto-Updater Environment Configuration

# Logging Configuration
LOG_LEVEL=INFO

# Update Check Interval (seconds)
CHECK_INTERVAL=3600

# AWS Configuration (if using ECR)
#AWS_ACCESS_KEY_ID=your_access_key
#AWS_SECRET_ACCESS_KEY=your_secret_key
#AWS_DEFAULT_REGION=us-west-2

# Google Cloud Configuration (if using GCR)
#GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
#GCP_PROJECT_ID=your-project-id

# Docker Hub Configuration (if using private repos)
#DOCKER_HUB_USERNAME=your_username
#DOCKER_HUB_PASSWORD=your_password
EOF
    echo "✅ Default environment file created"
fi

# Install sudoers configuration
echo -e "${YELLOW}Configuring sudo permissions...${NC}"
if visudo -c -f "$CURRENT_DIR/docker-updater-sudoers" >/dev/null 2>&1; then
    cp "$CURRENT_DIR/docker-updater-sudoers" /etc/sudoers.d/docker-updater
    chmod 440 /etc/sudoers.d/docker-updater
    echo "✅ Sudoers configuration installed"
else
    echo -e "${YELLOW}Warning: Creating basic sudoers configuration...${NC}"
    cat > /etc/sudoers.d/docker-updater << 'EOF'
# Docker Auto-Updater Sudoers Configuration
docker-updater ALL=(root) NOPASSWD: /usr/local/bin/docker-compose
docker-updater ALL=(root) NOPASSWD: /usr/bin/docker-compose
docker-updater ALL=(root) NOPASSWD: /bin/docker-compose
docker-updater ALL=(root) NOPASSWD: /usr/bin/docker
docker-updater ALL=(root) NOPASSWD: /bin/cp
EOF
    chmod 440 /etc/sudoers.d/docker-updater
    echo "✅ Basic sudoers configuration created"
fi

# Set permissions
echo -e "${YELLOW}Setting permissions...${NC}"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chown -R "$SERVICE_USER:docker" "$CONFIG_DIR"
chown -R "$SERVICE_USER:docker" "$STATE_DIR"
chown -R "$SERVICE_USER:docker" "$LOG_DIR"

chmod 600 "$CONFIG_DIR/.env"
chmod 644 "$CONFIG_DIR/updater_config.json"
chmod 755 "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR"

# Install Python dependencies
echo -e "${YELLOW}Installing Python dependencies...${NC}"
if command -v pip3 >/dev/null 2>&1; then
    pip3 install -r "$INSTALL_DIR/requirements.txt"
    echo "✅ Python dependencies installed"
else
    echo -e "${YELLOW}Warning: pip3 not found, please install Python dependencies manually${NC}"
fi

# Install and start systemd service
echo -e "${YELLOW}Installing systemd service...${NC}"
systemctl daemon-reload
systemctl enable docker-updater
echo "✅ Service enabled"

# Test configuration
echo -e "${YELLOW}Testing configuration...${NC}"
if sudo -u "$SERVICE_USER" docker version >/dev/null 2>&1; then
    echo "✅ Docker access test passed"
else
    echo -e "${YELLOW}Warning: Docker access test failed - may need manual configuration${NC}"
fi

# Start service
echo -e "${YELLOW}Starting service...${NC}"
systemctl start docker-updater

# Show status
echo -e "${GREEN}Installation Complete!${NC}"
echo "=================================="
echo "Service status:"
systemctl status docker-updater --no-pager -l

echo ""
echo -e "${GREEN}Next steps:${NC}"
echo "1. Edit $CONFIG_DIR/.env with your credentials"
echo "2. Edit $CONFIG_DIR/updater_config.json to configure your services"
echo "3. Check logs: journalctl -u docker-updater -f"
echo "4. Restart service after config changes: systemctl restart docker-updater"
