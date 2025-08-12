#!/bin/bash

# Docker Auto-Updater Installation Script
# Compatible with Ubuntu, Debian, Alpine, CentOS, RHEL, and other Linux distributions
# This script sets up the Docker Auto-Updater for host-based deployment

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_DIR="/opt/docker-updater"
CONFIG_DIR="/etc/docker-updater"
STATE_DIR="/var/lib/docker-updater"
SERVICE_USER="docker-updater"

# Detect OS and distribution
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        DISTRO=$ID
        VERSION=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        DISTRO=$(echo "$OS" | tr '[:upper:]' '[:lower:]')
        VERSION=$(lsb_release -sr)
    elif [ -f /etc/redhat-release ]; then
        OS=$(cat /etc/redhat-release | cut -d' ' -f1)
        DISTRO="rhel"
    else
        OS=$(uname -s)
        DISTRO="unknown"
    fi
}

# Install dependencies based on distribution
install_dependencies() {
    echo -e "${YELLOW}Installing system dependencies...${NC}"
    
    case "$DISTRO" in
        ubuntu|debian)
            apt-get update
            apt-get install -y python3 python3-pip python3-venv curl
            ;;
        alpine)
            apk update
            apk add --no-cache python3 py3-pip python3-dev build-base curl
            ;;
        centos|rhel|fedora)
            if command -v dnf &> /dev/null; then
                dnf install -y python3 python3-pip python3-venv curl
            else
                yum install -y python3 python3-pip curl
            fi
            ;;
        arch)
            pacman -Sy --noconfirm python python-pip curl
            ;;
        *)
            echo -e "${YELLOW}Unknown distribution. Assuming dependencies are installed.${NC}"
            ;;
    esac
}

# Create user with distribution-specific options
create_service_user() {
    echo -e "${YELLOW}Creating service user...${NC}"
    
    if ! id "$SERVICE_USER" &>/dev/null; then
        case "$DISTRO" in
            alpine)
                adduser -r -s /bin/false -h $INSTALL_DIR -D $SERVICE_USER
                ;;
            *)
                useradd -r -s /bin/false -d $INSTALL_DIR $SERVICE_USER 2>/dev/null || \
                useradd -r -s /sbin/nologin -d $INSTALL_DIR $SERVICE_USER
                ;;
        esac
        echo "Created user: $SERVICE_USER"
    else
        echo "User $SERVICE_USER already exists"
    fi
}

echo -e "${GREEN}Docker Auto-Updater Installation${NC}"
echo "=================================="

# Detect operating system
detect_os
echo -e "${BLUE}Detected OS: $OS ($DISTRO $VERSION)${NC}"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
   echo -e "${RED}This script must be run as root${NC}"
   exit 1
fi

# Install system dependencies
install_dependencies

# Check if Docker is installed
if ! command -v docker >/dev/null 2>&1; then
    echo -e "${RED}Docker is not installed. Please install Docker first.${NC}"
    echo -e "${BLUE}Installation guides:${NC}"
    echo "  Ubuntu/Debian: https://docs.docker.com/engine/install/ubuntu/"
    echo "  Alpine: https://wiki.alpinelinux.org/wiki/Docker"
    echo "  CentOS/RHEL: https://docs.docker.com/engine/install/centos/"
    exit 1
fi

# Check if docker-compose is installed
if ! command -v docker-compose >/dev/null 2>&1; then
    echo -e "${YELLOW}docker-compose not found. Installing...${NC}"
    
    case "$DISTRO" in
        ubuntu|debian)
            apt-get install -y docker-compose-plugin || {
                curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
                chmod +x /usr/local/bin/docker-compose
            }
            ;;
        alpine)
            apk add --no-cache docker-compose || {
                curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
                chmod +x /usr/local/bin/docker-compose
            }
            ;;
        *)
            curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
            chmod +x /usr/local/bin/docker-compose
            ;;
    esac
fi

# Verify Python 3 installation
if ! command -v python3 >/dev/null 2>&1; then
    echo -e "${RED}Python 3 installation failed. Please install Python 3 manually.${NC}"
    exit 1
fi

echo -e "${YELLOW}Creating directories...${NC}"
mkdir -p "$INSTALL_DIR"
mkdir -p "$CONFIG_DIR"
mkdir -p "$STATE_DIR"

# Create service user
create_service_user

# Add user to docker group (create group if it doesn't exist)
if ! getent group docker >/dev/null 2>&1; then
    echo -e "${YELLOW}Creating docker group...${NC}"
    case "$DISTRO" in
        alpine)
            addgroup docker
            ;;
        *)
            groupadd docker
            ;;
    esac
fi

echo -e "${YELLOW}Adding user to docker group...${NC}"
case "$DISTRO" in
    alpine)
        addgroup "$SERVICE_USER" docker
        ;;
    *)
        usermod -aG docker "$SERVICE_USER"
        ;;
esac

echo -e "${YELLOW}Copying application files...${NC}"
if [ ! -f "docker_updater.py" ]; then
    echo -e "${RED}Error: docker_updater.py not found in current directory${NC}"
    exit 1
fi

if [ ! -f "requirements.txt" ]; then
    echo -e "${RED}Error: requirements.txt not found in current directory${NC}"
    exit 1
fi

cp docker_updater.py "$INSTALL_DIR/"
cp requirements.txt "$INSTALL_DIR/"

echo -e "${YELLOW}Setting up Python virtual environment...${NC}"
cd "$INSTALL_DIR"

# Create virtual environment with distribution-specific handling
case "$DISTRO" in
    alpine)
        python3 -m venv docker-updater-env --system-site-packages
        ;;
    *)
        python3 -m venv docker-updater-env
        ;;
esac

# Activate virtual environment and install dependencies
if [ -f "docker-updater-env/bin/activate" ]; then
    . docker-updater-env/bin/activate
    
    # Upgrade pip
    python -m pip install --upgrade pip
    
    # Install requirements with error handling
    if ! python -m pip install -r requirements.txt; then
        echo -e "${RED}Failed to install Python dependencies${NC}"
        exit 1
    fi
    
    deactivate
else
    echo -e "${RED}Failed to create Python virtual environment${NC}"
    exit 1
fi

echo -e "${YELLOW}Copying configuration files...${NC}"

# Store the original directory where script was run
SCRIPT_SOURCE_DIR="$(pwd)"
echo "Script source directory: $SCRIPT_SOURCE_DIR"

# Check for required configuration file in source directory
if [ ! -f "$SCRIPT_SOURCE_DIR/updater_config.json" ]; then
    echo -e "${RED}Error: updater_config.json not found in source directory${NC}"
    echo "Source directory: $SCRIPT_SOURCE_DIR"
    echo "Files in source directory:"
    ls -la "$SCRIPT_SOURCE_DIR"
    echo "Please ensure you're running the installer from the docker-auto-updater directory"
    exit 1
fi

echo "✅ Found configuration files in source directory"

# Copy main configuration
if [ ! -f "$CONFIG_DIR/updater_config.json" ]; then
    cp "$SCRIPT_SOURCE_DIR/updater_config.json" "$CONFIG_DIR/"
    echo "Copied default configuration"
else
    echo "Configuration file already exists, skipping..."
fi

# Handle environment file (create if missing)
if [ ! -f "$CONFIG_DIR/.env" ]; then
    if [ -f "$SCRIPT_SOURCE_DIR/.env.example" ]; then
        cp "$SCRIPT_SOURCE_DIR/.env.example" "$CONFIG_DIR/.env"
        echo "Copied environment template"
    else
        echo -e "${YELLOW}Warning: .env.example not found, creating default environment file...${NC}"
        cat > "$CONFIG_DIR/.env" << 'EOF'
# Docker Auto-Updater Environment Configuration

# Logging
LOG_LEVEL=INFO

# AWS ECR Configuration (if using ECR)
#AWS_ACCESS_KEY_ID=your_access_key
#AWS_SECRET_ACCESS_KEY=your_secret_key
#AWS_DEFAULT_REGION=us-east-1

# Google Cloud Configuration (if using GCR)
#GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
#GCP_PROJECT_ID=your-project-id

# Docker Hub Configuration (if using private repos)
#DOCKER_HUB_USERNAME=your_username
#DOCKER_HUB_PASSWORD=your_password
EOF
        echo "Created default environment file"
    fi
else
    echo "Environment file already exists, skipping..."
fi

echo -e "${YELLOW}Copying application files...${NC}"

# Copy main script
cp "$SCRIPT_SOURCE_DIR/docker_updater.py" "$INSTALL_DIR/"

# Copy requirements file
cp "$SCRIPT_SOURCE_DIR/requirements.txt" "$INSTALL_DIR/"

echo -e "${YELLOW}Setting permissions...${NC}"
chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
chown -R "$SERVICE_USER:docker" "$CONFIG_DIR"
chown -R "$SERVICE_USER:docker" "$STATE_DIR"

# Make config files secure
chmod 600 "$CONFIG_DIR/.env"
chmod 644 "$CONFIG_DIR/updater_config.json"
chmod 755 "$INSTALL_DIR"
chmod 755 "$CONFIG_DIR"
chmod 755 "$STATE_DIR"

echo -e "${YELLOW}Installing systemd service...${NC}"
if [ ! -f "$SCRIPT_SOURCE_DIR/docker-updater.service" ]; then
    echo -e "${RED}Error: docker-updater.service not found in source directory${NC}"
    exit 1
fi

# Check if systemd is available
if ! command -v systemctl >/dev/null 2>&1; then
    echo -e "${YELLOW}Warning: systemd not available. Service file copied but not enabled.${NC}"
    cp "$SCRIPT_SOURCE_DIR/docker-updater.service" /etc/init.d/ 2>/dev/null || echo "Could not copy service file"
else
    cp "$SCRIPT_SOURCE_DIR/docker-updater.service" /etc/systemd/system/
    systemctl daemon-reload
    echo "Systemd service installed"
fi

echo -e "${YELLOW}Configuring sudo permissions for docker-compose operations...${NC}"
if [ -f "$SCRIPT_SOURCE_DIR/docker-updater-sudoers" ]; then
    # Validate sudoers file syntax
    if visudo -c -f "$SCRIPT_SOURCE_DIR/docker-updater-sudoers" >/dev/null 2>&1; then
        cp "$SCRIPT_SOURCE_DIR/docker-updater-sudoers" /etc/sudoers.d/docker-updater
        chmod 440 /etc/sudoers.d/docker-updater
        echo "Sudoers configuration installed"
    else
        echo -e "${YELLOW}Warning: sudoers file syntax invalid, skipping sudo configuration${NC}"
        echo "You may need to manually configure sudo permissions for docker-compose operations"
    fi
else
    echo -e "${YELLOW}Warning: docker-updater-sudoers not found, creating basic configuration${NC}"
    cat > /etc/sudoers.d/docker-updater << 'EOF'
# Docker Auto-Updater Sudoers Configuration
docker-updater ALL=(root) NOPASSWD: /usr/local/bin/docker-compose
docker-updater ALL=(root) NOPASSWD: /usr/bin/docker-compose
docker-updater ALL=(root) NOPASSWD: /bin/docker-compose
EOF
    chmod 440 /etc/sudoers.d/docker-updater
    echo "Basic sudoers configuration created"
fi

# Test Docker access
echo -e "${YELLOW}Testing Docker access...${NC}"
if sudo -u "$SERVICE_USER" docker version >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Docker access test passed${NC}"
else
    echo -e "${YELLOW}⚠ Docker access test failed. You may need to restart or re-login.${NC}"
fi

# Test Python environment
echo -e "${YELLOW}Testing Python environment...${NC}"
if sudo -u "$SERVICE_USER" "$INSTALL_DIR/docker-updater-env/bin/python" -c "import docker, requests, boto3" >/dev/null 2>&1; then
    echo -e "${GREEN}✓ Python dependencies test passed${NC}"
else
    echo -e "${YELLOW}⚠ Some Python dependencies may be missing${NC}"
fi

echo ""
echo -e "${GREEN}🎉 Installation completed successfully!${NC}"
echo "=================================="
echo ""
echo -e "${BLUE}Next steps:${NC}"
echo "1. Edit configuration:"
echo "   sudo nano $CONFIG_DIR/updater_config.json"
echo ""
echo "2. Set environment variables:"
echo "   sudo nano $CONFIG_DIR/.env"
echo ""
echo "3. Enable and start service:"
echo "   sudo systemctl enable docker-updater"
echo "   sudo systemctl start docker-updater"
echo ""
echo "4. Monitor service:"
echo "   sudo systemctl status docker-updater"
echo "   sudo journalctl -u docker-updater -f"
echo ""
echo -e "${YELLOW}Important Notes:${NC}"
echo "• Configure registry credentials in $CONFIG_DIR/.env"
echo "• Update service paths in $CONFIG_DIR/updater_config.json"
echo "• Ensure Docker daemon is running"
echo "• Check firewall settings if using remote registries"
echo ""
echo -e "${BLUE}Troubleshooting:${NC}"
echo "• Test Docker: sudo -u $SERVICE_USER docker ps"
echo "• Test config: python3 -c \"import json; json.load(open('$CONFIG_DIR/updater_config.json'))\""
echo "• View logs: sudo journalctl -u docker-updater --no-pager"
