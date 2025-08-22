#!/bin/bash

# Docker Auto-Updater Installation Script
# This script installs the Docker Auto-Updater service on a Linux system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
SERVICE_USER="docker-updater"
SERVICE_GROUP="docker"
INSTALL_DIR="/opt/docker-auto-updater"
CONFIG_DIR="/etc/docker-auto-updater"
STATE_DIR="/var/lib/docker-auto-updater"
LOG_DIR="/var/log/docker-auto-updater"

echo -e "${GREEN}Docker Auto-Updater Installation Script${NC}"
echo "========================================"

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Please run: sudo ./install.sh"
    exit 1
fi

# Get current directory (where script is run from) - more reliable approach
CURRENT_DIR="$(pwd)"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Use current directory if script directory detection fails
if [ ! -f "$SCRIPT_DIR/docker_updater.py" ] && [ -f "$CURRENT_DIR/docker_updater.py" ]; then
    SCRIPT_DIR="$CURRENT_DIR"
fi

echo "Installing from: $SCRIPT_DIR"

# Detect OS
detect_os() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        OS=$NAME
        VERSION=$VERSION_ID
    elif type lsb_release >/dev/null 2>&1; then
        OS=$(lsb_release -si)
        VERSION=$(lsb_release -sr)
    elif [ -f /etc/redhat-release ]; then
        OS="Red Hat Enterprise Linux"
        VERSION=$(cat /etc/redhat-release | sed 's/.*release //' | sed 's/ .*//')
    else
        OS=$(uname -s)
        VERSION=$(uname -r)
    fi
    
    echo -e "${BLUE}Detected OS: $OS $VERSION${NC}"
}

# Install dependencies based on OS
install_dependencies() {
    echo -e "${YELLOW}Installing system dependencies...${NC}"
    
    case "$OS" in
        "Ubuntu"*|"Debian"*)
            apt-get update
            apt-get install -y python3 python3-pip python3-venv docker.io curl sudo
            
            # Try to install docker-compose-plugin, fallback to manual installation
            if ! apt-get install -y docker-compose-plugin 2>/dev/null; then
                echo -e "${YELLOW}docker-compose-plugin not available, installing docker-compose manually...${NC}"
                curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
                chmod +x /usr/local/bin/docker-compose
            fi
            ;;
        "CentOS"*|"Red Hat"*|"Rocky"*|"AlmaLinux"*)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y python3 python3-pip docker curl sudo
            else
                yum install -y python3 python3-pip docker curl sudo
            fi
            
            # Install docker-compose manually for RHEL-based systems
            curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
            chmod +x /usr/local/bin/docker-compose
            ;;
        "Amazon Linux"*)
            yum update -y
            yum install -y python3 python3-pip docker curl sudo
            # Install docker-compose separately for Amazon Linux
            curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
            chmod +x /usr/local/bin/docker-compose
            ;;
        *)
            echo -e "${YELLOW}Unknown OS. Please install Python3, pip, Docker, and docker-compose manually.${NC}"
            ;;
    esac
    
    # Start Docker service
    systemctl enable docker
    systemctl start docker
    
    echo -e "${GREEN}✅ Dependencies installed${NC}"
}

# Create system user
create_user() {
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
    
    echo -e "${GREEN}✅ Service user configured${NC}"
}

# Create directories
create_directories() {
    echo -e "${YELLOW}Creating directories...${NC}"
    
    mkdir -p "$INSTALL_DIR"
    mkdir -p "$CONFIG_DIR"
    mkdir -p "$STATE_DIR"
    mkdir -p "$LOG_DIR"
    mkdir -p "/var/run/docker-auto-updater"
    
    echo -e "${GREEN}✅ Directories created${NC}"
}

# Verify required files exist
verify_files() {
    echo -e "${YELLOW}Checking required files...${NC}"
    
    REQUIRED_FILES=("docker_updater.py" "docker-updater.service" "docker-updater-sudoers" "requirements.txt")
    
    for file in "${REQUIRED_FILES[@]}"; do
        if [ ! -f "$SCRIPT_DIR/$file" ]; then
            echo -e "${RED}Error: Required file $file not found in $SCRIPT_DIR${NC}"
            echo "Current directory: $SCRIPT_DIR"
            echo "Files present:"
            ls -la "$SCRIPT_DIR"
            exit 1
        fi
        echo "✅ Found: $file"
    done
}

# Copy application files
copy_files() {
    echo -e "${YELLOW}Copying application files...${NC}"
    
    # Copy application files
    cp "$SCRIPT_DIR/docker_updater.py" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"
    echo "✅ Application files copied"
    
    # Copy configuration template if it exists
    if [ -f "$SCRIPT_DIR/updater_config.json" ]; then
        cp "$SCRIPT_DIR/updater_config.json" "$CONFIG_DIR/"
        echo "✅ Configuration template copied"
    else
        echo -e "${YELLOW}Warning: updater_config.json not found, you'll need to create it manually${NC}"
    fi
    
    # Handle environment file
    if [ -f "$SCRIPT_DIR/.env.example" ]; then
        cp "$SCRIPT_DIR/.env.example" "$CONFIG_DIR/.env"
        echo "✅ Environment template copied"
    else
        echo -e "${YELLOW}Creating default environment file...${NC}"
        cat > "$CONFIG_DIR/.env" << 'EOF'
# Docker Auto-Updater Environment Configuration

# Logging Configuration
LOG_LEVEL=INFO
# plain or json
LOG_FORMAT=plain

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

# Reliability tuning
# Timeout waiting for healthy containers after restart (seconds)
HEALTH_TIMEOUT=180
# Seconds containers must remain healthy before confirming update
HEALTH_STABLE=10
# Timeout for compose and subprocess commands (seconds)
COMPOSE_TIMEOUT=120

# State retention
# Number of timestamped state backups to keep
STATE_BACKUPS=5
# Optional separate directory for state backups
#STATE_BACKUP_DIR=/var/backups/docker-auto-updater

# Observability
#METRICS_PORT=9100
#WEBHOOK_URL=https://example.com/webhook

# Controls
# Comma-separated HH:MM-HH:MM windows (24h). Example: 02:00-04:00,14:00-15:30
#MAINTENANCE_WINDOW=02:00-04:00
#PAUSE_UPDATES=0
EOF
        echo "✅ Default environment file created"
    fi
    
    echo -e "${GREEN}✅ Files copied successfully${NC}"
}

# Install sudoers configuration
install_sudoers() {
    echo -e "${YELLOW}Installing sudoers configuration...${NC}"
    
    # Validate and install sudoers file
    if visudo -c -f "$SCRIPT_DIR/docker-updater-sudoers" >/dev/null 2>&1; then
        cp "$SCRIPT_DIR/docker-updater-sudoers" /etc/sudoers.d/docker-updater
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
    
    echo -e "${GREEN}✅ Sudoers configuration installed${NC}"
}

# Set file permissions
set_permissions() {
    echo -e "${YELLOW}Setting file permissions...${NC}"
    
    # Create .docker directory for Docker credentials
    mkdir -p "$INSTALL_DIR/.docker"
    
    # Set ownership
    chown -R "$SERVICE_USER:$SERVICE_USER" "$INSTALL_DIR"
    chown -R "$SERVICE_USER:docker" "$CONFIG_DIR"
    chown -R "$SERVICE_USER:docker" "$STATE_DIR"
    chown -R "$SERVICE_USER:docker" "$LOG_DIR"
    
    # Set permissions
    chmod 600 "$CONFIG_DIR/.env"
    if [ -f "$CONFIG_DIR/updater_config.json" ]; then
        chmod 644 "$CONFIG_DIR/updater_config.json"
    fi
    chmod 755 "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR"
    chmod 755 "$INSTALL_DIR/.docker"
    
    echo -e "${GREEN}✅ Permissions set${NC}"
}

# Install Python dependencies
install_python_deps() {
    echo -e "${YELLOW}Installing Python dependencies...${NC}"
    
    # Create virtual environment for the service
    VENV_DIR="$INSTALL_DIR/venv"
    if command -v python3 >/dev/null 2>&1; then
        # Create virtual environment
        python3 -m venv "$VENV_DIR"
        
        # Install dependencies in virtual environment including python-dotenv
        "$VENV_DIR/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
        "$VENV_DIR/bin/pip" install python-dotenv
        
        echo "✅ Python dependencies installed in virtual environment"
    else
        echo -e "${YELLOW}Warning: python3 not found, please install Python dependencies manually${NC}"
        return 1
    fi
    
    echo -e "${GREEN}✅ Python dependencies installed${NC}"
}

# Install systemd service
install_service() {
    echo -e "${YELLOW}Installing systemd service...${NC}"
    
    # Copy service file
    cp "$SCRIPT_DIR/docker-updater.service" /etc/systemd/system/
    
    # Update service file to use virtual environment
    VENV_DIR="$INSTALL_DIR/venv"
    if [ -d "$VENV_DIR" ]; then
        sed -i "s|ExecStart=.*|ExecStart=$VENV_DIR/bin/python $INSTALL_DIR/docker_updater.py|" /etc/systemd/system/docker-updater.service
    fi
    
    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable docker-updater
    
    echo -e "${GREEN}✅ Systemd service installed${NC}"
}

# Validate installation
validate_installation() {
    echo -e "${YELLOW}Validating installation...${NC}"
    
    # Test Docker access
    if sudo -u "$SERVICE_USER" docker version >/dev/null 2>&1; then
        echo "✅ Docker access test passed"
    else
        echo -e "${YELLOW}⚠️  Docker access test failed - may need manual configuration${NC}"
    fi
    
    # Test configuration file
    if [ -f "$CONFIG_DIR/updater_config.json" ]; then
        echo "✅ Configuration file present"
    else
        echo -e "${YELLOW}⚠️  Configuration file missing - please create $CONFIG_DIR/updater_config.json${NC}"
    fi
    
    # Test service file
    if systemctl is-enabled docker-updater >/dev/null 2>&1; then
        echo "✅ Service enabled"
    else
        echo -e "${RED}❌ Service not enabled${NC}"
    fi
    
    echo -e "${GREEN}✅ Installation validation complete${NC}"
}

# Start service and show status
start_service() {
    echo -e "${YELLOW}Starting service...${NC}"
    
    if systemctl start docker-updater; then
        echo "✅ Service started successfully"
        
        # Show service status
        echo -e "\n${BLUE}Service Status:${NC}"
        systemctl status docker-updater --no-pager -l
        
        echo -e "\n${BLUE}Recent logs:${NC}"
        journalctl -u docker-updater -n 10 --no-pager
    else
        echo -e "${RED}❌ Failed to start service${NC}"
        echo "Check logs with: journalctl -u docker-updater -f"
    fi
}

# Main installation process
main() {
    echo -e "${BLUE}Starting Docker Auto-Updater installation...${NC}"
    
    detect_os
    verify_files
    install_dependencies
    create_user
    create_directories
    copy_files
    install_sudoers
    set_permissions
    install_python_deps
    install_service
    validate_installation
    start_service
    
    echo
    echo -e "${GREEN}🎉 Installation completed successfully!${NC}"
    echo
    echo -e "${YELLOW}Next steps:${NC}"
    echo "1. Edit the configuration file: $CONFIG_DIR/updater_config.json"
    echo "2. Configure environment variables: $CONFIG_DIR/.env"
    echo "3. Check service status: systemctl status docker-updater"
    echo "4. View logs: journalctl -u docker-updater -f"
    echo "5. Restart service after config changes: systemctl restart docker-updater"
    echo
    echo -e "${BLUE}For more information, see the README.md file${NC}"
}

# Run main function
main "$@"
