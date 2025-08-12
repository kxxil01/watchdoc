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
