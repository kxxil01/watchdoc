#!/bin/bash

# Watchdoc Installation Script
# Installs the Watchdoc agent on a Linux system

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration
INSTALL_USER="${WATCHDOC_USER:-${SUDO_USER}}"
if [ -z "$INSTALL_USER" ]; then
    echo -e "${RED}Error: Unable to determine install user. Run with sudo from a non-root account or set WATCHDOC_USER.${NC}"
    exit 1
fi
SERVICE_USER="$INSTALL_USER"
SERVICE_GROUP="$(id -gn "$SERVICE_USER" 2>/dev/null || echo "$SERVICE_USER")"
INSTALL_DIR="/opt/watchdoc"
CONFIG_DIR="/etc/watchdoc"
STATE_DIR="/var/lib/watchdoc"
LOG_DIR="/var/log/watchdoc"
DOCKER_CONFIG_DIR="$STATE_DIR/docker-config"

echo -e "${GREEN}Watchdoc Installation Script${NC}"
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
if [ ! -f "$SCRIPT_DIR/watchdoc.py" ] && [ -f "$CURRENT_DIR/watchdoc.py" ]; then
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
            ;;
        "CentOS"*|"Red Hat"*|"Rocky"*|"AlmaLinux"*)
            if command -v dnf >/dev/null 2>&1; then
                dnf install -y python3 python3-pip docker curl sudo
            else
                yum install -y python3 python3-pip docker curl sudo
            fi
            ;;
        "Amazon Linux"*)
            yum update -y
            yum install -y python3 python3-pip docker curl sudo
            ;;
        *)
            echo -e "${YELLOW}Unknown OS. Please install Python3, pip, Docker, and curl manually.${NC}"
            ;;
    esac
    
    # Start Docker service
    systemctl enable docker
    systemctl start docker
    
    echo -e "${GREEN}✅ Dependencies installed${NC}"
}

# Configure service user
configure_user() {
    echo -e "${YELLOW}Configuring service user...${NC}"

    if ! id "$SERVICE_USER" &>/dev/null; then
        echo -e "${RED}Error: User $SERVICE_USER does not exist. Please create it before running install.${NC}"
        exit 1
    fi

    if ! getent group docker > /dev/null 2>&1; then
        echo -e "${YELLOW}Creating docker group...${NC}"
        groupadd docker
    fi

    if id -nG "$SERVICE_USER" | grep -qw docker; then
        echo "User $SERVICE_USER already in docker group"
    else
        usermod -a -G docker "$SERVICE_USER"
        echo "Added $SERVICE_USER to docker group"
    fi

    if [ -S /var/run/docker.sock ]; then
        chown root:docker /var/run/docker.sock
        chmod 660 /var/run/docker.sock
        echo "Adjusted Docker socket permissions"
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
    mkdir -p "$DOCKER_CONFIG_DIR"
    
    echo -e "${GREEN}✅ Directories created${NC}"
}

# Verify required files exist
verify_files() {
    echo -e "${YELLOW}Checking required files...${NC}"
    
    REQUIRED_FILES=("watchdoc.py" "watchdoc.service" "requirements.txt")
    
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
    cp "$SCRIPT_DIR/watchdoc.py" "$INSTALL_DIR/"
    cp "$SCRIPT_DIR/requirements.txt" "$INSTALL_DIR/"
    echo "✅ Application files copied"
    
    # Copy configuration template if it exists
    if [ -f "$SCRIPT_DIR/watchdoc_config.json" ]; then
        cp "$SCRIPT_DIR/watchdoc_config.json" "$CONFIG_DIR/"
        echo "✅ Configuration template copied"
    else
        echo -e "${YELLOW}Warning: watchdoc_config.json not found, you'll need to create it manually${NC}"
    fi
    
    # Create environment file
    echo -e "${YELLOW}Writing default environment file...${NC}"
    cat > "$CONFIG_DIR/.env" << 'EOF'
# Watchdoc Environment Configuration

# Logging Configuration
LOG_LEVEL=INFO

# Enable/disable label discovery (leave true for normal operation)
AUTO_DISCOVERY=true

# Registry Credentials (optional overrides)
#AWS_ACCESS_KEY_ID=your_access_key
#AWS_SECRET_ACCESS_KEY=your_secret_key
#AWS_DEFAULT_REGION=us-west-2
#GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json
#GCP_PROJECT_ID=your-project-id
#DOCKER_HUB_USERNAME=your_username
#DOCKER_HUB_PASSWORD=your_password
EOF
    echo "✅ Environment file created at $CONFIG_DIR/.env"
    
    echo "$SERVICE_USER" > "$CONFIG_DIR/install_user"
    chmod 600 "$CONFIG_DIR/install_user"
    echo "✅ Recorded install user"
    
    echo -e "${GREEN}✅ Files copied successfully${NC}"
}

# Install sudoers configuration
install_sudoers() {
    echo -e "${YELLOW}Skipping sudoers configuration (docker group access is sufficient for Watchdoc).${NC}"
}

# Set file permissions
set_permissions() {
    echo -e "${YELLOW}Setting file permissions...${NC}"
    
    # Create .docker directory for Docker credentials
    mkdir -p "$INSTALL_DIR/.docker"
    
    # Determine the group to use
    if getent group docker > /dev/null 2>&1; then
        CHOWN_GROUP="docker"
    else
        CHOWN_GROUP="$SERVICE_USER"
        echo -e "${YELLOW}Warning: docker group not found, using $SERVICE_USER group${NC}"
    fi
    
    # Set ownership
    chown -R "$SERVICE_USER:$SERVICE_GROUP" "$INSTALL_DIR"
    chown -R "$SERVICE_USER:$CHOWN_GROUP" "$CONFIG_DIR"
    chown -R "$SERVICE_USER:$CHOWN_GROUP" "$STATE_DIR"
    chown -R "$SERVICE_USER:$CHOWN_GROUP" "$LOG_DIR"
    
    # Set permissions
    chmod 600 "$CONFIG_DIR/.env"
    if [ -f "$CONFIG_DIR/watchdoc_config.json" ]; then
        chmod 644 "$CONFIG_DIR/watchdoc_config.json"
    fi
    chmod 755 "$INSTALL_DIR" "$CONFIG_DIR" "$STATE_DIR" "$LOG_DIR"
    chmod 755 "$INSTALL_DIR/.docker"
    chmod 700 "$DOCKER_CONFIG_DIR"
    
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
    cp "$SCRIPT_DIR/watchdoc.service" /etc/systemd/system/
    
    # Update service file to use virtual environment
    VENV_DIR="$INSTALL_DIR/venv"
    if [ -d "$VENV_DIR" ]; then
        sed -i "s|ExecStart=.*|ExecStart=$VENV_DIR/bin/python $INSTALL_DIR/watchdoc.py|" /etc/systemd/system/watchdoc.service
    fi
    sed -i "s|^User=.*|User=$SERVICE_USER|" /etc/systemd/system/watchdoc.service
    sed -i "s|^Group=.*|Group=$SERVICE_GROUP|" /etc/systemd/system/watchdoc.service
    if ! grep -q "^Environment=DOCKER_CONFIG" /etc/systemd/system/watchdoc.service; then
        sed -i "/^EnvironmentFile/a Environment=DOCKER_CONFIG=$DOCKER_CONFIG_DIR" /etc/systemd/system/watchdoc.service
    else
        sed -i "s|^Environment=DOCKER_CONFIG=.*|Environment=DOCKER_CONFIG=$DOCKER_CONFIG_DIR|" /etc/systemd/system/watchdoc.service
    fi

    # Reload systemd and enable service
    systemctl daemon-reload
    systemctl enable watchdoc
    
    echo -e "${GREEN}✅ Systemd service installed${NC}"
}

# Validate installation
validate_installation() {
    echo -e "${YELLOW}Validating installation...${NC}"
    
    # Test Docker access
    if sudo -u "$SERVICE_USER" docker version >/dev/null 2>&1; then
        echo "✅ Docker access test passed"
    else
        echo -e "${RED}❌ Docker access test failed${NC}"
        echo -e "${YELLOW}Troubleshooting steps:${NC}"
        echo "1. Check if user is in docker group: groups $SERVICE_USER"
        echo "2. Check Docker socket permissions: ls -la /var/run/docker.sock"
        echo "3. Fix permissions: sudo chown root:docker /var/run/docker.sock"
        echo "4. Add user to group: sudo usermod -a -G docker $SERVICE_USER"
        echo "5. Restart Docker: sudo systemctl restart docker"
        echo "6. Test manually: sudo -u $SERVICE_USER docker version"
    fi
    
    # Test configuration file
    if [ -f "$CONFIG_DIR/watchdoc_config.json" ]; then
        echo "✅ Configuration file present"
    else
        echo -e "${YELLOW}⚠️  Configuration file missing - please create $CONFIG_DIR/watchdoc_config.json${NC}"
    fi
    
    # Test service file
    if systemctl is-enabled watchdoc >/dev/null 2>&1; then
        echo "✅ Service enabled"
    else
        echo -e "${RED}❌ Service not enabled${NC}"
    fi
    
    echo -e "${GREEN}✅ Installation validation complete${NC}"
}

# Start service and show status
start_service() {
    echo -e "${YELLOW}Starting service...${NC}"
    
    if systemctl start watchdoc; then
        echo "✅ Service started successfully"
        
        # Show service status
        echo -e "\n${BLUE}Service Status:${NC}"
        systemctl status watchdoc --no-pager -l
        
        echo -e "\n${BLUE}Recent logs:${NC}"
        journalctl -u watchdoc -n 10 --no-pager
    else
        echo -e "${RED}❌ Failed to start service${NC}"
        echo "Check logs with: journalctl -u watchdoc -f"
    fi
}

# Main installation process
main() {
    echo -e "${BLUE}Starting Watchdoc installation...${NC}"
    
    detect_os
    verify_files
    install_dependencies
    configure_user
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
    echo "1. Adjust the check interval in $CONFIG_DIR/watchdoc_config.json if needed."
    echo "2. Populate $CONFIG_DIR/.env with registry credentials (optional)."
    echo "3. Add Watchdoc labels to the containers you want auto-updated."
    echo "4. Check service status: systemctl status watchdoc"
    echo "5. Tail logs: journalctl -u watchdoc -f"
    echo
    echo -e "${BLUE}For more information, see the README.md file${NC}"
}

# Run main function
main "$@"
