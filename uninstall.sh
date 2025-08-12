#!/bin/bash

# Docker Auto-Updater Uninstall Script
# Safely removes all components installed by install.sh

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Configuration - matches install.sh structure
SERVICE_NAME="docker-updater"
SERVICE_USER="docker-updater"
SERVICE_GROUP="docker"
INSTALL_DIR="/opt/docker-auto-updater"
CONFIG_DIR="/etc/docker-auto-updater"
STATE_DIR="/var/lib/docker-auto-updater"
LOG_DIR="/var/log/docker-auto-updater"
VENV_DIR="$INSTALL_DIR/venv"

echo -e "${BLUE}Docker Auto-Updater Uninstall Script${NC}"
echo -e "${BLUE}====================================${NC}"
echo

# Check if running as root
if [ "$EUID" -ne 0 ]; then
    echo -e "${RED}Error: This script must be run as root${NC}"
    echo "Please run: sudo $0"
    exit 1
fi

# Confirmation prompt
echo -e "${YELLOW}WARNING: This will completely remove Docker Auto-Updater and all its components.${NC}"
echo -e "${YELLOW}This action cannot be undone.${NC}"
echo
read -p "Are you sure you want to continue? (y/N): " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    echo -e "${BLUE}Uninstall cancelled.${NC}"
    exit 0
fi

echo -e "${YELLOW}Starting uninstall process...${NC}"
echo

# Stop and disable systemd service
echo -e "${YELLOW}Stopping and disabling systemd service...${NC}"
if systemctl is-active --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl stop "$SERVICE_NAME"
    echo "Service stopped"
else
    echo "Service was not running"
fi

if systemctl is-enabled --quiet "$SERVICE_NAME" 2>/dev/null; then
    systemctl disable "$SERVICE_NAME"
    echo "Service disabled"
else
    echo "Service was not enabled"
fi

# Remove systemd service file
if [ -f "/etc/systemd/system/$SERVICE_NAME.service" ]; then
    rm -f "/etc/systemd/system/$SERVICE_NAME.service"
    systemctl daemon-reload
    echo "Systemd service file removed"
else
    echo "Systemd service file not found"
fi

# Remove sudoers configuration
echo -e "${YELLOW}Removing sudoers configuration...${NC}"
if [ -f "/etc/sudoers.d/$SERVICE_NAME" ]; then
    rm -f "/etc/sudoers.d/$SERVICE_NAME"
    echo "Sudoers configuration removed"
else
    echo "Sudoers configuration not found"
fi

# Remove service user and group
echo -e "${YELLOW}Removing service user and group...${NC}"
if id "$SERVICE_USER" &>/dev/null; then
    # Remove user from docker group if it exists
    if getent group docker >/dev/null 2>&1; then
        gpasswd -d "$SERVICE_USER" docker 2>/dev/null || echo "User was not in docker group"
    fi
    
    # Remove user
    userdel "$SERVICE_USER" 2>/dev/null || echo "Could not remove user (may not exist)"
    echo "Service user removed"
else
    echo "Service user not found"
fi

if getent group "$SERVICE_GROUP" >/dev/null 2>&1; then
    groupdel "$SERVICE_GROUP" 2>/dev/null || echo "Could not remove group (may be in use)"
    echo "Service group removed"
else
    echo "Service group not found"
fi

# Remove installation directory (includes virtual environment)
echo -e "${YELLOW}Removing installation directory...${NC}"
if [ -d "$INSTALL_DIR" ]; then
    if [ -d "$VENV_DIR" ]; then
        echo "Removing Python virtual environment: $VENV_DIR"
    fi
    rm -rf "$INSTALL_DIR"
    echo "Installation directory removed: $INSTALL_DIR"
else
    echo "Installation directory not found: $INSTALL_DIR"
fi

# Remove configuration directory
echo -e "${YELLOW}Removing configuration directory...${NC}"
if [ -d "$CONFIG_DIR" ]; then
    echo -e "${YELLOW}Configuration directory contains user data.${NC}"
    read -p "Remove configuration directory $CONFIG_DIR? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$CONFIG_DIR"
        echo "Configuration directory removed: $CONFIG_DIR"
    else
        echo "Configuration directory preserved: $CONFIG_DIR"
    fi
else
    echo "Configuration directory not found: $CONFIG_DIR"
fi

# Remove log directory
echo -e "${YELLOW}Removing log directory...${NC}"
if [ -d "$LOG_DIR" ]; then
    echo -e "${YELLOW}Log directory contains historical data.${NC}"
    read -p "Remove log directory $LOG_DIR? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$LOG_DIR"
        echo "Log directory removed: $LOG_DIR"
    else
        echo "Log directory preserved: $LOG_DIR"
    fi
else
    echo "Log directory not found: $LOG_DIR"
fi

# Remove state directory
echo -e "${YELLOW}Removing state directory...${NC}"
if [ -d "$STATE_DIR" ]; then
    echo -e "${YELLOW}State directory contains application state data.${NC}"
    read -p "Remove state directory $STATE_DIR? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        rm -rf "$STATE_DIR"
        echo "State directory removed: $STATE_DIR"
    else
        echo "State directory preserved: $STATE_DIR"
    fi
else
    echo "State directory not found: $STATE_DIR"
fi

# Clean up temporary files
echo -e "${YELLOW}Cleaning up temporary files...${NC}"
TEMP_FILES_REMOVED=0
for temp_file in /tmp/docker-compose-*.yml; do
    if [ -f "$temp_file" ]; then
        rm -f "$temp_file"
        ((TEMP_FILES_REMOVED++))
    fi
done

if [ $TEMP_FILES_REMOVED -gt 0 ]; then
    echo "Removed $TEMP_FILES_REMOVED temporary docker-compose files"
else
    echo "No temporary files found"
fi

# Check for any remaining processes
echo -e "${YELLOW}Checking for remaining processes...${NC}"
REMAINING_PROCESSES=$(pgrep -f "docker_updater.py" || true)
if [ -n "$REMAINING_PROCESSES" ]; then
    echo -e "${YELLOW}Warning: Found running docker_updater.py processes:${NC}"
    echo "$REMAINING_PROCESSES"
    read -p "Kill these processes? (y/N): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        pkill -f "docker_updater.py" || echo "Could not kill processes"
        echo "Processes terminated"
    else
        echo "Processes left running"
    fi
else
    echo "No remaining processes found"
fi

# Final cleanup verification
echo -e "${YELLOW}Performing final verification...${NC}"
ISSUES_FOUND=0

# Check systemd service
if systemctl list-unit-files | grep -q "$SERVICE_NAME.service"; then
    echo -e "${RED}⚠️  Systemd service still exists${NC}"
    ((ISSUES_FOUND++))
fi

# Check user
if id "$SERVICE_USER" &>/dev/null; then
    echo -e "${RED}⚠️  Service user still exists${NC}"
    ((ISSUES_FOUND++))
fi

# Check sudoers
if [ -f "/etc/sudoers.d/$SERVICE_NAME" ]; then
    echo -e "${RED}⚠️  Sudoers configuration still exists${NC}"
    ((ISSUES_FOUND++))
fi

# Check installation directory
if [ -d "$INSTALL_DIR" ]; then
    echo -e "${RED}⚠️  Installation directory still exists${NC}"
    ((ISSUES_FOUND++))
fi

echo
if [ $ISSUES_FOUND -eq 0 ]; then
    echo -e "${GREEN}✅ Docker Auto-Updater successfully uninstalled!${NC}"
    echo -e "${GREEN}✅ All components removed cleanly${NC}"
else
    echo -e "${YELLOW}⚠️  Uninstall completed with $ISSUES_FOUND issues${NC}"
    echo -e "${YELLOW}   Manual cleanup may be required${NC}"
fi

echo
echo -e "${BLUE}Uninstall Summary:${NC}"
echo -e "${BLUE}=================${NC}"
echo "• Systemd service: Stopped and removed"
echo "• Service user/group: Removed"
echo "• Sudoers configuration: Removed"
echo "• Installation directory: Removed (includes Python venv)"
echo "• State directory: User choice"
echo "• Configuration directory: User choice"
echo "• Log directory: User choice"
echo "• Temporary files: Cleaned up"
echo
echo -e "${BLUE}Thank you for using Docker Auto-Updater!${NC}"

# Optional: Suggest manual verification steps
echo
echo -e "${YELLOW}Optional manual verification:${NC}"
echo "• Check for any remaining docker_updater processes: ps aux | grep docker_updater"
echo "• Verify no systemd services: systemctl list-unit-files | grep docker-updater"
echo "• Check sudoers: sudo visudo -c"
echo "• Verify user removal: id docker-updater"
