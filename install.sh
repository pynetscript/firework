#!/bin/bash
# A bulletproof script to set up the environment for the Firework app.
# It is designed to be idempotent and can be run multiple times safely.

# Exit immediately if a command exits with a non-zero status, unless checked.
set -e

# Define variables for users, groups, and paths
readonly APP_USER="firework_app_user"
readonly APP_GROUP="www-data"
readonly PROJECT_DIR="/home/firework/firework"

echo "Beginning idempotent setup for the Firework app..."

# --- 1. Create dedicated application user and home directory ---
# Check if the user exists. If not, create it with a home directory.
if ! id "${APP_USER}" &>/dev/null; then
    echo "User '${APP_USER}' does not exist. Creating system user with home directory..."
    sudo useradd -m -r -s /usr/sbin/nologin -g "${APP_GROUP}" "${APP_USER}"
    echo "User '${APP_USER}' created with home directory at /home/${APP_USER}."
else
    echo "User '${APP_USER}' already exists. Skipping user creation."
    # Ensure home directory and its ownership are correct, as it might have been created without -m.
    if [ ! -d "/home/${APP_USER}" ]; then
        echo "Home directory for '${APP_USER}' not found. Creating and setting ownership..."
        sudo mkdir -p "/home/${APP_USER}"
        sudo chown "${APP_USER}":"${APP_GROUP}" "/home/${APP_USER}"
    fi
fi

# --- 2. Create and configure application directories ---
echo "Configuring required directories..."
# Use mkdir -p which is idempotent (does not fail if directory exists).
sudo mkdir -p "${PROJECT_DIR}/ansible_collections"
sudo mkdir -p "${PROJECT_DIR}/outputs"

# Set permissions and ownership for directories
sudo chown "${APP_USER}":"${APP_GROUP}" "${PROJECT_DIR}/ansible_collections"
sudo chmod 775 "${PROJECT_DIR}/ansible_collections"

sudo chown "${APP_USER}":"${APP_GROUP}" "${PROJECT_DIR}/outputs"
sudo chmod 2775 "${PROJECT_DIR}/outputs" # The `2` sets the `setgid` bit.

# --- 3. Install Ansible Collections ---
echo "Installing Ansible collections..."
# Check for existing collections before attempting to install
if [ ! -d "${PROJECT_DIR}/ansible_collections/fortinet/fortios" ]; then
    echo "Installing fortinet.fortios..."
    sudo -u "${APP_USER}" ansible-galaxy collection install fortinet.fortios -p "${PROJECT_DIR}/ansible_collections"
else
    echo "fortinet.fortios collection already installed. Skipping."
fi

if [ ! -d "${PROJECT_DIR}/ansible_collections/paloaltonetworks/panos" ]; then
    echo "Installing paloaltonetworks.panos..."
    sudo -u "${APP_USER}" ansible-galaxy collection install paloaltonetworks.panos -p "${PROJECT_DIR}/ansible_collections"
else
    echo "paloaltonetworks.panos collection already installed. Skipping."
fi

# --- 4. Create and configure Ansible files ---
echo "Creating Ansible configuration files..."
# Create inventory.yml if it doesn't exist
if [ ! -f "${PROJECT_DIR}/inventory.yml" ]; then
    sudo touch "${PROJECT_DIR}/inventory.yml"
    sudo chown firework:"${APP_GROUP}" "${PROJECT_DIR}/inventory.yml"
    sudo chmod 644 "${PROJECT_DIR}/inventory.yml"
    echo "File 'inventory.yml' created."
else
    echo "File 'inventory.yml' already exists. Skipping creation."
fi

# Create .vault_pass.txt if it doesn't exist
if [ ! -f "${PROJECT_DIR}/.vault_pass.txt" ]; then
    sudo touch "${PROJECT_DIR}/.vault_pass.txt"
    sudo chown firework:firework "${PROJECT_DIR}/.vault_pass.txt"
    sudo chmod 640 "${PROJECT_DIR}/.vault_pass.txt"
    echo "File '.vault_pass.txt' created."
else
    echo "File '.vault_pass.txt' already exists. Skipping creation."
fi

# --- 5. Final confirmation ---
echo ""
echo "========================================================"
echo "Setup complete! All users, directories, and files are in place."
echo "Please remember to manually edit the following files:"
echo "  - ${PROJECT_DIR}/inventory.yml"
echo "  - ${PROJECT_DIR}/.vault_pass.txt"
echo "========================================================"
