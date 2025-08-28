#!/bin/bash
# A script to create a dedicated user and configure folder permissions for the Firework app.

# Exit immediately if a command exits with a non-zero status.
set -e

# Define variables for user and groups
APP_USER="firework_app_user"
APP_GROUP="www-data"
PROJECT_DIR="/home/firework/firework"

echo "Beginning user and folder setup for the Firework app..."

# --- 1. Create the dedicated application user ---
# The user is created as a system user (-r) without a password and with a non-interactive shell (-s).
# This is a security best practice for service accounts.
echo "Creating system user '${APP_USER}'..."
sudo useradd -r -s /usr/sbin/nologin -g "${APP_GROUP}" "${APP_USER}"

# --- 2. Create and configure application directories ---
echo "Creating required directories..."
# Create the ansible_collections directory and set ownership
sudo mkdir -p "${PROJECT_DIR}/ansible_collections"
sudo chown "${APP_USER}":"${APP_GROUP}" "${PROJECT_DIR}/ansible_collections"
sudo chmod 775 "${PROJECT_DIR}/ansible_collections"

# Create the outputs directory and set ownership
sudo mkdir -p "${PROJECT_DIR}/outputs"
sudo chown "${APP_USER}":"${APP_GROUP}" "${PROJECT_DIR}/outputs"
sudo chmod 2775 "${PROJECT_DIR}/outputs" # The `2` at the start sets the GID (setgid) bit.

# --- 3. Install Ansible Collections ---
echo "Installing Ansible collections..."
ansible-galaxy collection install fortinet.fortios -p "${PROJECT_DIR}/ansible_collections"
ansible-galaxy collection install paloaltonetworks.panos -p "${PROJECT_DIR}/ansible_collections"

# --- 4. Explanation of permissions ---
echo ""
echo "Permissions for ${PROJECT_DIR}/ansible_collections set to 775 (drwxrwxr-x)."
echo "Permissions for ${PROJECT_DIR}/outputs set to 2775 (drwxrwsr-x)."
echo "The 's' bit on the 'outputs' folder is called the 'setgid' bit. It ensures"
echo "that any new files or directories created inside 'outputs' will automatically"
echo "inherit the group owner ('${APP_GROUP}'), which is crucial for file access"
echo "between the different users and services."

echo ""
echo "Setup complete. The '${APP_USER}' has been created and permissions are set."
