# --- 1. Create the dedicated application user ---
# Check if the user already exists before creating it
if id "${APP_USER}" &>/dev/null; then
    echo "User '${APP_USER}' already exists. Skipping user creation."
else
    echo "Creating system user '${APP_USER}'..."
    # Create the user with a home directory and add it to the www-data group
    sudo useradd -m -r -s /usr/sbin/nologin -g "${APP_GROUP}" "${APP_USER}"
fi

# --- 2. Create and configure application directories ---
echo "Creating required directories..."
# Create the ansible_collections directory and set ownership
sudo mkdir -p "${PROJECT_DIR}/ansible_collections"
sudo chown "${APP_USER}":"${APP_GROUP}" "${PROJECT_DIR}/ansible_collections"
sudo chmod 775 "${PROJECT_DIR}/ansible_collections"

# ... (the rest of the script is the same)
