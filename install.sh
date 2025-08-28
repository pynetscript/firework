#!/bin/bash
# A script to prepare the environment for the Firework app.
# It is designed to be idempotent and can be run multiple times safely.

set -Eeuo pipefail

# --- Variables ---------------------------------------------------------------
readonly APP_USER="firework_app_user"
readonly APP_GROUP="www-data"
readonly PROJECT_DIR="/home/firework/firework"
readonly ANSIBLE_COLLECTIONS_PATH="${PROJECT_DIR}/ansible_collections"
readonly ANSIBLE_TMP_DIR="${PROJECT_DIR}/ansible_tmp"
readonly INVENTORY_FILE="${PROJECT_DIR}/inventory.yml"
readonly VAULT_PASS_FILE="${PROJECT_DIR}/.vault_pass.txt"
readonly ENV_FILE="${PROJECT_DIR}/.env"
readonly STATIC_DIR="${PROJECT_DIR}/static"
readonly APP_DIR="${PROJECT_DIR}/app"

echo "========================================================"
echo "Starting script..."

# --- 1) Create users, folders, files -----------------------------------------
echo "Creating users, folders, and files if they do not exist..."

# 1a) Create dedicated application user and home directory
if ! id "${APP_USER}" &>/dev/null; then
  echo "Creating system user '${APP_USER}' (shell: nologin, group: ${APP_GROUP})..."
  sudo useradd -m -r -s /usr/sbin/nologin -g "${APP_GROUP}" "${APP_USER}"
  echo "User '${APP_USER}' created with home directory at /home/${APP_USER}."
else
  echo "User '${APP_USER}' already exists. Skipping user creation."
  if [ ! -d "/home/${APP_USER}" ]; then
    echo "Home directory for '${APP_USER}' missing. Creating..."
    sudo mkdir -p "/home/${APP_USER}"
  fi
fi

# 1b) Create directories
sudo mkdir -p "${ANSIBLE_COLLECTIONS_PATH}" "${PROJECT_DIR}/outputs" "${ANSIBLE_TMP_DIR}" "${STATIC_DIR}" "${APP_DIR}"

# 1c) Create files
sudo touch "${INVENTORY_FILE}" "${VAULT_PASS_FILE}" "${ENV_FILE}"

# --- 2) Ownership & permissions (project root) --------------------------------
echo "Setting permissions and ownership (project root)..."

# Collections dir (owned by firework for ansible-galaxy)
sudo chown firework:"${APP_GROUP}" "${ANSIBLE_COLLECTIONS_PATH}"
sudo chmod 775 "${ANSIBLE_COLLECTIONS_PATH}"

# Outputs dir (setgid)
sudo chown "${APP_USER}":"${APP_GROUP}" "${PROJECT_DIR}/outputs"
sudo chmod 2775 "${PROJECT_DIR}/outputs"

# Ansible temp dir
sudo chown firework:"${APP_GROUP}" "${ANSIBLE_TMP_DIR}"
sudo chmod 775 "${ANSIBLE_TMP_DIR}"

# Key config files
sudo chown firework:"${APP_GROUP}" "${INVENTORY_FILE}"
sudo chmod 664 "${INVENTORY_FILE}"

sudo chown firework:"${APP_GROUP}" "${VAULT_PASS_FILE}"
sudo chmod 640 "${VAULT_PASS_FILE}"

sudo chown firework:firework "${ENV_FILE}"
sudo chmod 600 "${ENV_FILE}"

# --- 2b) Playbooks in project root -------------------------------------------
echo "Applying owner/perms to Ansible playbooks..."
declare -a PLAYBOOKS=(
  "${PROJECT_DIR}/post_check_firewall_rule_fortinet.yml"
  "${PROJECT_DIR}/post_check_firewall_rule_paloalto.yml"
  "${PROJECT_DIR}/pre_check_firewall_rule_fortinet.yml"
  "${PROJECT_DIR}/pre_check_firewall_rule_paloalto.yml"
  "${PROJECT_DIR}/provision_firewall_rule_fortinet.yml"
  "${PROJECT_DIR}/provision_firewall_rule_paloalto.yml"
)
for pb in "${PLAYBOOKS[@]}"; do
  if [ -f "$pb" ]; then
    sudo chown firework:"${APP_GROUP}" "$pb"
    sudo chmod 644 "$pb"
    echo "Set firework:${APP_GROUP} and 0644 on $(basename "$pb")"
  else
    echo "Missing $(basename "$pb") — skipping."
  fi
done

# --- 2c) Scripts in project root ---------------------------------------------
echo "Applying owner/perms to project scripts..."
declare -A SCRIPTS=(
  ["${PROJECT_DIR}/add_default_users.sh"]="firework:${APP_GROUP}:755"
  ["${PROJECT_DIR}/clean.sh"]="firework:${APP_GROUP}:755"
  ["${PROJECT_DIR}/run.py"]="firework:${APP_GROUP}:755"
  ["${PROJECT_DIR}/setup.sh"]="firework:firework:755"
  ["${PROJECT_DIR}/start_firework.sh"]="firework:firework:775"
  ["${PROJECT_DIR}/status_firework.sh"]="firework:firework:775"
  ["${PROJECT_DIR}/stop_firework.sh"]="firework:firework:775"
)
for script in "${!SCRIPTS[@]}"; do
  if [ -f "$script" ]; then
    IFS=":" read -r owner group mode <<<"${SCRIPTS[$script]}"
    sudo chown "$owner":"$group" "$script"
    sudo chmod "$mode" "$script"
    echo "Set $owner:$group and $mode on $(basename "$script")"
  else
    echo "Missing $(basename "$script") — skipping."
  fi
done

# --- 2d) requirements.txt -----------------------------------------------------
echo "Applying owner/perms to requirements.txt..."
REQ_FILE="${PROJECT_DIR}/requirements.txt"
if [ -f "$REQ_FILE" ]; then
  sudo chown firework:"${APP_GROUP}" "$REQ_FILE"
  sudo chmod 644 "$REQ_FILE"
  echo "Set firework:${APP_GROUP} and 0644 on $(basename "$REQ_FILE")"
else
  echo "Missing requirements.txt — skipping."
fi

# --- 2e) static/ (root) -------------------------------------------------------
echo "Normalizing static/ directory and assets..."
sudo chown firework:"${APP_GROUP}" "${STATIC_DIR}"
sudo chmod 775 "${STATIC_DIR}"

declare -a STATIC_FILES=(
  "${STATIC_DIR}/scripts.js"
  "${STATIC_DIR}/styles.css"
)
for sf in "${STATIC_FILES[@]}"; do
  if [ -f "$sf" ]; then
    sudo chown firework:"${APP_GROUP}" "$sf"
    sudo chmod 644 "$sf"
    echo "Set firework:${APP_GROUP} and 0644 on $(basename "$sf")"
  else
    echo "Missing $(basename "$sf") — skipping."
  fi
done

# --- 2f) app/ tree normalization ---------------------------------------------
echo "Normalizing app/ directory tree..."

sudo chown -R firework:"${APP_GROUP}" "${APP_DIR}"
sudo find "${APP_DIR}" -type d -not -path "*/__pycache__" -exec chmod 755 {} \;
sudo find "${APP_DIR}" -type d -name "__pycache__" -exec chown firework:firework {} \; -exec chmod 775 {} \;

# Default: top-level app/*.py
sudo find "${APP_DIR}" -maxdepth 1 -type f -name "*.py" -exec chown firework:"${APP_GROUP}" {} \; -exec chmod 644 {} \;

# Exceptions
if [ -f "${APP_DIR}/routes.py" ]; then
  sudo chown firework:firework "${APP_DIR}/routes.py"
  sudo chmod 644 "${APP_DIR}/routes.py"
fi
for f in models.py utils.py; do
  if [ -f "${APP_DIR}/$f" ]; then
    sudo chown firework:"${APP_GROUP}" "${APP_DIR}/$f"
    sudo chmod 664 "${APP_DIR}/$f"
  fi
done

if [ -d "${APP_DIR}/services" ]; then
  sudo chown firework:"${APP_GROUP}" "${APP_DIR}/services"
  sudo chmod 755 "${APP_DIR}/services"
  if [ -f "${APP_DIR}/services/network_automation.py" ]; then
    sudo chown firework:firework "${APP_DIR}/services/network_automation.py"
    sudo chmod 664 "${APP_DIR}/services/network_automation.py"
  fi
fi

if [ -d "${APP_DIR}/static" ]; then
  sudo chown firework:"${APP_GROUP}" "${APP_DIR}/static"
  sudo chmod 775 "${APP_DIR}/static"
  if [ -f "${APP_DIR}/static/favicon.png" ]; then
    sudo chown firework:"${APP_GROUP}" "${APP_DIR}/static/favicon.png"
    sudo chmod 644 "${APP_DIR}/static/favicon.png"
  fi
fi

if [ -d "${APP_DIR}/templates" ]; then
  sudo chown firework:"${APP_GROUP}" "${APP_DIR}/templates"
  sudo chmod 755 "${APP_DIR}/templates"
  sudo find "${APP_DIR}/templates" -maxdepth 1 -type f -name "*.html" -exec chown firework:"${APP_GROUP}" {} \; -exec chmod 644 {} \;
fi

if [ -d "${APP_DIR}/outputs" ]; then
  sudo chown firework:"${APP_GROUP}" "${APP_DIR}/outputs"
  sudo chmod 755 "${APP_DIR}/outputs"
fi

# --- 3) Install Ansible Collections (last) ------------------------------------
echo "Installing Ansible collections..."
if ! command -v ansible-galaxy >/dev/null 2>&1; then
  echo "WARNING: 'ansible-galaxy' not found in PATH. Skipping collection installs."
else
  readonly ANSIBLE_ENV_VARS="ANSIBLE_COLLECTIONS_PATH=${ANSIBLE_COLLECTIONS_PATH} ANSIBLE_TMPDIR=${ANSIBLE_TMP_DIR}"

  # Pre-create namespace dirs
  sudo -u firework mkdir -p "${ANSIBLE_COLLECTIONS_PATH}/fortinet" "${ANSIBLE_COLLECTIONS_PATH}/paloaltonetworks"
  sudo chown firework:"${APP_GROUP}" "${ANSIBLE_COLLECTIONS_PATH}/fortinet" "${ANSIBLE_COLLECTIONS_PATH}/paloaltonetworks"
  sudo chmod 775 "${ANSIBLE_COLLECTIONS_PATH}/fortinet" "${ANSIBLE_COLLECTIONS_PATH}/paloaltonetworks"

  # fortinet.fortios
  if [ ! -d "${ANSIBLE_COLLECTIONS_PATH}/fortinet/fortios" ]; then
    echo "Installing fortinet.fortios..."
    sudo -u firework env ${ANSIBLE_ENV_VARS} \
      ansible-galaxy collection install fortinet.fortios -p "${ANSIBLE_COLLECTIONS_PATH}"
  else
    echo "fortinet.fortios collection already installed. Skipping."
  fi

  # paloaltonetworks.panos
  if [ ! -d "${ANSIBLE_COLLECTIONS_PATH}/paloaltonetworks/panos" ]; then
    echo "Installing paloaltonetworks.panos..."
    sudo -u firework env ${ANSIBLE_ENV_VARS} \
      ansible-galaxy collection install paloaltonetworks.panos -p "${ANSIBLE_COLLECTIONS_PATH}"
  else
    echo "paloaltonetworks.panos collection already installed. Skipping."
  fi

  # --- 3b) Post-install: normalize ansible_collections ownership & perms -----
  echo "Normalizing ansible_collections ownership & permissions..."
  sudo chown -R "${APP_USER}":"${APP_GROUP}" "${ANSIBLE_COLLECTIONS_PATH}"
  # Preserve execute only where it already exists; ensure dirs are executable
  sudo chmod -R u+rwX,g+rwX,o+rX "${ANSIBLE_COLLECTIONS_PATH}"
  # Ensure all directories end up 775 explicitly
  sudo find "${ANSIBLE_COLLECTIONS_PATH}" -type d -exec chmod 775 {} \;
fi

# --- 4) Final confirmation ----------------------------------------------------
cat <<EOF
========================================================
Setup complete! Project files and app/ tree normalized.
Remember to edit:
  - ${INVENTORY_FILE}
  - ${VAULT_PASS_FILE}
  - ${ENV_FILE}
========================================================
EOF
