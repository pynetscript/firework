#!/bin/bash
# A bulletproof script to set up the environment for the Firework app.
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

echo "Beginning idempotent setup for the Firework app..."

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
sudo mkdir -p "${ANSIBLE_COLLECTIONS_PATH}" "${PROJECT_DIR}/outputs" "${ANSIBLE_TMP_DIR}" "${STATIC_DIR}"

# 1c) Create files
sudo touch "${INVENTORY_FILE}" "${VAULT_PASS_FILE}" "${ENV_FILE}"

# --- 2) Ownership & permissions ----------------------------------------------
echo "Setting permissions and ownership..."

# Collections dir
sudo chown "${APP_USER}":"${APP_GROUP}" "${ANSIBLE_COLLECTIONS_PATH}"
sudo chmod 775 "${ANSIBLE_COLLECTIONS_PATH}"

# Outputs dir (setgid)
sudo chown "${APP_USER}":"${APP_GROUP}" "${PROJECT_DIR}/outputs"
sudo chmod 2775 "${PROJECT_DIR}/outputs"

# Ansible temp dir (match VM pattern)
sudo chown firework:"${APP_GROUP}" "${ANSIBLE_TMP_DIR}"
sudo chmod 775 "${ANSIBLE_TMP_DIR}"

# Key config files
sudo chown firework:"${APP_GROUP}" "${INVENTORY_FILE}"
sudo chmod 664 "${INVENTORY_FILE}"

sudo chown firework:firework "${VAULT_PASS_FILE}"
sudo chmod 640 "${VAULT_PASS_FILE}"

sudo chown firework:firework "${ENV_FILE}"
sudo chmod 600 "${ENV_FILE}"

# 2b) Enforce owner/perms for Ansible playbooks
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

# 2c) Enforce owner/perms for scripts
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

# 2d) requirements.txt
echo "Applying owner/perms to requirements.txt..."
REQ_FILE="${PROJECT_DIR}/requirements.txt"
if [ -f "$REQ_FILE" ]; then
  sudo chown firework:"${APP_GROUP}" "$REQ_FILE"
  sudo chmod 644 "$REQ_FILE"
  echo "Set firework:${APP_GROUP} and 0644 on $(basename "$REQ_FILE")"
else
  echo "Missing requirements.txt — skipping."
fi

# 2e) static/ directory & assets
echo "Normalizing static/ directory and assets..."
sudo chown firework:"${APP_GROUP}" "${STATIC_DIR}"
sudo chmod 755 "${STATIC_DIR}"

# Apply for known static files (skip if missing)
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

# --- 3) Install Ansible Collections (last) ------------------------------------
echo "Installing Ansible collections..."
readonly ANSIBLE_ENV_VARS="ANSIBLE_COLLECTIONS_PATH=${ANSIBLE_COLLECTIONS_PATH} ANSIBLE_TMPDIR=${ANSIBLE_TMP_DIR}"

if [ ! -d "${ANSIBLE_COLLECTIONS_PATH}/fortinet/fortios" ]; then
  echo "Installing fortinet.fortios..."
  sudo -u "${APP_USER}" bash -c "cd ~ && ${ANSIBLE_ENV_VARS} ansible-galaxy collection install fortinet.fortios -p '${ANSIBLE_COLLECTIONS_PATH}'"
else
  echo "fortinet.fortios collection already installed. Skipping."
fi

if [ ! -d "${ANSIBLE_COLLECTIONS_PATH}/paloaltonetworks/panos" ]; then
  echo "Installing paloaltonetworks.panos..."
  sudo -u "${APP_USER}" bash -c "cd ~ && ${ANSIBLE_ENV_VARS} ansible-galaxy collection install paloaltonetworks.panos -p '${ANSIBLE_COLLECTIONS_PATH}'"
else
  echo "paloaltonetworks.panos collection already installed. Skipping."
fi

# --- 4) Final confirmation ----------------------------------------------------
cat <<EOF

========================================================
Setup complete! Users, directories, files, playbooks, scripts, requirements.txt,
and static assets are normalized. Collections were installed at the end.

Remember to edit:
  - ${INVENTORY_FILE}
  - ${VAULT_PASS_FILE}
  - ${ENV_FILE}
========================================================
EOF
