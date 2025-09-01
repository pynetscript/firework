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
readonly PGPASS_FILE="/home/firework/.pgpass"

readonly STATIC_DIR="${PROJECT_DIR}/static"
readonly APP_DIR="${PROJECT_DIR}/app"
readonly SCRIPTS_DIR="${PROJECT_DIR}/scripts"

readonly GV_DIR="${PROJECT_DIR}/group_vars"
readonly GV_ALL="${GV_DIR}/all"
readonly GV_VAULT="${GV_ALL}/vault.yml"

readonly SERVICE_FILE="/etc/systemd/system/firework.service"
readonly NGINX_SITE="/etc/nginx/sites-available/firework"
readonly NGINX_LINK="/etc/nginx/sites-enabled/firework"

echo "========================================================"
echo "Starting script..."

# --- 0) System packages: pip, venv, Ansible ----------------------------------
echo "[1/8] Ensuring system packages are installed..."
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo apt-get install -y software-properties-common

  if ! command -v pip3 >/dev/null 2>&1; then
    echo "Installing python3-pip..."
    sudo apt-get install -y python3-pip
  else
    echo "python3-pip already installed. Skipping."
  fi

  if ! python3 -m venv -h >/dev/null 2>&1; then
    echo "Installing python3-venv..."
    sudo apt-get install -y python3-venv
  else
    echo "python3-venv already installed. Skipping."
  fi

  if ! command -v ansible >/dev/null 2>&1; then
    echo "Adding Ansible PPA and installing Ansible..."
    sudo add-apt-repository --yes --update ppa:ansible/ansible
    sudo apt-get install -y ansible
  else
    echo "Ansible already installed. Skipping."
  fi
else
  echo "apt-get not found; skipping system package installation."
fi

# --- 1) Create users, folders, files -----------------------------------------
echo "[2/8] Creating users, folders, and files if they do not exist..."

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

# Add application user to firework group (for traversal when /home/firework is 750/755)
sudo usermod -aG firework "${APP_USER}"

# 1b) Create directories
sudo mkdir -p \
  "${ANSIBLE_COLLECTIONS_PATH}" \
  "${PROJECT_DIR}/outputs" \
  "${ANSIBLE_TMP_DIR}" \
  "${STATIC_DIR}" \
  "${APP_DIR}" \
  "${SCRIPTS_DIR}" \
  "${GV_ALL}"

# 1c) Create files
sudo touch "${INVENTORY_FILE}" "${VAULT_PASS_FILE}" "${ENV_FILE}"

# Ensure .pgpass exists (empty is fine; you can fill later)
if [ ! -f "${PGPASS_FILE}" ]; then
  sudo -u firework touch "${PGPASS_FILE}"
fi

# --- 2) Path posture  --------------------------------------------------------
echo "[3/8] Applying path posture..."
# Make /home/firework traversable and project dir group=www-data, mode=755
sudo chmod 755 /home/firework
sudo chgrp "${APP_GROUP}" "${PROJECT_DIR}"
sudo chmod 755 "${PROJECT_DIR}"

# --- 3) Ownership & permissions ----------------------------------------------
echo "[4/8] Setting ownership and permissions..."

# Ansible collections dir (owned by firework for ansible-galaxy to write)
sudo chown firework:"${APP_GROUP}" "${ANSIBLE_COLLECTIONS_PATH}"
sudo chmod 775 "${ANSIBLE_COLLECTIONS_PATH}"

# Outputs dir (setgid so group is preserved)
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

sudo chown firework:firework "${PGPASS_FILE}"
sudo chmod 600 "${PGPASS_FILE}"

# group_vars / vault.yml normalization
sudo chown -R firework:"${APP_GROUP}" "${GV_DIR}"
sudo find "${GV_DIR}" -type d -exec chmod 750 {} \;
# If vault.yml exists, lock it down
if [ -f "${GV_VAULT}" ]; then
  sudo chown firework:"${APP_GROUP}" "${GV_VAULT}"
  sudo chmod 640 "${GV_VAULT}"
else
  # Optionally create an encrypted stub if ansible-vault & vault pass are present
  if command -v ansible-vault >/dev/null 2>&1 && [ -f "${VAULT_PASS_FILE}" ]; then
    echo "Creating encrypted stub ${GV_VAULT}..."
    tmp_plain="$(mktemp)"
    printf -- "---\n# Put your encrypted variables here\n" | sudo tee "${tmp_plain}" >/dev/null
    sudo -u firework ansible-vault encrypt --vault-password-file "${VAULT_PASS_FILE}" \
      --output "${GV_VAULT}" "${tmp_plain}"
    sudo rm -f "${tmp_plain}"
    sudo chown firework:"${APP_GROUP}" "${GV_VAULT}"
    sudo chmod 640 "${GV_VAULT}"
  else
    echo "Skipping auto-create of ${GV_VAULT} (ansible-vault or vault pass file not available)."
  fi
fi

# --- 3b) Playbooks in project root (leave as-is for now) ---------------------
echo "Normalizing playbooks in project root..."
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
  fi
done

# --- 3c) Scripts under scripts/ ----------------------------------------------
echo "Normalizing scripts/ directory and files..."
# scripts/ dir itself (baseline)
sudo chown -R firework:"${APP_GROUP}" "${SCRIPTS_DIR}"
sudo find "${SCRIPTS_DIR}" -type d -exec chmod 755 {} \;
sudo find "${SCRIPTS_DIR}" -type f -name "*.sh" -exec chmod 755 {} \;

# per-file owner/mode overrides
declare -A SCRIPTS=(
  ["${SCRIPTS_DIR}/add_default_users.sh"]="firework:${APP_GROUP}:755"
  ["${SCRIPTS_DIR}/clean.sh"]="firework:${APP_GROUP}:755"
  ["${SCRIPTS_DIR}/install.sh"]="firework:${APP_GROUP}:755"
  ["${SCRIPTS_DIR}/setup.sh"]="firework:firework:755"
  ["${SCRIPTS_DIR}/start_firework.sh"]="firework:firework:775"
  ["${SCRIPTS_DIR}/status_firework.sh"]="firework:firework:775"
  ["${SCRIPTS_DIR}/stop_firework.sh"]="firework:firework:775"
)
for script in "${!SCRIPTS[@]}"; do
  if [ -f "$script" ]; then
    IFS=":" read -r owner group mode <<<"${SCRIPTS[$script]}"
    sudo chown "$owner":"$group" "$script"
    sudo chmod "$mode" "$script"
  fi
done

# run.py stays at repo root; keep it executable for convenience
if [ -f "${PROJECT_DIR}/run.py" ]; then
  sudo chown firework:"${APP_GROUP}" "${PROJECT_DIR}/run.py"
  sudo chmod 755 "${PROJECT_DIR}/run.py"
fi

# --- 3d) requirements.txt -----------------------------------------------------
echo "Normalizing requirements.txt (if present)..."
REQ_FILE="${PROJECT_DIR}/requirements.txt"
if [ -f "$REQ_FILE" ]; then
  sudo chown firework:"${APP_GROUP}" "$REQ_FILE"
  sudo chmod 644 "$REQ_FILE"
fi

# --- 3e) static/ (project root) ----------------------------------------------
echo "Normalizing static/ directory (project root)..."
sudo chown firework:"${APP_GROUP}" "${STATIC_DIR}"
sudo chmod 775 "${STATIC_DIR}"
for sf in "${STATIC_DIR}/scripts.js" "${STATIC_DIR}/styles.css"; do
  if [ -f "$sf" ]; then
    sudo chown firework:"${APP_GROUP}" "$sf"
    sudo chmod 644 "$sf"
  fi
done

# --- 3f) app/ tree normalization ---------------------------------------------
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

# --- 4) PostgreSQL: install & configure --------------------------------------
echo "[5/8] Installing and configuring PostgreSQL..."
# Install packages if missing
if ! dpkg -s postgresql >/dev/null 2>&1; then
  sudo apt-get install -y postgresql postgresql-contrib
fi
# Enable & start service
sudo systemctl enable --now postgresql >/dev/null 2>&1 || true

# Create role 'firework' if missing
if ! sudo -u postgres psql -Atqc "SELECT 1 FROM pg_roles WHERE rolname='firework'" | grep -q 1; then
  sudo -u postgres psql -c "CREATE USER firework WITH PASSWORD 'firework';"
fi
# Ensure CREATEDB on role
sudo -u postgres psql -c "ALTER ROLE firework CREATEDB;" >/dev/null

# Create database if missing, owned by firework
if ! sudo -u postgres psql -Atqc "SELECT 1 FROM pg_database WHERE datname='fireworkdb'" | grep -q 1; then
  sudo -u postgres psql -c "CREATE DATABASE fireworkdb OWNER firework;"
fi
# Grant privileges (idempotent)
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE fireworkdb TO firework;" >/dev/null

# Ensure .pgpass has localhost entry
grep -q "^localhost:5432:\*:firework:" "${PGPASS_FILE}" 2>/dev/null || echo "localhost:5432:*:firework:firework" | sudo tee -a "${PGPASS_FILE}" >/dev/null
sudo chown firework:firework "${PGPASS_FILE}"
sudo chmod 600 "${PGPASS_FILE}"

# --- 5) Install Ansible Collections (last-ish) --------------------------------
echo "[6/8] Installing Ansible collections..."
if ! command -v ansible-galaxy >/dev/null 2>&1; then
  echo "WARNING: 'ansible-galaxy' not found in PATH. Skipping collection installs."
else
  readonly ANSIBLE_ENV_VARS="ANSIBLE_COLLECTIONS_PATH=${ANSIBLE_COLLECTIONS_PATH} ANSIBLE_TMPDIR=${ANSIBLE_TMP_DIR}"

  # Pre-create namespace dirs to avoid path bugs
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

  # Post-install: normalize ansible_collections ownership & perms
  echo "Normalizing ansible_collections ownership & permissions..."
  sudo chown -R firework:"${APP_GROUP}" "${ANSIBLE_COLLECTIONS_PATH}"
  sudo chmod -R u+rwX,g+rwX,o+rX "${ANSIBLE_COLLECTIONS_PATH}"
  sudo find "${ANSIBLE_COLLECTIONS_PATH}" -type d -exec chmod 775 {} \;
fi

# --- 6) Install & configure Nginx --------------------------------------------
echo "[7/8] Installing and configuring Nginx..."
# install nginx if missing
if ! command -v nginx >/dev/null 2>&1; then
  sudo apt-get install -y nginx
fi

# write your site config
sudo tee "${NGINX_SITE}" >/dev/null <<'NGINX'
server {
    listen 80;
    server_name _;

    # Serve static files directly from the app/static directory
    location /static {
        alias /home/firework/firework/app/static;
        expires 30d;
        access_log on; # Keep access logging on for debugging
        log_not_found off;
    }

    # Proxy all other requests to the Gunicorn Unix socket
    location / {
        include proxy_params;
        proxy_pass http://unix:/tmp/firework.sock;
        proxy_read_timeout 180;
        proxy_connect_timeout 180;
        proxy_send_timeout 180;
    }
}
NGINX
sudo chown root:root "${NGINX_SITE}"
sudo chmod 0644 "${NGINX_SITE}"

# enable site, remove default
sudo ln -sf "${NGINX_SITE}" "${NGINX_LINK}"
[ -e /etc/nginx/sites-enabled/default ] && sudo rm -f /etc/nginx/sites-enabled/default || true

# test and restart
sudo nginx -t
sudo systemctl restart nginx

# --- 7) Create systemd service if missing ------------------------------------
echo "[8/8] Create systemd service if missing..."
if [ ! -f "${SERVICE_FILE}" ]; then
  echo "Creating systemd service at ${SERVICE_FILE}..."
  sudo tee "${SERVICE_FILE}" >/dev/null <<'UNIT'
[Unit]
Description=Gunicorn instance to serve Firework Flask app
After=network.target postgresql.service

[Service]
User=firework_app_user
Group=www-data
WorkingDirectory=/home/firework/firework
Environment="HOME=/home/firework_app_user"
Environment="ANSIBLE_CACHE_DIR=/home/firework_app_user/.ansible/cache"
Environment="ANSIBLE_TMPDIR=/home/firework_app_user/.ansible/tmp"
Environment="FIREWORK_VAULT_PASS_FILE=/home/firework/firework/.vault_pass.txt"
EnvironmentFile=/home/firework/firework/.env
ExecStart=/home/firework/firework/venv/bin/gunicorn --workers 3 --bind unix:/tmp/firework.sock --timeout 120 run:app
Restart=always

[Install]
WantedBy=multi-user.target
UNIT
  sudo chmod 0644 "${SERVICE_FILE}"
  sudo chown root:root "${SERVICE_FILE}"
  sudo systemctl daemon-reload
else
  echo "Systemd service already exists at ${SERVICE_FILE}. Skipping creation."
fi

# --- Final confirmation -------------------------------------------------------
cat <<EOF
========================================================
Setup complete!
- Nginx site: ${NGINX_SITE}
- Systemd unit: ${SERVICE_FILE}
- PostgreSQL: role 'firework' and DB 'fireworkdb' ensured

Remember to edit:
- ${INVENTORY_FILE}
- ${VAULT_PASS_FILE}
- ${ENV_FILE}
- ${GV_VAULT} (encrypted)
========================================================
EOF
