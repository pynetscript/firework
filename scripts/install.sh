#!/bin/bash
# Firework installer: system deps, config, permissions, PostgreSQL, Ansible, Nginx,
# systemd unit, Python venv + deps, DB migrations, default users, and service start.
# Idempotent; safe to run multiple times.

set -Eeuo pipefail

# --- Vars --------------------------------------------------------------------
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

readonly VENV_DIR="${PROJECT_DIR}/venv"
readonly REQ_FILE="${PROJECT_DIR}/requirements.txt"
readonly MIGRATIONS_DIR="${PROJECT_DIR}/migrations"
readonly FLASK_APP_FILE="${PROJECT_DIR}/run.py"

EDITOR="${EDITOR:-nano}"

# --- Helpers -----------------------------------------------------------------
ask_yes_no () {
  local prompt="${1:-Continue?} [y/N]: "
  local ans
  read -r -p "$prompt" ans || true
  case "${ans:-}" in
    y|Y|yes|YES) return 0 ;;
    *) return 1 ;;
  esac
}

gen_secret_key () {
  if command -v python3 >/dev/null 2>&1; then
    python3 - <<'PY'
import secrets, base64
print(base64.b64encode(secrets.token_bytes(32)).decode())
PY
  elif command -v openssl >/dev/null 2>&1; then
    openssl rand -base64 32
  else
    date +%s%N | sha256sum | awk '{print $1}'
  fi
}

# Prompt for DB details (hidden password)
prompt_db_details () {
  echo "Please enter database connection details:"
  read -r -p "DB host [localhost]: " DB_HOST || true
  DB_HOST="${DB_HOST:-localhost}"

  read -r -p "DB port [5432]: " DB_PORT || true
  DB_PORT="${DB_PORT:-5432}"

  read -r -p "DB name [fireworkdb]: " DB_NAME || true
  DB_NAME="${DB_NAME:-fireworkdb}"

  read -r -p "DB user [firework]: " DB_USER || true
  DB_USER="${DB_USER:-firework}"

  printf "DB pass [........]: "
  stty -echo
  read -r DB_PASS || true
  stty echo
  echo
  while [ -z "${DB_PASS:-}" ]; do
    echo "Password cannot be empty."
    printf "DB pass [........]: "
    stty -echo
    read -r DB_PASS || true
    stty echo
    echo
  done
}

# Create ENV file from captured values
write_env_file () {
  local sk="$1"
  local host="$2" port="$3" db="$4" user="$5" pass="$6"
  sudo tee "${ENV_FILE}" >/dev/null <<EOF
SECRET_KEY="${sk}"
DATABASE_URL="postgresql://${user}:${pass}@${host}:${port}/${db}"
EOF
  echo "${ENV_FILE}: OK"
}

write_inventory_example () {
  sudo tee "${INVENTORY_FILE}" >/dev/null <<'INV'
all:
  vars:
    ansible_user: admin
    ansible_connection: network_cli

  children:
    cisco_ios:
      hosts:
        R1:
          ansible_host: 10.250.10.111
          ansible_network_os: cisco.ios.ios
        R2:
          ansible_host: 10.250.10.112
          ansible_network_os: cisco.ios.ios
        R3:
          ansible_host: 10.250.10.113
          ansible_network_os: cisco.ios.ios
        SW1:
          ansible_host: 10.250.10.110
          ansible_network_os: cisco.ios.ios

    fortinet:
      hosts:
        fgt:
          ansible_host: 10.250.10.101
          ansible_network_os: fortinet.fortios.fortios
          ansible_httpapi_use_ssl: yes
          ansible_httpapi_validate_certs: no
          ansible_connection: httpapi
          ansible_httpapi_pass: "{{ fortinet_api_password }}"

    paloalto:
      hosts:
        pafw:
          ansible_host: 10.250.10.161
          ansible_network_os: paloaltonetworks.panos.panos
          ansible_connection: httpapi
          ansible_user: admin
          ansible_password: "{{ paloalto_api_password }}"
          ansible_httpapi_use_ssl: yes
          ansible_httpapi_validate_certs: no
INV
}

is_local_host () {
  case "${1}" in
    localhost|127.0.0.1|::1) return 0 ;;
    *) return 1 ;;
  esac
}

# Escape single quotes for SQL
sql_escape () {
  printf "%s" "$1" | sed "s/'/''/g"
}

# YAML-quote a value (single quotes, with inner quotes doubled)
yaml_quote () {
  local v="${1-}"
  v="${v//\'/\'\'}"
  printf "'%s'" "$v"
}

# --- Start -------------------------------------------------------------------
echo "========================================================"
echo "Installation started..."

# 1) System packages ----------------------------------------------------------
echo "--------------------------------------------------------"
echo "[1/11] Ensuring system packages are installed..."
export DEBIAN_FRONTEND=noninteractive
if command -v apt-get >/dev/null 2>&1; then
  sudo apt-get update -y
  sudo apt-get install -y software-properties-common
  command -v pip3 >/dev/null 2>&1 || sudo apt-get install -y python3-pip
  python3 -m venv -h >/dev/null 2>&1 || sudo apt-get install -y python3-venv
  if ! command -v ansible >/dev/null 2>&1; then
    sudo add-apt-repository --yes --update ppa:ansible/ansible
    sudo apt-get install -y ansible
  fi
  pip install pan-os-python --break-system-packages
  sudo -u firework_app_user pip install pan-os-python --break-system-packages
  dpkg -s postgresql >/dev/null 2>&1 || sudo apt-get install -y postgresql postgresql-contrib
  command -v nginx >/dev/null 2>&1 || sudo apt-get install -y nginx
else
  echo "apt-get not found; skipping package installation."
fi

# 2) Users/dirs/files ---------------------------------------------------------
echo "--------------------------------------------------------"
echo "[2/11] Creating users, folders, and files..."
if ! id "${APP_USER}" &>/dev/null; then
  sudo useradd -m -r -s /usr/sbin/nologin -g "${APP_GROUP}" "${APP_USER}"
else
  [ -d "/home/${APP_USER}" ] || sudo mkdir -p "/home/${APP_USER}"
fi
sudo usermod -aG firework "${APP_USER}"
sudo -u "${APP_USER}" mkdir -p "/home/${APP_USER}/.ansible/cache" "/home/${APP_USER}/.ansible/tmp"
sudo chown -R "${APP_USER}":"${APP_GROUP}" "/home/${APP_USER}/.ansible"
sudo chmod 700 "/home/${APP_USER}"
sudo find "/home/${APP_USER}/.ansible" -type d -exec chmod 700 {} \;

sudo mkdir -p \
  "${ANSIBLE_COLLECTIONS_PATH}" \
  "${PROJECT_DIR}/outputs" \
  "${ANSIBLE_TMP_DIR}" \
  "${STATIC_DIR}" \
  "${APP_DIR}" \
  "${SCRIPTS_DIR}" \
  "${GV_ALL}"
# ADD THIS LINE TO FIX THE ENCRYPTION PERMISSION ERROR
sudo chown firework:firework "${GV_ALL}"

sudo touch "${INVENTORY_FILE}" "${VAULT_PASS_FILE}" "${ENV_FILE}"
[ -f "${PGPASS_FILE}" ] || sudo -u firework touch "${PGPASS_FILE}"

# 3) Interactive config -------------------------------------------------------
echo "--------------------------------------------------------"
echo "[3/11] Interactive configuration (.env, inventory, vault pass, vault.yml)..."

# 3a) .env
echo "#################################################################################"
read -r -p "Please enter a SECRET_KEY or leave blank to auto-generate [${ENV_FILE}]: " SK || true
if [ -z "${SK:-}" ]; then
  SK="$(gen_secret_key)"
  echo "#################################################################################"
fi
DB_HOST=""; DB_PORT=""; DB_NAME=""; DB_USER=""; DB_PASS=""
prompt_db_details
write_env_file "${SK}" "${DB_HOST}" "${DB_PORT}" "${DB_NAME}" "${DB_USER}" "${DB_PASS}"


# 3b) inventory.yml
echo "#################################################################################"
if ask_yes_no "Populate inventory.yml with example template?"; then
  write_inventory_example
  echo "${INVENTORY_FILE}: OK"
elif ask_yes_no "Open ${INVENTORY_FILE} in ${EDITOR} now?"; then
  sudo "${EDITOR}" "${INVENTORY_FILE}"
fi

# 3c) .vault_pass.txt
echo "#################################################################################"
read -r -s -p "Please enter a password for vault_pass.txt: " VPASS; echo
printf "%s\n" "${VPASS}" | sudo tee "${VAULT_PASS_FILE}" >/dev/null
echo "${VAULT_PASS_FILE}: OK"

# 3d) group_vars/all/vault.yml
echo "#################################################################################"
if command -v ansible-vault >/dev/null 2>&1 && [ -s "${VAULT_PASS_FILE}" ]; then
  echo "Please provide passwords/keys for network devices to store in ${GV_VAULT}."
  read -r -p "ansible_password: " APASS || true
  read -r -p "fortinet_api_password: " FNPASS || true
  read -r -p "fortinet_api_access_token: " FNTOK || true
  read -r -p "paloalto_api_password: " PAPASS || true

  # YAML-quoted values (single quotes, inner quotes doubled)
  APASS_YAML="${APASS}"
  FNPASS_YAML="${FNPASS}"
  FNTOK_YAML="${FNTOK}"
  PAPASS_YAML="${PAPASS}"

  tmp_yaml="$(sudo -u firework mktemp)"
  sudo -u firework tee "${tmp_yaml}" >/dev/null <<YML
---
ansible_password: ${APASS_YAML}
fortinet_api_password: ${FNPASS_YAML}
fortinet_api_access_token: ${FNTOK_YAML}
paloalto_api_password: ${PAPASS_YAML}
YML

  if sudo -u firework ansible-vault encrypt \
       --vault-password-file "${VAULT_PASS_FILE}" \
       --output "${GV_VAULT}" "${tmp_yaml}" >/dev/null 2>&1; then
    sudo rm -f "${tmp_yaml}"
    echo "${GV_VAULT}: OK"
    echo "Note: You can edit later with: ansible-vault edit ${GV_VAULT} --vault-password-file ${VAULT_PASS_FILE}"
  else
    echo "Encryption FAILED; leaving plaintext temp at: ${tmp_yaml}"
    echo "You can inspect it, then encrypt manually:"
    echo "  ansible-vault encrypt ${tmp_yaml} --vault-password-file ${VAULT_PASS_FILE} --output ${GV_VAULT}"
  fi
else
  echo "ansible-vault not available or ${VAULT_PASS_FILE} empty."
  echo "Writing PLAINTEXT ${GV_VAULT} (you should encrypt it later):"
  APASS_YAML="$(yaml_quote "admin")"
  sudo tee "${GV_VAULT}" >/dev/null <<YML
---
# WARNING: PLAINTEXT (not encrypted) — later run:
#   ansible-vault encrypt ${GV_VAULT} --vault-password-file ${VAULT_PASS_FILE}
ansible_password: ${APASS_YAML}
fortinet_api_password: ''
fortinet_api_access_token: ''
paloalto_api_password: ''
YML
fi

# 4) Path posture -------------------------------------------------------------
echo "--------------------------------------------------------"
echo "[4/11] Applying path posture..."
sudo chmod 755 /home/firework
sudo chgrp "${APP_GROUP}" "${PROJECT_DIR}"
sudo chmod 755 "${PROJECT_DIR}"

# 5) Ownership & permissions ---------------------------------------------------
echo "--------------------------------------------------------"
echo "[5/11] Setting ownership and permissions..."

# /ansible_collections
sudo chown -R firework:firework "${ANSIBLE_COLLECTIONS_PATH}"
sudo chmod 775 "${ANSIBLE_COLLECTIONS_PATH}"

# /outputs
sudo chown "${APP_USER}":"${APP_GROUP}" "${PROJECT_DIR}/outputs"
sudo chmod 2775 "${PROJECT_DIR}/outputs"

# /ansible_tmp
sudo chown firework:"${APP_GROUP}" "${ANSIBLE_TMP_DIR}"
sudo chmod 775 "${ANSIBLE_TMP_DIR}"

# inventory.yml
sudo chown firework:"${APP_GROUP}" "${INVENTORY_FILE}"
sudo chmod 664 "${INVENTORY_FILE}"

# .vault_pass.txt
sudo chown firework:"${APP_GROUP}" "${VAULT_PASS_FILE}"
sudo chmod 640 "${VAULT_PASS_FILE}"

# .env
sudo chown firework:firework "${ENV_FILE}"
sudo chmod 600 "${ENV_FILE}"

# .pgpass
sudo chown firework:firework "${PGPASS_FILE}"
sudo chmod 600 "${PGPASS_FILE}"

# group_vars/all/vault.yml
sudo chown -R firework:firework "${GV_DIR}"
sudo chmod 775 "${GV_DIR}"
sudo chown -R firework:firework "${GV_ALL}"
sudo chmod 775 "${GV_ALL}"
sudo chown firework:"${APP_GROUP}" "${GV_VAULT}"
sudo chmod 640 "${GV_VAULT}"

# playbooks
declare -a PLAYBOOKS_ROOT=(
  "${PROJECT_DIR}/post_check_firewall_rule_fortinet.yml"
  "${PROJECT_DIR}/post_check_firewall_rule_paloalto.yml"
  "${PROJECT_DIR}/pre_check_firewall_rule_fortinet.yml"
  "${PROJECT_DIR}/pre_check_firewall_rule_paloalto.yml"
  "${PROJECT_DIR}/provision_firewall_rule_fortinet.yml"
  "${PROJECT_DIR}/provision_firewall_rule_paloalto.yml"
)
for pb in "${PLAYBOOKS_ROOT[@]}"; do
  [ -f "$pb" ] || continue
  sudo chown firework:firework "$pb"
  sudo chmod 664 "$pb"
done

# scripts/
sudo chown -R firework:firework "${SCRIPTS_DIR}"
sudo find "${SCRIPTS_DIR}" -type d -exec chmod 775 {} \;
sudo find "${SCRIPTS_DIR}" -type f -name "*.sh" -exec chmod 775 {} \;

# run.py
[ -f "${PROJECT_DIR}/run.py" ] && sudo chown firework:firework "${PROJECT_DIR}/run.py" && sudo chmod 775 "${PROJECT_DIR}/run.py"

# requirements.txt
[ -f "${PROJECT_DIR}/requirements.txt" ] && sudo chown firework:"${APP_GROUP}" "${PROJECT_DIR}/requirements.txt" && sudo chmod 644 "${PROJECT_DIR}/requirements.txt"

# collector.yml
[ -f "${PROJECT_DIR}/collector.yml" ] && sudo chown firework:firework "${PROJECT_DIR}/collector.yml" && sudo chmod 664 "${PROJECT_DIR}/collector.yml"

# /static
sudo chown firework:"${APP_GROUP}" "${STATIC_DIR}"
sudo chmod 755 "${STATIC_DIR}"
for sf in "${STATIC_DIR}/scripts.js" "${STATIC_DIR}/styles.css"; do
  [ -f "$sf" ] || continue
  sudo chown firework:"${APP_GROUP}" "$sf"
  sudo chmod 755 "$sf"
done

# /app
sudo chown -R firework:"${APP_GROUP}" "${APP_DIR}"
sudo find "${APP_DIR}" -type d -not -path "*/__pycache__" -exec chmod 755 {} \;
sudo find "${APP_DIR}" -type d -name "__pycache__" -exec chown firework:firework {} \; -exec chmod 775 {} \;
sudo find "${APP_DIR}" -maxdepth 1 -type f -name "*.py" -exec chown firework:"${APP_GROUP}" {} \; -exec chmod 644 {} \;
[ -f "${APP_DIR}/routes.py" ] && sudo chown firework:firework "${APP_DIR}/routes.py" && sudo chmod 644 "${APP_DIR}/routes.py"
for f in models.py utils.py; do
  [ -f "${APP_DIR}/$f" ] && sudo chown firework:"${APP_GROUP}" "${APP_DIR}/$f" && sudo chmod 664 "${APP_DIR}/$f"
done
if [ -d "${APP_DIR}/services" ]; then
  sudo chown firework:"${APP_GROUP}" "${APP_DIR}/services"
  sudo chmod 755 "${APP_DIR}/services"
  [ -f "${APP_DIR}/services/network_automation.py" ] && sudo chown firework:firework "${APP_DIR}/services/network_automation.py" && sudo chmod 664 "${APP_DIR}/services/network_automation.py"
fi
if [ -d "${APP_DIR}/static" ]; then
  sudo chown firework:"${APP_GROUP}" "${APP_DIR}/static"
  sudo chmod 775 "${APP_DIR}/static"
  [ -f "${APP_DIR}/static/favicon.png" ] && sudo chown firework:"${APP_GROUP}" "${APP_DIR}/static/favicon.png" && sudo chmod 644 "${APP_DIR}/static/favicon.png"
fi
if [ -d "${APP_DIR}/templates" ]; then
  sudo chown firework:"${APP_GROUP}" "${APP_DIR}/templates"
  sudo chmod 755 "${APP_DIR}/templates"
  sudo find "${APP_DIR}/templates" -maxdepth 1 -type f -name "*.html" -exec chown firework:"${APP_GROUP}" {} \; -exec chmod 644 {} \;
fi
[ -d "${APP_DIR}/outputs" ] && sudo chown firework:"${APP_GROUP}" "${APP_DIR}/outputs" && sudo chmod 755 "${APP_DIR}/outputs"

# 6) PostgreSQL ---------------------------------------------------------------
echo "--------------------------------------------------------"
echo "[6/11] Installing and configuring PostgreSQL..."
sudo systemctl enable --now postgresql >/dev/null 2>&1 || true

# Use just-captured DB_* to set up local DB if host is local
if is_local_host "${DB_HOST}"; then
  if ! sudo -u postgres psql -Atqc "SELECT 1 FROM pg_roles WHERE rolname='${DB_USER}'" | grep -q 1; then
    DB_PASS_ESC="$(sql_escape "${DB_PASS}")"
    sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE USER ${DB_USER} WITH PASSWORD '${DB_PASS_ESC}';"
  fi
  sudo -u postgres psql -v ON_ERROR_STOP=1 -c "ALTER ROLE ${DB_USER} CREATEDB;" >/dev/null
  if ! sudo -u postgres psql -Atqc "SELECT 1 FROM pg_database WHERE datname='${DB_NAME}'" | grep -q 1; then
    sudo -u postgres psql -v ON_ERROR_STOP=1 -c "CREATE DATABASE ${DB_NAME} OWNER ${DB_USER};"
  fi
  sudo -u postgres psql -v ON_ERROR_STOP=1 -c "GRANT ALL PRIVILEGES ON DATABASE ${DB_NAME} TO ${DB_USER};" >/dev/null
else
  echo "Remote DB host '${DB_HOST}' detected — skipping local role/DB creation."
fi

# Ensure .pgpass has the captured creds
grep -q "^${DB_HOST}:${DB_PORT}:\*:${DB_USER}:" "${PGPASS_FILE}" 2>/dev/null || \
  echo "${DB_HOST}:${DB_PORT}:*:${DB_USER}:${DB_PASS}" | sudo tee -a "${PGPASS_FILE}" >/dev/null
sudo chown firework:firework "${PGPASS_FILE}"
sudo chmod 600 "${PGPASS_FILE}"

# --- PostgreSQL verification (like nginx -t) ---
if command -v psql >/dev/null 2>&1; then
  echo "psql client: $(psql --version 2>/dev/null || echo 'unknown')"
  if PGPASSFILE="${PGPASS_FILE}" psql -h "${DB_HOST}" -p "${DB_PORT}" -U "${DB_USER}" -d "${DB_NAME}" -tAc "SELECT 1" >/dev/null 2>&1; then
    echo "PostgreSQL: OK"
  else
    echo "PostgreSQL: FAIL"
  fi
fi

# 7) Ansible collections ------------------------------------------------------
echo "--------------------------------------------------------"
echo "[7/11] Installing Ansible collections..."
if command -v ansible-galaxy >/dev/null 2>&1; then
  readonly ANSIBLE_ENV_VARS="ANSIBLE_COLLECTIONS_PATH=${ANSIBLE_COLLECTIONS_PATH} ANSIBLE_TMPDIR=${ANSIBLE_TMP_DIR}"
  #sudo chown "${APP_USER}":"${APP_GROUP}" "${ANSIBLE_COLLECTIONS_PATH}/fortinet" "${ANSIBLE_COLLECTIONS_PATH}/paloaltonetworks"
  #sudo chmod 775 "${ANSIBLE_COLLECTIONS_PATH}/fortinet" "${ANSIBLE_COLLECTIONS_PATH}/paloaltonetworks"

  sudo -u firework env ${ANSIBLE_ENV_VARS:-ANSIBLE_COLLECTIONS_PATH=${ANSIBLE_COLLECTIONS_PATH} ANSIBLE_TMPDIR=${ANSIBLE_TMP_DIR}} \
    ansible-galaxy collection install --force -p "${ANSIBLE_COLLECTIONS_PATH}" \
      fortinet.fortios:2.4.0 paloaltonetworks.panos:3.0.1

  # Normalize ownership/perms afterward
  sudo chown -R "${APP_USER}":"${APP_GROUP}" "${ANSIBLE_COLLECTIONS_PATH}"
  sudo chmod -R u+rwX,g+rwX,o+rX "${ANSIBLE_COLLECTIONS_PATH}"
  sudo find "${ANSIBLE_COLLECTIONS_PATH}" -type d -exec chmod 775 {} \;
else
  echo "WARNING: ansible-galaxy not found; skipped collections."
fi

# 8) Nginx --------------------------------------------------------------------
echo "--------------------------------------------------------"
echo "[8/11] Installing and configuring Nginx..."
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
sudo ln -sf "${NGINX_SITE}" "${NGINX_LINK}"
[ -e /etc/nginx/sites-enabled/default ] && sudo rm -f /etc/nginx/sites-enabled/default || true

# Test config and restart
if sudo nginx -t; then
  sudo systemctl restart nginx
  sudo systemctl enable nginx >/dev/null 2>&1 || true
else
  echo "nginx -t failed; see errors above."
fi

# Verify service is running
nginx_state="$(systemctl is-active nginx 2>/dev/null || true)"
echo "nginx: OK"
if [ "${nginx_state}" != "active" ]; then
  echo "nginx: FAIL"
  sudo journalctl -u nginx --no-pager -n 30 || true
fi

# 9) systemd ------------------------------------------------------------------
echo "--------------------------------------------------------"
echo "[9/11] Create systemd service if missing..."
if [ ! -f "${SERVICE_FILE}" ]; then
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
Environment="ANSIBLE_COLLECTIONS_PATH=/home/firework/firework/ansible_collections:/home/firework_app_user/.ansible/collections:/usr/share/ansible/collections"
Environment="ANSIBLE_CONFIG=/home/firework/firework/ansible.cfg"
EnvironmentFile=/home/firework/firework/.env
ExecStart=/home/firework/firework/venv/bin/gunicorn --workers 3 --bind unix:/tmp/firework.sock --timeout 120 run:app
Restart=always

[Install]
WantedBy=multi-user.target
UNIT
  sudo chmod 0644 "${SERVICE_FILE}"
  sudo chown root:root "${SERVICE_FILE}"
  sudo systemctl daemon-reload
  sudo systemctl enable firework >/dev/null 2>&1 || true
  echo "Systemd service: OK"
else
  echo "Systemd service: Already exists; skipping."
fi

# 10) App setup: venv, deps, migrations, default users ------------------------
echo "--------------------------------------------------------"
echo "[10/11] Python venv, dependencies, DB migrations, default users..."

PY_BIN="$(command -v python3 || true)"
if [ -z "$PY_BIN" ]; then
  echo "Python 3 not found. FAIL"
  exit 1
fi

# Ensure venv support
if ! "$PY_BIN" -c "import ensurepip" >/dev/null 2>&1; then
  PYV="$("$PY_BIN" - <<'PY'
import sys; print(f"python{sys.version_info.major}.{sys.version_info.minor}")
PY
)"
  VENV_PKG="${PYV}-venv"
  if command -v apt-get >/dev/null 2>&1; then
    if [ "$EUID" -ne 0 ]; then SUDO="sudo"; else SUDO=""; fi
    export DEBIAN_FRONTEND=noninteractive
    $SUDO apt-get update -y
    $SUDO apt-get install -y "$VENV_PKG" || $SUDO apt-get install -y python3-venv
  else
    "$PY_BIN" -m ensurepip --upgrade || true
  fi
fi

# (Re)create venv if missing/broken
if [ ! -f "$VENV_DIR/bin/activate" ]; then
  rm -rf "$VENV_DIR"
  "$PY_BIN" -m venv "$VENV_DIR" || { echo "Create venv: FAIL"; exit 1; }
fi

# shellcheck disable=SC1090
. "$VENV_DIR/bin/activate"
python -m pip install -U pip wheel setuptools || { echo "pip bootstrap: FAIL"; deactivate; exit 1; }

# Install deps
if [ -f "${REQ_FILE}" ]; then
  echo "Installing dependencies from ${REQ_FILE}..."
  pip install --upgrade pip
  pip install -r "${REQ_FILE}"
else
  echo "WARNING: ${REQ_FILE} not found; skipping pip install."
fi

# Flask app env
export FLASK_APP="${FLASK_APP_FILE}"
echo "FLASK_APP set to ${FLASK_APP}"

# Initialize migrations if missing
if [ ! -d "${MIGRATIONS_DIR}" ]; then
  echo "Initializing Flask-Migrate repository..."
  (cd "${PROJECT_DIR}" && flask db init)
else
  echo "Flask-Migrate repository already initialized."
fi

# Patch migrations/env.py (idempotent)
ENV_PY_FILE="${MIGRATIONS_DIR}/env.py"
if [ -f "${ENV_PY_FILE}" ]; then
  echo "Patching migrations/env.py..."
  grep -q "sys.path.append(" "${ENV_PY_FILE}" || \
    sed -i '\@^import os@a\
import sys\
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '\''..'\'' )))' "${ENV_PY_FILE}"

  grep -q "from app import create_app" "${ENV_PY_FILE}" || \
    sed -i '\@from alembic import context@a\
from app import create_app\
from app.models import db, JSONEncodedList' "${ENV_PY_FILE}"

  grep -q "^app = create_app()" "${ENV_PY_FILE}" || \
    sed -i 's|^target_metadata = None|target_metadata = db.metadata\
app = create_app()|' "${ENV_PY_FILE}"

  grep -q "config.set_main_option('sqlalchemy.url'" "${ENV_PY_FILE}" || \
    sed -i '/fileConfig(context.config.config_file_name)/a\
config = context.config\
config.set_main_option('\''sqlalchemy.url'\'', app.config.get('\''SQLALCHEMY_DATABASE_URI'\''))' "${ENV_PY_FILE}"

  grep -q "with app.app_context():" "${ENV_PY_FILE}" || \
    sed -i '/def run_migrations_online() -> None:/a\
    with app.app_context():' "${ENV_PY_FILE}"

  grep -q 'url=config.get_main_option("sqlalchemy.url")' "${ENV_PY_FILE}" || \
    sed -i '0,/context.configure(/{
/context.configure(/,/)/s/context.configure([^)]*)/context.configure(\
        connection=connection,\
        target_metadata=target_metadata,\
        url=config.get_main_option("sqlalchemy.url"),\
    )/
}' "${ENV_PY_FILE}"
  echo "Patched migrations/env.py successfully."
else
  echo "WARNING: ${ENV_PY_FILE} not found (did flask db init run?)."
fi

# Generate migration (safe if none)
echo "Generating migration from models.py (if any changes)..."
if ! (cd "${PROJECT_DIR}" && flask db migrate -m "Initial Firework app schema"); then
  echo "No schema changes or migrate failed; continuing."
fi

# Patch latest migration for JSONEncodedList, if needed
MIGR_FILE="$(ls -t "${MIGRATIONS_DIR}/versions/"*.py 2>/dev/null | head -n 1 || true)"
if [ -n "${MIGR_FILE}" ]; then
  echo "Detected migration file: ${MIGR_FILE}"
  if grep -q "app.models.JSONEncodedList" "${MIGR_FILE}" && \
     ! grep -q "^from app.models import JSONEncodedList" "${MIGR_FILE}"; then
    echo "Patching migration for JSONEncodedList import..."
    sed -i '\@import sqlalchemy as sa@a from app.models import JSONEncodedList' "${MIGR_FILE}"
    sed -i 's/app.models.JSONEncodedList/JSONEncodedList/g' "${MIGR_FILE}"
  fi
fi

# Apply migrations
echo "Upgrading database..."
(cd "${PROJECT_DIR}" && flask db upgrade)

# Set ownership and permissions for the now-existing __pycache__ directories
sudo find "${APP_DIR}" -type d -name "__pycache__" -exec chown firework:firework {} \; -exec chmod 775 {} \;

# Load .env for default user creation (if present)
if [ -f "${ENV_FILE}" ]; then
  echo "Loading environment variables from ${ENV_FILE}..."
  set -a
  # shellcheck disable=SC1091
  source "${ENV_FILE}"
  set +a
fi

# Create default users (idempotent)
echo "Creating default users..."
(
  cd "${PROJECT_DIR}"
  PYTHONPATH="${PROJECT_DIR}:${PYTHONPATH:-}" python - <<'EOF'
import os, sys
from datetime import datetime, timezone

from app import create_app, db
from app.models import User

app = create_app()
with app.app_context():
    users = [
        {'username':'super_admin','password':'super_admin','email':'superadmin@firework','role':'superadmin'},
        {'username':'admin','password':'admin','email':'admin@firework','role':'admin'},
        {'username':'implementer','password':'implementer','email':'implementer@firework','role':'implementer'},
        {'username':'approver1','password':'approver1','email':'approver1@firework','role':'approver'},
        {'username':'approver2','password':'approver2','email':'approver2@firework','role':'approver'},
        {'username':'requester1','password':'requester1','email':'requester1@firework','role':'requester'},
        {'username':'requester2','password':'requester2','email':'requester2@firework','role':'requester'},
    ]
    created = 0
    for u in users:
        if User.query.filter_by(username=u['username']).first():
            print(f"User '{u['username']}' already exists.")
            continue
        obj = User(username=u['username'], email=u['email'], role=u['role'], created_at=datetime.now(timezone.utc))
        obj.set_password(u['password'])
        db.session.add(obj); created += 1
    if created:
        db.session.commit()
    print(f"Default user creation done. Created: {created}.")
EOF
)

# 11) Start services ----------------------------------------------------------
echo "--------------------------------------------------------"
echo "[11/11] Starting services..."

firework_state="$(systemctl is-active nginx 2>/dev/null || true)"
if [ "${firework_state}" != "active" ]; then
  sudo systemctl restart firework
  sudo systemctl start firework
else
  sudo systemctl restart firework
  echo "Firework already running."
fi

nginx_state="$(systemctl is-active nginx 2>/dev/null || true)"
if [ "${nginx_state}" != "active" ]; then
  sudo systemctl start nginx
else
  echo "Nginx already running."
fi

echo "--------------------------------------------------------"
echo "Installation completed!"
echo "========================================================"
