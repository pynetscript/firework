#!/bin/bash

set -Eeuo pipefail

echo "--- Firework RESET starting ---"

# --- Resolve project root -----------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${PROJECT_DIR}/venv"
MIGRATIONS_DIR="${PROJECT_DIR}/migrations"
SOCKET_FILE="/tmp/firework.sock"

# --- Stop services ---------------------------------------------------------
echo "Stopping services..."

echo "Stopping nginx..."
if sudo systemctl stop nginx; then
  echo "Nginx stopped."
else
  echo "Warning: Nginx may not have stopped cleanly or wasn't running."
fi

echo "Stopping firework (Gunicorn) service..."
if sudo systemctl stop firework; then
  echo "Firework service stopped."
else
  echo "Warning: Firework service may not have stopped cleanly or wasn't running."
fi

echo "Reloading systemd daemon..."
sudo systemctl daemon-reload || true

# --- Deactivate any active virtual environment -----------------------------
echo "Deactivating any active virtual environment..."
deactivate 2>/dev/null || true

# --- Remove migrations directory ------------------------------------------
echo "Removing migrations directory..."
rm -rf "${MIGRATIONS_DIR}"

# --- Remove virtual environment -------------------------------------------
echo "Removing virtual environment at '${VENV_DIR}'..."
rm -rf "${VENV_DIR}"

# --- Remove Gunicorn socket ------------------------------------------------
echo "Removing Gunicorn socket (if present)..."
rm -f "${SOCKET_FILE}"

# --- Reset logs ------------------------------------------------------------
echo "Resetting logs..."
LOGS_RESET=0
for lf in "${PROJECT_DIR}/firework.log"; do
  if [ -e "$lf" ]; then
    if ! : > "$lf" 2>/dev/null; then
      sudo sh -c ": > '$lf'" || true
    fi
    echo "Reset: $lf"
    LOGS_RESET=1
  fi
done
if [ "${LOGS_RESET}" -eq 0 ]; then
  echo "No known log files found to reset."
fi

# --- PostgreSQL reset ------------------------------------------------------
echo "Resetting PostgreSQL database 'fireworkdb'..."
if ! command -v psql >/dev/null 2>&1; then
  echo "Error: psql not found. Install PostgreSQL client or run the installer first."
  exit 1
fi

# Drop DB (if exists)
if psql -h localhost -U firework -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS fireworkdb;"; then
  echo "Dropped database 'fireworkdb' (if it existed)."
else
  echo "Error: Failed to drop database 'fireworkdb'. Check user permissions or ~/.pgpass."
  exit 1
fi

# Create DB owned by 'firework'
if psql -h localhost -U firework -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE fireworkdb OWNER firework;"; then
  echo "Created database 'fireworkdb' owned by 'firework'."
else
  echo "Error: Failed to create database 'fireworkdb'. Check user permissions or ~/.pgpass."
  exit 1
fi

# --- Resolve project root -----------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_DIR}"

VENV_DIR="${PROJECT_DIR}/venv"
REQ_FILE="${PROJECT_DIR}/requirements.txt"
MIGRATIONS_DIR="${PROJECT_DIR}/migrations"
ENV_FILE="${PROJECT_DIR}/.env"

echo "Starting Firework Application and Database Schema Setup"

# --- Create (if missing) and activate venv --------------------------------
if [ ! -d "${VENV_DIR}" ]; then
  echo "Creating new virtual environment at '${VENV_DIR}'..."
  python3 -m venv "${VENV_DIR}"
else
  echo "Virtual environment already exists at '${VENV_DIR}'."
fi

echo "Activating virtual environment..."
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

# --- Install Python dependencies ------------------------------------------
echo "Installing dependencies from ${REQ_FILE}..."
pip install --upgrade pip
pip install -r "${REQ_FILE}"

# --- Set FLASK_APP and ensure we're at project root -----------------------
export FLASK_APP="${PROJECT_DIR}/run.py"
echo "FLASK_APP set to ${FLASK_APP}"

# --- Initialize Flask-Migrate if needed -----------------------------------
if [ ! -d "${MIGRATIONS_DIR}" ]; then
  echo "Initializing Flask-Migrate repository..."
  flask db init
else
  echo "Flask-Migrate repository already initialized."
fi

# --- Patch migrations/env.py (idempotent) ---------------------------------
ENV_PY_FILE="${MIGRATIONS_DIR}/env.py"
if [ -f "${ENV_PY_FILE}" ]; then
  echo "Patching migrations/env.py to support Flask app context and custom types..."

  # Add sys.path append only if missing
  if ! grep -q "sys.path.append(" "${ENV_PY_FILE}"; then
    sed -i '\@^import os@a\
import sys\
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '\''..'\'' )))' "${ENV_PY_FILE}"
  fi

  # Ensure imports for create_app, db, JSONEncodedList
  if ! grep -q "from app import create_app" "${ENV_PY_FILE}"; then
    sed -i '\@from alembic import context@a\
from app import create_app\
from app.models import db, JSONEncodedList' "${ENV_PY_FILE}"
  fi

  # Ensure target_metadata and app assignment
  if ! grep -q "^app = create_app()" "${ENV_PY_FILE}"; then
    sed -i 's|^target_metadata = None|target_metadata = db.metadata\
app = create_app()|' "${ENV_PY_FILE}"
  fi

  # Set sqlalchemy.url from app config after fileConfig() (only once)
  if ! grep -q "config.set_main_option('sqlalchemy.url'" "${ENV_PY_FILE}"; then
    sed -i '/fileConfig(context.config.config_file_name)/a\
config = context.config\
config.set_main_option('\''sqlalchemy.url'\'', app.config.get('\''SQLALCHEMY_DATABASE_URI'\''))' "${ENV_PY_FILE}"
  fi

  # Ensure we enter app context in run_migrations_online()
  if ! grep -q "with app.app_context():" "${ENV_PY_FILE}"; then
    sed -i '/def run_migrations_online() -> None:/a\
    with app.app_context():' "${ENV_PY_FILE}"
  fi

  # Normalize context.configure block to include url=...
  if ! grep -q 'url=config.get_main_option("sqlalchemy.url")' "${ENV_PY_FILE}"; then
    sed -i '0,/context.configure(/{
/context.configure(/,/)/s/context.configure([^)]*)/context.configure(\
        connection=connection,\
        target_metadata=target_metadata,\
        url=config.get_main_option("sqlalchemy.url"),\
    )/
}' "${ENV_PY_FILE}"
  fi

  echo "Patched migrations/env.py successfully."
else
  echo "WARNING: ${ENV_PY_FILE} does not exist yet (migrations not initialized?)."
fi

# --- Generate migration (safe if no changes) -------------------------------
echo "Generating initial (or incremental) migration script from models.py..."
if ! flask db migrate -m "Initial Firework app schema"; then
  echo "No changes in schema detected or migrate failed; continuing."
fi

# Patch latest migration if needed for JSONEncodedList
MIGRATION_FILE_GENERATED="$(ls -t "${MIGRATIONS_DIR}/versions/"*.py 2>/dev/null | head -n 1 || true)"
if [ -n "${MIGRATION_FILE_GENERATED}" ]; then
  echo "Detected migration file: ${MIGRATION_FILE_GENERATED}"
  if grep -q "app.models.JSONEncodedList" "${MIGRATION_FILE_GENERATED}" && \
     ! grep -q "^from app.models import JSONEncodedList" "${MIGRATION_FILE_GENERATED}"; then
    echo "Patching migration for JSONEncodedList import..."
    sed -i '\@import sqlalchemy as sa@a from app.models import JSONEncodedList' "${MIGRATION_FILE_GENERATED}"
    sed -i 's/app.models.JSONEncodedList/JSONEncodedList/g' "${MIGRATION_FILE_GENERATED}"
  fi
else
  echo "No migration file found under ${MIGRATIONS_DIR}/versions (maybe nothing changed)."
fi

# --- Apply migrations ------------------------------------------------------
echo "Applying all pending database migrations to PostgreSQL..."
flask db upgrade

# --- Load .env for add_default_users step ---------------------------------
if [ -f "${ENV_FILE}" ]; then
  echo "Loading environment variables from ${ENV_FILE}..."
  set -a
  # shellcheck disable=SC1091
  source "${ENV_FILE}"
  set +a
else
  echo "Warning: ${ENV_FILE} not found. Continuing without loading extra env vars."
fi

# --- add_default_users ---------------------------------------------
echo "Creating default users (idempotent)..."
python - <<'EOF'
import sys
import os
from datetime import datetime, timezone

BASE_DIR = os.path.abspath(os.path.dirname(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import create_app, db
from app.models import User

app = create_app()
with app.app_context():
    users_to_create = [
        {'username': 'super_admin', 'password': 'super_admin', 'email': 'superadmin@firework', 'role': 'superadmin'},
        {'username': 'admin',        'password': 'admin',        'email': 'admin@firework',        'role': 'admin'},
        {'username': 'implementer',  'password': 'implementer',  'email': 'implementer@firework',  'role': 'implementer'},
        {'username': 'approver1',    'password': 'approver1',    'email': 'approver1@firework',    'role': 'approver'},
        {'username': 'approver2',    'password': 'approver2',    'email': 'approver2@firework',    'role': 'approver'},
        {'username': 'requester1',   'password': 'requester1',   'email': 'requester1@firework',   'role': 'requester'},
        {'username': 'requester2',   'password': 'requester2',   'email': 'requester2@firework',   'role': 'requester'},
    ]

    created = 0
    skipped = 0
    for u in users_to_create:
        if User.query.filter_by(username=u['username']).first():
            print(f"User '{u['username']}' already exists.")
            skipped += 1
            continue
        new_user = User(
            username=u['username'],
            email=u['email'],
            role=u['role'],
            created_at=datetime.now(timezone.utc)
        )
        new_user.set_password(u['password'])
        db.session.add(new_user)
        created += 1

    if created:
        db.session.commit()

    print(f"Default user creation process completed. Created: {created}, Skipped: {skipped}.")
EOF

# --- start services (systemd + nginx) ------------------------------
echo "Starting Firework services..."

start_unit () {
  local unit="$1"
  if sudo systemctl start "$unit"; then
    echo "Started: $unit"
  else
    echo "Error: Failed to start $unit. Check logs: journalctl -u ${unit}.service"
    exit 1
  fi
}

start_unit "firework"
start_unit "nginx"

echo "Services started: firework (Gunicorn), nginx."
echo "Firework Application and Database Schema Setup Completed."
echo "--- Firework RESET finished ---"
