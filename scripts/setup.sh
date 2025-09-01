#!/bin/bash
# Setup the Firework app's Python environment and migrate the PostgreSQL schema.
# NOTE: This script is meant to be run from anywhere; it resolves paths itself.
# It does NOT create users, install system packages, add default users, or start services.

set -Eeuo pipefail

# --- Resolve project root -----------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
cd "${PROJECT_DIR}"

echo "Starting Firework Application and Database Schema Setup"

# --- 1) Create (if missing) and activate venv --------------------------------
VENV_DIR="${PROJECT_DIR}/venv"
if [ ! -d "${VENV_DIR}" ]; then
  echo "Creating new virtual environment at '${VENV_DIR}'..."
  python3 -m venv "${VENV_DIR}"
else
  echo "Virtual environment already exists at '${VENV_DIR}'."
fi

echo "Activating virtual environment..."
# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate"

# --- 2) Install Python dependencies ------------------------------------------
REQ_FILE="${PROJECT_DIR}/requirements.txt"
echo "Installing dependencies from ${REQ_FILE}..."
pip install --upgrade pip
pip install -r "${REQ_FILE}"

# --- 3) Set FLASK_APP and ensure we're at project root -----------------------
export FLASK_APP="${PROJECT_DIR}/run.py"
echo "FLASK_APP set to ${FLASK_APP}"

# --- 4) Initialize Flask-Migrate if needed -----------------------------------
MIGRATIONS_DIR="${PROJECT_DIR}/migrations"
if [ ! -d "${MIGRATIONS_DIR}" ]; then
  echo "Initializing Flask-Migrate repository..."
  flask db init
else
  echo "Flask-Migrate repository already initialized."
fi

# --- 5) Patch migrations/env.py (idempotent) ---------------------------------
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

  # Normalize context.configure block to include url=... if not already present
  if ! grep -q 'url=config.get_main_option("sqlalchemy.url")' "${ENV_PY_FILE}"; then
    # Replace the default literal_binds block with a simpler connection/metadata/url block
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

# --- 6) Generate migration (safe if no changes) -------------------------------
echo "Generating initial (or incremental) migration script from models.py..."
if ! flask db migrate -m "Initial Firework app schema"; then
  echo "No changes in schema detected or migrate failed; continuing."
fi

# Try to detect the newest migration file (may be empty if no changes)
MIGRATION_FILE_GENERATED="$(ls -t "${MIGRATIONS_DIR}/versions/"*.py 2>/dev/null | head -n 1 || true)"
if [ -n "${MIGRATION_FILE_GENERATED}" ]; then
  echo "Detected migration file: ${MIGRATION_FILE_GENERATED}"

  # Patch for JSONEncodedList imports only if needed
  if grep -q "app.models.JSONEncodedList" "${MIGRATION_FILE_GENERATED}" && \
     ! grep -q "^from app.models import JSONEncodedList" "${MIGRATION_FILE_GENERATED}"; then
    echo "Patching migration for JSONEncodedList import..."
    sed -i '\@import sqlalchemy as sa@a from app.models import JSONEncodedList' "${MIGRATION_FILE_GENERATED}"
    sed -i 's/app.models.JSONEncodedList/JSONEncodedList/g' "${MIGRATION_FILE_GENERATED}"
  fi
else
  echo "No migration file found under ${MIGRATIONS_DIR}/versions (maybe nothing changed)."
fi

# --- 7) Apply migrations ------------------------------------------------------
echo "Applying all pending database migrations to PostgreSQL..."
flask db upgrade

echo "Firework Application and Database Schema Setup Completed."
echo "Run './scripts/add_default_users.sh' to add default users to the database."
