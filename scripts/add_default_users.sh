#!/bin/bash
# Populate the database with default users.
# Works from anywhere; resolves paths relative to /scripts.

set -Eeuo pipefail

echo "--- Populating Database with Default Users ---"

# --- Resolve project root -----------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${PROJECT_DIR}/venv"
ENV_FILE="${PROJECT_DIR}/.env"

cd "${PROJECT_DIR}"

# --- Activate venv ------------------------------------------------------------
echo "Activating virtual environment..."
if [ ! -d "${VENV_DIR}" ]; then
  echo "Error: venv not found at '${VENV_DIR}'. Run '${SCRIPT_DIR}/setup.sh' first."
  exit 1
fi

# shellcheck disable=SC1091
source "${VENV_DIR}/bin/activate" || {
  echo "Error: Failed to activate virtual environment at '${VENV_DIR}'."
  exit 1
}

# --- Load .env (if present) ---------------------------------------------------
if [ -f "${ENV_FILE}" ]; then
  echo "Loading environment variables from ${ENV_FILE}..."
  set -a
  # shellcheck disable=SC1091
  source "${ENV_FILE}"
  set +a
else
  echo "Warning: ${ENV_FILE} not found. Continuing without loading extra env vars."
fi

# --- Create default users -----------------------------------------------------
echo "Executing embedded Python script for user creation..."
python - <<'EOF'
import sys
import os
from datetime import datetime, timezone

# Ensure imports work when invoked from scripts/
BASE_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "."))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from app import create_app, db
from app.models import User

app = create_app()
with app.app_context():
    users_to_create = [
        {'username': 'super_admin', 'password': 'super_admin', 'email': 'superadmin@firework', 'role': 'superadmin'},
        {'username': 'admin', 'password': 'admin', 'email': 'admin@firework', 'role': 'admin'},
        {'username': 'implementer', 'password': 'implementer', 'email': 'implementer@firework', 'role': 'implementer'},
        {'username': 'approver1', 'password': 'approver1', 'email': 'approver1@firework', 'role': 'approver'},
        {'username': 'approver2', 'password': 'approver2', 'email': 'approver2@firework', 'role': 'approver'},
        {'username': 'requester1', 'password': 'requester1', 'email': 'requester1@firework', 'role': 'requester'},
        {'username': 'requester2', 'password': 'requester2', 'email': 'requester2@firework', 'role': 'requester'},
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

echo "--- Database Population Completed ---"

# optional: deactivate venv
deactivate 2>/dev/null || true
