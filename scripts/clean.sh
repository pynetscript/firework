#!/bin/bash
# Reset the Firework environment: drop/recreate DB, remove venv & migrations, clear logs.
# Works from anywhere; resolves paths relative to /scripts.

set -Eeuo pipefail

echo "--- Cleaning Firework Environment and Database ---"

# --- Resolve project root -----------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${PROJECT_DIR}/venv"
MIGRATIONS_DIR="${PROJECT_DIR}/migrations"
SOCKET_FILE="/tmp/firework.sock"

# --- Deactivate any active virtual environment --------------------------------
echo "Deactivating any active virtual environment..."
deactivate 2>/dev/null || true

# --- Remove migrations directory ----------------------------------------------
echo "Removing old migrations directory..."
rm -rf "${MIGRATIONS_DIR}"

# --- Remove virtual environment -----------------------------------------------
echo "Removing old virtual environment 'venv'..."
rm -rf "${VENV_DIR}"

# --- Remove Gunicorn socket ----------------------------------------------------
echo "Removing Gunicorn socket file if it exists..."
rm -f "${SOCKET_FILE}"

# --- Reset logs (handle both common log filenames) -----------------------------
echo "Resetting logs..."
LOGS_RESET=0
for lf in "${PROJECT_DIR}/firework_app.log" "${PROJECT_DIR}/firework.log"; do
  if [ -e "$lf" ]; then
    # Try to truncate; if permission blocked, try via sudo.
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

# --- PostgreSQL reset ----------------------------------------------------------
# Uses ~/.pgpass of user 'firework' for passwordless auth.
echo "Resetting PostgreSQL database 'fireworkdb'..."
if ! command -v psql >/dev/null 2>&1; then
  echo "Error: psql not found. Install PostgreSQL client or run the installer first."
  exit 1
fi

# Drop DB (if exists)
if psql -h localhost -U firework -d postgres -v ON_ERROR_STOP=1 -c "DROP DATABASE IF EXISTS fireworkdb;"; then
  echo "Database 'fireworkdb' dropped successfully (if it existed)."
else
  echo "Error: Failed to drop database 'fireworkdb'. Check user permissions or ~/.pgpass. Exiting."
  exit 1
fi

# Create DB owned by 'firework'
if psql -h localhost -U firework -d postgres -v ON_ERROR_STOP=1 -c "CREATE DATABASE fireworkdb OWNER firework;"; then
  echo "Database 'fireworkdb' created successfully."
else
  echo "Error: Failed to create database 'fireworkdb'. Check user permissions or ~/.pgpass. Exiting."
  exit 1
fi

echo "PostgreSQL database 'fireworkdb' reset completed."
echo "--- Firework Environment and Database Cleaned ---"
echo "You can now run './scripts/setup.sh' for a fresh environment and database schema setup."
