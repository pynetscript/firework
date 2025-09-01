#!/bin/bash
# Reset Firework completely:
# 1) Stop services (Gunicorn systemd unit + Nginx)
# 2) Remove venv & migrations, clear logs, remove socket
# 3) Drop & recreate PostgreSQL database (uses ~/.pgpass)
# Works from anywhere; resolves paths relative to /scripts.

set -Eeuo pipefail

echo "--- Firework RESET starting ---"

# --- Resolve project root -----------------------------------------------------
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${PROJECT_DIR}/venv"
MIGRATIONS_DIR="${PROJECT_DIR}/migrations"
SOCKET_FILE="/tmp/firework.sock"

# --- 1) Stop services ---------------------------------------------------------
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

# --- 2) Deactivate any active virtual environment -----------------------------
echo "Deactivating any active virtual environment..."
deactivate 2>/dev/null || true

# --- 3) Remove migrations directory ------------------------------------------
echo "Removing migrations directory..."
rm -rf "${MIGRATIONS_DIR}"

# --- 4) Remove virtual environment -------------------------------------------
echo "Removing virtual environment at '${VENV_DIR}'..."
rm -rf "${VENV_DIR}"

# --- 5) Remove Gunicorn socket ------------------------------------------------
echo "Removing Gunicorn socket (if present)..."
rm -f "${SOCKET_FILE}"

# --- 6) Reset logs ------------------------------------------------------------
echo "Resetting logs..."
LOGS_RESET=0
for lf in "${PROJECT_DIR}/firework_app.log" "${PROJECT_DIR}/firework.log"; do
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

# --- 7) PostgreSQL reset ------------------------------------------------------
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

echo "--- Firework RESET completed ---"
