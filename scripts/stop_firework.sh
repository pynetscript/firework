#!/bin/bash
# Stop Firework services (Gunicorn via systemd, and Nginx).
# Works from anywhere; resolves paths relative to /scripts.

set -Eeuo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(cd "${SCRIPT_DIR}/.." && pwd)"
VENV_DIR="${PROJECT_DIR}/venv"
SOCKET_FILE="/tmp/firework.sock"

echo "Stopping firework..."

echo "Stopping nginx..."
if sudo systemctl stop nginx; then
  echo "Nginx stopped successfully."
else
  echo "Warning: Nginx service might not have stopped cleanly or was not running."
fi

echo "Stopping Gunicorn Firework service..."
if sudo systemctl stop firework; then
  echo "Gunicorn Firework service stopped successfully."
else
  echo "Warning: Gunicorn Firework service might not have stopped cleanly or was not running."
fi

echo "Reload system daemons"
sudo systemctl daemon-reload

echo "Deactivating any active virtual environment..."
deactivate 2>/dev/null || true

echo "Removing virtual environment 'venv'..."
rm -rf "${VENV_DIR}"

echo "Removing Gunicorn socket file if it exists..."
rm -f "${SOCKET_FILE}"

echo "Completed!"
