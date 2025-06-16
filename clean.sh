#!/bin/bash

# --- IMPORTANT: Ensure you are in your project's root directory (e.g., ~/firework) before running this script ---
# This script removes the virtual environment, Flask-Migrate migrations,
# and resets the entire schema (including all application tables) in the PostgreSQL database,
# effectively resetting the application's environment and schema setup for a clean start.

echo "--- Cleaning Firework Environment and Database (Full Reset) ---"

# 1. Deactivate any active virtual environment
echo "Deactivating any active virtual environment..."
deactivate 2>/dev/null || true # Suppress error if no venv is active

# 2. Remove old migrations directory
echo "Removing old migrations directory..."
rm -rf migrations

# 3. Remove old virtual environment
echo "Removing old virtual environment 'venv'..."
rm -rf venv

# Optional: Remove the Gunicorn socket file if it exists, ensuring a clean start
echo "Removing Gunicorn socket file if it exists..."
rm -f /tmp/firework.sock

# 4. Remove all application tables and Alembic version history from PostgreSQL database
echo "Resetting database schema in PostgreSQL (dropping all application tables)..."
# Ensure your database credentials (firework:firework) and database name (fireworkdb) are correct
psql -h localhost -U firework -d fireworkdb -c "DROP TABLE IF EXISTS \"user\" CASCADE; DROP TABLE IF EXISTS blacklist_rule CASCADE; DROP TABLE IF EXISTS firewall_rule CASCADE; DROP TABLE IF EXISTS alembic_version CASCADE;"
if [ $? -eq 0 ]; then
    echo "All application tables and Alembic version history removed successfully (if they existed)."
else
    echo "Warning: Failed to drop one or more tables. Check PostgreSQL access/permissions."
    # Don't exit here, as it might just not exist, and we still want to try setup.sh
fi

echo "--- Firework Environment and Database Cleaned ---"
echo "You can now run './setup.sh' for a fresh environment and database schema setup."
