#!/bin/bash

# Ensure you are in your project's root directory (e.g., ~/firework) before running this script ---
# This script removes the virtual environment, Flask-Migrate migrations,
# and performs a full reset of the PostgreSQL database,
# effectively resetting the application's environment and schema setup for a clean start.

echo "--- Cleaning Firework Environment and Database ---"

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

# 4. Reset logs
echo "Resetting logs..."
truncate -s 0 firework_app.log

# 5. Perform a full reset of the PostgreSQL database
# Use the 'firework' user to connect to the default 'postgres' database
# to drop and recreate 'fireworkdb'. This relies on ~/.pgpass for password.
echo "Resetting PostgreSQL database 'fireworkdb'..."

# Drop the database (if it exists)
psql -h localhost -U firework -d postgres -c "DROP DATABASE IF EXISTS fireworkdb;"
if [ $? -eq 0 ]; then
echo "Database 'fireworkdb' dropped successfully (if it existed)."
else
echo "Error: Failed to drop database 'fireworkdb'. Check user permissions or ~/.pgpass. Exiting."
exit 1 # Exit on critical database operation failure
fi

# Create the database again, owned by the 'firework' user.
psql -h localhost -U firework -d postgres -c "CREATE DATABASE fireworkdb OWNER firework;"
if [ $? -eq 0 ]; then
echo "Database 'fireworkdb' created successfully."
else
echo "Error: Failed to create database 'fireworkdb'. Check user permissions or ~/.pgpass. Exiting."
exit 1 # Exit on critical database operation failure
fi

echo "PostgreSQL database 'fireworkdb' reset completed."
echo "--- Firework Environment and Database Cleaned ---"
echo "You can now run './setup.sh' for a fresh environment and database schema setup."
