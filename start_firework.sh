#!/bin/bash

# --- IMPORTANT: Ensure you are in your project's root directory (e.g., ~/firework) before running this script ---
# This script starts the Firework application services (Gunicorn via systemd, and Nginx).
# It assumes the virtual environment and database schema have already been set up by 'setup.sh'.

echo "Starting firework..."

echo "Starting Gunicorn Firework service..."
sudo systemctl start firework
if [ $? -eq 0 ]; then
    echo "Gunicorn Firework service started successfully."
else
    echo "Error: Failed to start Gunicorn Firework service. Check logs: journalctl -u firework.service"
    exit 1 # Exit if Gunicorn fails to start
fi

echo "Starting Nginx service..."
sudo systemctl start nginx
if [ $? -eq 0 ]; then
    echo "Nginx started successfully."
else
    echo "Error: Failed to start Nginx service. Check logs: journalctl -u nginx.service"
    exit 1 # Exit if Nginx fails to start
fi

echo "Completed!"
