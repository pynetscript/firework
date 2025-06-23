#!/bin/bash

echo "Stopping firework..."

echo "Stopping nginx..."
sudo systemctl stop nginx
if [ $? -eq 0 ]; then
    echo "Nginx stopped successfully."
else
    echo "Warning: Nginx service might not have stopped cleanly or was not running."
fi

echo "Stopping Gunicorn Firework service..."
sudo systemctl stop firework
if [ $? -eq 0 ]; then
    echo "Gunicorn Firework service stopped successfully."
else
    echo "Warning: Gunicorn Firework service might not have stopped cleanly or was not running."
fi

echo "Reload system daemons"
sudo systemctl daemon-reload

echo "Deactivating any active virtual environment..."
deactivate 2>/dev/null || true

echo "Removing virtual environment 'venv'..."
rm -rf venv

echo "Removing Gunicorn socket file if it exists..."
rm -f /tmp/firework.sock

echo "Completed!"
