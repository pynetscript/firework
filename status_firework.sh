#!/bin/bash

# Ensure you are in your project's root directory (e.g., ~/firework) before running this script ---
# This script checks the Firework application services (Gunicorn via systemd, and Nginx).

sudo systemctl status firework | grep active
sudo systemctl status nginx | grep active
