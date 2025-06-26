#!/bin/bash

# --- IMPORTANT: Ensure you are in your project's root directory (e.g., ~/firework) before running this script ---
# This script activates the virtual environment and then runs an embedded Python script
# to populate the database with default users.

echo "--- Populating Database with Default Users ---"

# 1. Activate the virtual environment
echo "Activating virtual environment..."
source venv/bin/activate
if [ $? -ne 0 ]; then
    echo "Error: Failed to activate virtual environment. Ensure 'venv' exists and is set up."
    exit 1
fi

# 2. Run the embedded Python script to populate the database
echo "Executing embedded Python script for user creation..."
python - <<EOF
import sys
import os
from app import create_app, db
from app.models import User
from datetime import datetime, timezone

# Ensure the app context is pushed correctly for this standalone script
app = create_app()
with app.app_context():
    users_to_create = [
        {'username': 'super_admin', 'password': 'super_admin', 'email': 'superadmin@firework', 'role': 'superadmin'},
        {'username': 'admin', 'password': 'admin', 'email': 'admin@firework', 'role': 'admin'},
        {'username': 'implementer', 'password': 'implementer', 'email': 'implementer@firework', 'role': 'implementer'},
        {'username': 'approver1', 'password': 'approver1', 'email': 'approver1@firework', 'role': 'approver'},
        {'username': 'approver2', 'password': 'approver2', 'email': 'approver2@firework', 'role': 'approver'},
        {'username': 'requester1', 'password': 'requester1', 'email': 'requester1@firework', 'role': 'requester'},
        {'username': 'requester2', 'password': 'requester2', 'email': 'requester2@firework', 'role': 'requester'}
    ]

    for user_data in users_to_create:
        username = user_data['username']
        password = user_data['password']
        email = user_data['email']
        role = user_data['role']

        if not User.query.filter_by(username=username).first():
            new_user = User(username=username, email=email, role=role, created_at=datetime.now(timezone.utc))
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            print(f"User '{username}' created successfully with password '{password}' and role '{role}'.")
        else:
            print(f"User '{username}' already exists.")

print("Default user creation process completed.")
EOF
if [ $? -ne 0 ]; then
    echo "Error: Embedded Python script failed during execution."
    exit 1
fi

echo "--- Database Population Completed ---"
# Deactivate the virtual environment to return to the system Python (optional for script end)
deactivate 2>/dev/null || true
