#!/bin/bash

# --- IMPORTANT: Ensure you are in your project's root directory (e.g., ~/firework) before running this script ---

echo "--- Starting Firework ---"

# 1. Deactivate any active virtual environment
echo "Deactivating any active virtual environment..."
deactivate 2>/dev/null || true # Suppress error if no venv is active

# 2. Remove old database files
echo "Removing old database files..."
rm -f network.db firework.db

# 3. Remove old migrations directory
echo "Removing old migrations directory..."
rm -rf migrations

# 4. Remove old virtual environment (for ultimate cleanliness)
echo "Removing old virtual environment 'venv'..."
rm -rf venv

# 5. Create new virtual environment
echo "Creating new virtual environment 'venv'..."
python3 -m venv venv

# 6. Activate new virtual environment
echo "Activating new virtual environment..."
source venv/bin/activate

# 7. Install dependencies from requirements.txt
echo "Installing dependencies from requirements.txt..."
pip install -r requirements.txt

# 8. Set FLASK_APP environment variable
echo "Setting FLASK_APP environment variable..."
export FLASK_APP=run.py

# 9. Initialize Flask-Migrate repository
echo "Initializing Flask-Migrate repository..."
flask db init

# 10. Create the initial database migration script
echo "Creating the initial database migration script..."
flask db migrate -m "Initial schema for Firework app"

# Get the name of the newly generated migration file
MIGRATION_FILE=$(ls -t migrations/versions/*.py | head -n 1)

if [ -z "$MIGRATION_FILE" ]; then
    echo "ERROR: No migration file generated. Exiting."
    exit 1
fi

echo "Detected new migration file: $MIGRATION_FILE"

# 11. AUTOMATICALLY EDIT THE NEWLY GENERATED MIGRATION FILE
echo "Automatically editing the migration file to fix NameError..."
# Add the import statement: from app.models import JSONEncodedList
sed -i '/import sqlalchemy as sa/a from app.models import JSONEncodedList' "$MIGRATION_FILE"

# Replace 'app.models.JSONEncodedList()' with 'JSONEncodedList()'
sed -i 's/app.models.JSONEncodedList()/JSONEncodedList()/g' "$MIGRATION_FILE"
echo "Migration file edited successfully."

# 12. Apply database migrations
echo "Applying database migrations..."
flask db upgrade

# 13. Create super_admin user
echo "Creating super_admin user..."
# Create a temporary Python script for user creation
cat << EOF > create_superadmin.py
from app import create_app, db
from app.models import User
from datetime import datetime
import os

app = create_app()
with app.app_context():
    if not User.query.filter_by(username='super_admin').first():
        super_admin_user = User(username='super_admin', email='superadmin@firework.dev', role='superadmin', created_at=datetime.utcnow())
        super_admin_user.set_password('super_admin') # Set the password
        db.session.add(super_admin_user)
        db.session.commit()
        print("Super admin user 'super_admin' created successfully with password 'super_admin'.")
    else:
        print("Super admin user 'super_admin' already exists.")
EOF

# Execute the temporary script
python create_superadmin.py

# Clean up the temporary script
rm create_superadmin.py
echo "Super admin user creation process completed."

# 14. Verify database tables
echo "Verifying database tables in network.db..."
sqlite3 network.db ".tables"

# 15. Start Flask application
echo "Starting Flask..."
./run.py

echo "--- Stopped Firework ---"
