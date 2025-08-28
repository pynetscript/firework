#!/bin/bash

# Ensure you are in your project's root directory (e.g., ~/firework) before running this script ---
# This script sets up the application's Python environment and migrates the database schema to PostgreSQL.

echo "Starting Firework Application and Database Schema Setup"

# 1. Create new virtual environment
echo "Creating new virtual environment 'venv'..."
python3 -m venv venv

# 2. Activate new virtual environment
echo "Activating new virtual environment..."
source venv/bin/activate

# 3. Install dependencies from requirements.txt
echo "Installing dependencies from requirements.txt (ensure psycopg2-binary is included)..."
pip install -r requirements.txt

# 4. Set FLASK_APP environment variable
echo "Setting FLASK_APP environment variable..."
export FLASK_APP=run.py

# --- IMPORTANT: Ensure your app/__init__.py is configured for PostgreSQL before running migrations! ---
# Example: app.config['SQLALCHEMY_DATABASE_URI'] = 'postgresql://firework:firework@localhost:5432/fireworkdb'

# 5. Initialize Flask-Migrate repository (only if it doesn't exist)
echo "Initializing Flask-Migrate repository (if not already initialized)..."
flask db init || echo "Flask-Migrate repository already initialized."

# --- START NEW ADDITION: PATCH env.py FOR PERMANENT FIX ---
# Get the path to the env.py file
ENV_PY_FILE="migrations/env.py"

echo "Patching migrations/env.py to support Flask app context and custom types..."

# Ensure 'os' is imported FIRST, then add sys.path and Flask-related imports.
# Replace existing 'import os' and 'import sys' if they exist, and add sys.path.append.
sed -i '\@^import os@a\
import sys\
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), '\''..'\'' )))' "$ENV_PY_FILE"

# Add 'from app import create_app' and 'from app.models import db, JSONEncodedList'
sed -i '\@from alembic import context@a\
from app import create_app\
from app.models import db, JSONEncodedList' "$ENV_PY_FILE"

# Modify target_metadata and app creation outside functions
sed -i 's|^target_metadata = None|target_metadata = db.metadata\napp = create_app()|' "$ENV_PY_FILE"

# Set sqlalchemy.url from app config globally for alembic (insert after fileConfig)
sed -i '/fileConfig(context.config.config_file_name)/a\
config = context.config\
config.set_main_option('\''sqlalchemy.url'\'', app.config.get('\''SQLALCHEMY_DATABASE_URI'\''))' "$ENV_PY_FILE"

# Insert 'with app.app_context():' into run_migrations_online()
sed -i '/def run_migrations_online() -> None:/a\
with app.app_context():' "$ENV_PY_FILE"

# Adjust context.configure parameters within run_migrations_online
sed -i 's/context.configure(\n        connection=connection,\n        target_metadata=target_metadata,\n        literal_binds=True,\n        dialect_opts={"paramstyle": "named"},\n    )/context.configure(\n        connection=connection,\n        target_metadata=target_metadata,\n        url=config.get_main_option("sqlalchemy.url"),\n    )/' "$ENV_PY_FILE"

echo "Patched migrations/env.py successfully."
# --- END NEW ADDITION: PATCH env.py FOR PERMANENT FIX ---

# 6. Generate (autogenerate) the initial migration script based on models.py.
echo "Generating initial database migration script based on models.py..."
flask db migrate -m "Initial Firework app schema"

# Get the name of the newly generated migration file
MIGRATION_FILE_GENERATED=$(ls -t migrations/versions/*.py 2>/dev/null | head -n 1)

if [ -z "$MIGRATION_FILE_GENERATED" ]; then
    echo "ERROR: No migration file generated. Exiting."
    exit 1
fi

echo "Detected new (auto-generated) migration file: $MIGRATION_FILE_GENERATED"

# Patch the newly generated migration file to fix app.models.JSONEncodedList references
echo "Patching the auto-generated migration file for JSONEncodedList imports..."
# Add JSONEncodedList import
sed -i '\@import sqlalchemy as sa@a from app.models import JSONEncodedList' "$MIGRATION_FILE_GENERATED"
# Replace app.models.JSONEncodedList with JSONEncodedList
sed -i 's/app.models.JSONEncodedList/JSONEncodedList/g' "$MIGRATION_FILE_GENERATED"
echo "Auto-generated migration file patched successfully."

# 7. Apply all pending database migrations to PostgreSQL
echo "Applying all pending database migrations to PostgreSQL..."
flask db upgrade

echo "Firework Application and Database Schema Setup Completed."
echo "Run './add_default_users.sh' to add default users to the database."
