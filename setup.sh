#!/bin/bash

# --- IMPORTANT: Ensure you are in your project's root directory (e.g., ~/firework) before running this script ---
# This script sets up the application's Python environment and migrates the database schema to PostgreSQL.
# It does NOT populate users or start the application services.

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

# 5. Initialize Flask-Migrate repository
echo "Initializing Flask-Migrate repository..."
flask db init

# 6. Create an EMPTY initial database migration script
# This command explicitly creates a new empty revision, which we will then populate manually via sed.
echo "Creating an EMPTY initial database migration script for PostgreSQL..."
flask db revision -m "Initial schema for Firework app (PostgreSQL)"

# Get the name of the newly generated migration file
MIGRATION_FILE=$(ls -t migrations/versions/*.py | head -n 1)

if [ -z "$MIGRATION_FILE" ]; then
    echo "ERROR: No migration file generated. Exiting."
    exit 1
fi

echo "Detected new (empty) migration file: $MIGRATION_FILE"

# --- AUTOMATICALLY POPULATE THE NEWLY GENERATED MIGRATION FILE ---
echo "Automatically populating migration file with initial schema..."

# 1. Add the necessary import statement for JSONEncodedList
sed -i '/import sqlalchemy as sa/a from app.models import JSONEncodedList' "$MIGRATION_FILE"

# 2. Insert the 'upgrade' operations (schema creation) into the upgrade() function
#sed -i '/def upgrade():/a\
#    op.create_table('\''user'\'',\
#    sa.Column('\''id'\'', sa.Integer(), nullable=False),\
#    sa.Column('\''username'\'', sa.String(length=64), nullable=False),\
#    sa.Column('\''email'\'', sa.String(length=120), nullable=False),\
#    sa.Column('\''password_hash'\'', sa.String(length=512), nullable=False),\
#    sa.Column('\''role'\'', sa.String(length=64), nullable=False),\
#    sa.Column('\''first_name'\'', sa.String(length=64), nullable=True),\
#    sa.Column('\''last_name'\'', sa.String(length=64), nullable=True),\
#    sa.Column('\''created_at'\'', sa.DateTime(), nullable=False),\
#    sa.Column('\''last_login'\'', sa.DateTime(), nullable=True),\
#    sa.PrimaryKeyConstraint('\''id'\''),\
#    sa.UniqueConstraint('\''email'\''),\
#    sa.UniqueConstraint('\''username'\'')\
#    )\
#\
#    op.create_table('\''blacklist_rule'\'',\
#    sa.Column('\''id'\'', sa.Integer(), nullable=False),\
#    sa.Column('\''rule_name'\'', sa.String(length=128), nullable=False),\
#    sa.Column('\''source_ip'\'', sa.String(length=45), nullable=False),\
#    sa.Column('\''destination_ip'\'', sa.String(length=45), nullable=True),\
#    sa.Column('\''ports'\'', JSONEncodedList(), nullable=True),\
#    sa.Column('\''protocol'\'', sa.String(length=16), nullable=True),\
#    sa.Column('\''description'\'', sa.String(length=256), nullable=True),\
#    sa.Column('\''created_at'\'', sa.DateTime(), nullable=True),\
#    sa.Column('\''expires_at'\'', sa.DateTime(), nullable=True),\
#    sa.Column('\''status'\'', sa.String(length=32), nullable=True),\
#    sa.PrimaryKeyConstraint('\''id'\''),\
#    sa.UniqueConstraint('\''rule_name'\'')\
#    )\
#\
#    op.create_table('\''firewall_rule'\'',\
#    sa.Column('\''id'\'', sa.Integer(), nullable=False),\
#    sa.Column('\''rule_name'\'', sa.String(length=128), nullable=False),\
#    sa.Column('\''source_ip'\'', sa.String(length=45), nullable=False),\
#    sa.Column('\''destination_ip'\'', sa.String(length=45), nullable=True),\
#    sa.Column('\''ports'\'', JSONEncodedList(), nullable=True),\
#    sa.Column('\''protocol'\'', sa.String(length=16), nullable=True),\
#    sa.Column('\''description'\'', sa.String(length=256), nullable=True),\
#    sa.Column('\''created_at'\'', sa.DateTime(), nullable=True),\
#    sa.Column('\''expires_at'\'', sa.DateTime(), nullable=True),\
#    sa.Column('\''status'\'', sa.String(length=32), nullable=True),\
#    sa.Column('\''firewalls_involved'\'', JSONEncodedList(), nullable=True),\
#    sa.Column('\''firewalls_to_provision'\'', JSONEncodedList(), nullable=True),\
#    sa.Column('\''firewalls_already_configured'\'', JSONEncodedList(), nullable=True),\
#    sa.Column('\''requested_by_user_id'\'', sa.Integer(), nullable=True),\
#    sa.Column('\''approved_by_user_id'\'', sa.Integer(), nullable=True),\
#    sa.ForeignKeyConstraint(['\''approved_by_user_id'\''], ['\''user.id'\''], ),\
#    sa.ForeignKeyConstraint(['\''requested_by_user_id'\''], ['\''user.id'\''], ),\
#    sa.PrimaryKeyConstraint('\''id'\''),\
#    sa.UniqueConstraint('\''rule_name'\'')\
#    )' "$MIGRATION_FILE"

    # 2. Insert the 'upgrade' operations (schema creation) into the upgrade() function
    # The multiline sed command syntax uses backslashes to escape newlines.
    # Each line of the Python code that needs to be inserted must be preceded by a backslash.
    sed -i '/def upgrade():/a\
    op.create_table('\''user'\'',\
    sa.Column('\''id'\'', sa.Integer(), nullable=False),\
    sa.Column('\''username'\'', sa.String(length=64), nullable=False),\
    sa.Column('\''email'\'', sa.String(length=120), nullable=False),\
    sa.Column('\''password_hash'\'', sa.String(length=512), nullable=False),\
    sa.Column('\''role'\'', sa.String(length=20), nullable=False),\
    sa.Column('\''first_name'\'', sa.String(length=64), nullable=True),\
    sa.Column('\''last_name'\'', sa.String(length=64), nullable=True),\
    sa.Column('\''created_at'\'', sa.DateTime(), nullable=False),\
    sa.Column('\''last_login'\'', sa.DateTime(), nullable=True),\
    sa.PrimaryKeyConstraint('\''id'\''),\
    sa.UniqueConstraint('\''email'\''),\
    sa.UniqueConstraint('\''username'\'')\
    )\
\
    op.create_table('\''blacklist_rule'\'',\
    sa.Column('\''id'\'', sa.Integer(), nullable=False),\
    sa.Column('\''sequence'\'', sa.Integer(), nullable=False),\
    sa.Column('\''rule_name'\'', sa.String(length=100), nullable=False),\
    sa.Column('\''enabled'\'', sa.Boolean(), nullable=True),\
    sa.Column('\''source_ip'\'', sa.String(length=50), nullable=True),\
    sa.Column('\''destination_ip'\'', sa.String(length=50), nullable=True),\
    sa.Column('\''protocol'\'', sa.String(length=10), nullable=True),\
    sa.Column('\''destination_port'\'', sa.String(length=50), nullable=True),\
    sa.Column('\''description'\'', sa.String(length=255), nullable=True),\
    sa.Column('\''created_at'\'', sa.DateTime(), nullable=True),\
    sa.Column('\''updated_at'\'', sa.DateTime(), nullable=True),\
    sa.PrimaryKeyConstraint('\''id'\''),\
    sa.UniqueConstraint('\''sequence'\'')\
    )\
\
    op.create_table('\''firewall_rule'\'',\
    sa.Column('\''id'\'', sa.Integer(), nullable=False),\
    sa.Column('\''source_ip'\'', sa.String(length=50), nullable=False),\
    sa.Column('\''destination_ip'\'', sa.String(length=50), nullable=False),\
    sa.Column('\''protocol'\'', sa.String(length=10), nullable=False),\
    sa.Column('\''ports'\'', JSONEncodedList(), nullable=True),\
    sa.Column('\''status'\'', sa.String(length=20), nullable=True),\
    sa.Column('\''approval_status'\'', sa.String(length=20), nullable=True),\
    sa.Column('\''approver_id'\'', sa.String(length=50), nullable=True),\
    sa.Column('\''approver_comment'\'', sa.Text(), nullable=True),\
    sa.Column('\''firewalls_involved'\'', JSONEncodedList(), nullable=True),\
    sa.Column('\''firewalls_to_provision'\'', JSONEncodedList(), nullable=True),\
    sa.Column('\''firewalls_already_configured'\'', JSONEncodedList(), nullable=True),\
    sa.Column('\''created_at'\'', sa.DateTime(), nullable=True),\
    sa.Column('\''implemented_at'\'', sa.DateTime(), nullable=True),\
    sa.Column('\''approved_at'\'', sa.DateTime(), nullable=True),\
    sa.Column('\''requester_id'\'', sa.Integer(), nullable=True),\
    sa.ForeignKeyConstraint(['\''requester_id'\''], ['\''user.id'\''], ),\
    sa.PrimaryKeyConstraint('\''id'\'')\
    )' "$MIGRATION_FILE"

# 3. Insert the 'downgrade' operations (schema deletion) into the downgrade() function
sed -i '/def downgrade():/a\
    op.drop_table('\''firewall_rule'\'')\
    op.drop_table('\''blacklist_rule'\'')\
    op.drop_table('\''user'\'')' "$MIGRATION_FILE"

echo "Migration file populated and patched successfully."
# --- END AUTOMATIC POPULATION ---

# 7. Apply database migrations to PostgreSQL
echo "Applying database migrations to PostgreSQL..."
flask db upgrade

echo "Firework Application and Database Schema Setup Completed."
echo "Run './add_default_users.sh' to add default users to the database."
