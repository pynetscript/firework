"""Initial schema for Firework app (PostgreSQL)

Revision ID: 2d92061eabaf
Revises: 
Create Date: 2025-06-23 21:53:47.830823

"""
from alembic import op
import sqlalchemy as sa
from app.models import JSONEncodedList


# revision identifiers, used by Alembic.
revision = '2d92061eabaf'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table('user',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('username', sa.String(length=64), nullable=False),
    sa.Column('email', sa.String(length=120), nullable=False),
    sa.Column('password_hash', sa.String(length=512), nullable=False),
    sa.Column('role', sa.String(length=20), nullable=False),
    sa.Column('first_name', sa.String(length=64), nullable=True),
    sa.Column('last_name', sa.String(length=64), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=False),
    sa.Column('last_login', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('email'),
    sa.UniqueConstraint('username')
    )

    op.create_table('blacklist_rule',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('sequence', sa.Integer(), nullable=False),
    sa.Column('rule_name', sa.String(length=100), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=True),
    sa.Column('source_ip', sa.String(length=50), nullable=True),
    sa.Column('destination_ip', sa.String(length=50), nullable=True),
    sa.Column('protocol', sa.String(length=10), nullable=True),
    sa.Column('destination_port', sa.String(length=50), nullable=True),
    sa.Column('description', sa.String(length=255), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('sequence')
    )

    op.create_table('firewall_rule',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('source_ip', sa.String(length=50), nullable=False),
    sa.Column('destination_ip', sa.String(length=50), nullable=False),
    sa.Column('protocol', sa.String(length=10), nullable=False),
    sa.Column('ports', JSONEncodedList(), nullable=True),
    sa.Column('status', sa.String(length=20), nullable=True),
    sa.Column('approval_status', sa.String(length=20), nullable=True),
    sa.Column('approver_id', sa.String(length=50), nullable=True),
    sa.Column('approver_comment', sa.Text(), nullable=True),
    sa.Column('firewalls_involved', JSONEncodedList(), nullable=True),
    sa.Column('firewalls_to_provision', JSONEncodedList(), nullable=True),
    sa.Column('firewalls_already_configured', JSONEncodedList(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('implemented_at', sa.DateTime(), nullable=True),
    sa.Column('approved_at', sa.DateTime(), nullable=True),
    sa.Column('requester_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['requester_id'], ['user.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    pass


def downgrade():
    op.drop_table('firewall_rule')
    op.drop_table('blacklist_rule')
    op.drop_table('user')
    pass
