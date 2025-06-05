from flask_sqlalchemy import SQLAlchemy
import json # Import json for JSON serialization/deserialization
from sqlalchemy.types import TypeDecorator, Text # Import TypeDecorator and Text for custom type
from datetime import datetime # Import datetime for timestamp defaults
from flask_login import UserMixin # Import UserMixin for Flask-Login
from werkzeug.security import generate_password_hash, check_password_hash # For password hashing

db = SQLAlchemy()

# Custom SQLAlchemy type to store Python lists as JSON strings in the database
class JSONEncodedList(TypeDecorator):
    impl = Text # Store as TEXT in the database

    def process_bind_param(self, value, dialect):
        """Convert Python list to JSON string for storage."""
        if value is not None:
            return json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        """Convert JSON string from database back to Python list."""
        if value is not None:
            return json.loads(value)
        return value

# User Model for Authentication
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False) # Adding email for common user identification
    password_hash = db.Column(db.String(128), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='requester') # e.g., 'superadmin', 'admin', 'implementer', 'approver', 'requester'
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    # Relationship to FirewallRule: A user can request many firewall rules
    requested_rules = db.relationship('FirewallRule', backref='requester', lazy='dynamic', foreign_keys='FirewallRule.requester_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    # Helper method to check if a user has a specific role
    def has_role(self, *roles):
        return self.role in roles

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

class FirewallRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(50), nullable=False)
    destination_ip = db.Column(db.String(50), nullable=False)
    protocol = db.Column(db.String(10), nullable=False)
    port = db.Column(db.Integer, nullable=False)
    status = db.Column(db.String(20), default="Pending")
    # New fields for Approval Workflow
    approval_status = db.Column(db.String(20), default="Pending") # Can be 'Pending', 'Approved', 'Denied'
    approver_id = db.Column(db.String(50), nullable=True) # Placeholder for approver's identifier
    approver_comment = db.Column(db.Text, nullable=True)
    # New field to store firewalls involved in the path
    firewalls_involved = db.Column(JSONEncodedList, nullable=True) # Stores list of firewall hostnames as JSON
    created_at = db.Column(db.DateTime, default=datetime.utcnow) # Timestamp for creation
    implemented_at = db.Column(db.DateTime, nullable=True) # Timestamp for implementation completion
    approved_at = db.Column(db.DateTime, nullable=True) # Timestamp for approval

    # Link to the User who created this request
    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True) # Changed to nullable=True for now, existing rules might not have a requester

    def __repr__(self):
        return f'<FirewallRule {self.id} {self.source_ip} to {self.destination_ip}:{self.port}/{self.protocol} Status: {self.status}>'

class BlacklistRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sequence = db.Column(db.Integer, nullable=False, unique=True) # For processing order
    rule_name = db.Column(db.String(100), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    source_ip = db.Column(db.String(50), nullable=True) # Can be IP, subnet, or Any (null)
    destination_ip = db.Column(db.String(50), nullable=True) # Can be IP, subnet, or Any (null)
    protocol = db.Column(db.String(10), nullable=True) # Can be 'tcp', 'udp', 'icmp', or Any (null)
    destination_port = db.Column(db.String(50), nullable=True) # Can be single port, range, or Any (null)
    description = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<BlacklistRule {self.id} - {self.rule_name} (Seq: {self.sequence})>'

