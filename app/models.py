from flask_sqlalchemy import SQLAlchemy
import json # Import json for JSON serialization/deserialization
from sqlalchemy.types import TypeDecorator, Text # Import TypeDecorator and Text for custom type
from datetime import datetime # Import datetime for timestamp defaults

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
    created_at = db.Column(db.DateTime, default=datetime.utcnow, nullable=False) # Added
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow, nullable=False) # Added

    def __repr__(self):
        return f"<BlacklistRule {self.sequence}: {self.rule_name}>"
