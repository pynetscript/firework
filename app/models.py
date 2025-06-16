from flask_sqlalchemy import SQLAlchemy
import json
from sqlalchemy.types import TypeDecorator, Text
from datetime import datetime
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class JSONEncodedList(TypeDecorator):
    impl = Text

    def process_bind_param(self, value, dialect):
        if value is not None:
            return json.dumps(value)
        return value

    def process_result_value(self, value, dialect):
        if value is not None:
            return json.loads(value)
        return value

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='requester')
    first_name = db.Column(db.String(64), nullable=True) # New field
    last_name = db.Column(db.String(64), nullable=True)  # New field
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    requested_rules = db.relationship('FirewallRule', backref='requester', lazy='dynamic', foreign_keys='FirewallRule.requester_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_role(self, *roles):
        return self.role in roles

    def __repr__(self):
        return f'<User {self.username} ({self.role})>'

class FirewallRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(50), nullable=False)
    destination_ip = db.Column(db.String(50), nullable=False)
    protocol = db.Column(db.String(10), nullable=False)
    # CHANGED: 'port' (singular, Integer) to 'ports' (plural, JSONEncodedList)
    ports = db.Column(JSONEncodedList, nullable=True) # Now stores a list of ports or port ranges
    status = db.Column(db.String(20), default="Pending")
    approval_status = db.Column(db.String(20), default="Pending")
    approver_id = db.Column(db.String(50), nullable=True)
    approver_comment = db.Column(db.Text, nullable=True)
    firewalls_involved = db.Column(JSONEncodedList, nullable=True)

    firewalls_to_provision = db.Column(JSONEncodedList, nullable=True)
    firewalls_already_configured = db.Column(JSONEncodedList, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    implemented_at = db.Column(db.DateTime, nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)

    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    def __repr__(self):
        # CHANGED: 'self.port' to 'self.ports'
        return f'<FirewallRule {self.id} {self.source_ip} to {self.destination_ip}:{self.ports}/{self.protocol} Status: {self.status}>'

class BlacklistRule(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    sequence = db.Column(db.Integer, nullable=False, unique=True)
    rule_name = db.Column(db.String(100), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    source_ip = db.Column(db.String(50), nullable=True)
    destination_ip = db.Column(db.String(50), nullable=True)
    protocol = db.Column(db.String(10), nullable=True)
    destination_port = db.Column(db.String(50), nullable=True)
    description = db.Column(db.String(255), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    def __repr__(self):
        return f'<BlacklistRule {self.id} - {self.rule_name} (Seq: {self.sequence})>'

