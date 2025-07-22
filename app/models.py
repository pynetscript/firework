from flask_sqlalchemy import SQLAlchemy
import json
from sqlalchemy.types import TypeDecorator, Text
from datetime import datetime, timezone
from flask_login import UserMixin
from werkzeug.security import generate_password_hash, check_password_hash

db = SQLAlchemy()

class JSONEncodedList(TypeDecorator):
    """
    A custom SQLAlchemy type to store Python lists as JSON strings in the database.
    Useful for fields like 'ports' or 'firewalls_involved'.
    """
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
    """
    User model for authentication and role-based access control.
    """
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(64), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(512), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='requester')
    first_name = db.Column(db.String(64), nullable=True)
    last_name = db.Column(db.String(64), nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    last_login = db.Column(db.DateTime, nullable=True)

    requested_rules = db.relationship('FirewallRule', backref='requester', lazy='dynamic', foreign_keys='FirewallRule.requester_id')

    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

    def has_role(self, *roles):
        """Checks if the user has any of the specified roles."""
        return self.role in roles

    def __repr__(self):
        return f'<User {self.username} (Role: {self.role})>'

class ActivityLogEntry(db.Model):
    """
    Model for activity logs.
    """
    __tablename__ = 'activity_log_entry'

    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, default=datetime.utcnow, nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    username = db.Column(db.String(80), nullable=False)
    event_type = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text, nullable=False)
    related_resource_id = db.Column(db.Integer, nullable=True)
    related_resource_type = db.Column(db.String(50), nullable=True)

    def __repr__(self):
        return f"<ActivityLogEntry {self.timestamp} - {self.username} - {self.event_type}>"

class FirewallRule(db.Model):
    """
    Model for Firewall Rules.
    """
    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(50), nullable=False)
    destination_ip = db.Column(db.String(50), nullable=False)
    protocol = db.Column(db.String(10), nullable=False)
    ports = db.Column(JSONEncodedList, nullable=False)

    status = db.Column(db.String(50), default='Pending')
    rule_description = db.Column(db.Text, nullable=True)

    approval_status = db.Column(db.String(20), default='Pending')
    approver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approver = db.relationship('User', foreign_keys=[approver_id])
    approver_comment = db.Column(db.Text, nullable=True)

    implementer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    implementer = db.relationship('User', foreign_keys=[implementer_id])
    implementer_comment = db.Column(db.Text, nullable=True)

    firewalls_involved = db.Column(JSONEncodedList, nullable=True)
    firewalls_to_provision = db.Column(JSONEncodedList, nullable=True)
    firewalls_already_configured = db.Column(JSONEncodedList, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    implemented_at = db.Column(db.DateTime, nullable=True)
    approved_at = db.Column(db.DateTime, nullable=True)

    requester_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    def __repr__(self):
        return f'<FirewallRule {self.id} {self.source_ip} to {self.destination_ip}:{self.ports}/{self.protocol} Status: {self.status}>'

class BlacklistRule(db.Model):
    """
    Model for Blacklsit Rules.
    """
    id = db.Column(db.Integer, primary_key=True)
    sequence = db.Column(db.Integer, unique=True, nullable=False)
    rule_name = db.Column(db.String(100), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    source_ip = db.Column(db.String(50), nullable=True)
    destination_ip = db.Column(db.String(50), nullable=True)
    protocol = db.Column(db.String(10), nullable=True)
    destination_port = db.Column(db.String(50), nullable=True)
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    created_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    last_updated_by_user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)

    creator = db.relationship('User', foreign_keys=[created_by_user_id], backref='created_rules_rel', lazy=True)
    editor = db.relationship('User', foreign_keys=[last_updated_by_user_id], backref='edited_rules_rel', lazy=True)

    def __repr__(self):
        return f'<BlacklistRule {self.rule_name} (ID: {self.id})>'

    def to_dict(self):
        """Converts the BlacklistRule object to a dictionary for JSON serialization."""
        return {
            'id': self.id,
            'sequence': self.sequence,
            'rule_name': self.rule_name,
            'enabled': self.enabled,
            'source_ip': self.source_ip,
            'destination_ip': self.destination_ip,
            'protocol': self.protocol,
            'destination_port': self.destination_port,
            'description': self.description,
            'created_at': self.created_at.replace(tzinfo=timezone.utc).isoformat() if self.created_at else None,
            'updated_at': self.updated_at.replace(tzinfo=timezone.utc).isoformat() if self.updated_at else None,
            'created_by_username': self.creator.username if self.creator else None,
            'last_updated_by_username': self.editor.username if self.editor else None
        }

class Device(db.Model):
    """
    Represents a network device (router, switch, firewall).
    """
    __tablename__ = 'devices'
    device_id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), unique=True, nullable=False)
    device_type = db.Column(db.String(50))

    interfaces = db.relationship('Interface', backref='device', lazy='dynamic')
    arp_entries = db.relationship('ArpEntry', backref='device', lazy='dynamic')
    route_entries = db.relationship('RouteEntry', backref='device', lazy='dynamic')

    def __repr__(self):
        return f"<Device {self.hostname} ({self.device_type})>"

class Interface(db.Model):
    """
    Represents an interface on a network device.
    """
    __tablename__ = 'interfaces'
    interface_id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.device_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    ipv4_address = db.Column(db.String(50))
    ipv4_subnet = db.Column(db.String(50))
    mac_address = db.Column(db.String(50))
    description = db.Column(db.Text)
    status = db.Column(db.String(50))
    type = db.Column(db.String(50))

    def __repr__(self):
        return f"<Interface {self.name} on Device ID {self.device_id}>"

class ArpEntry(db.Model):
    """
    Represents an ARP table entry for a device.
    """
    __tablename__ = 'arp_entries'
    arp_id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.device_id'), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    mac_address = db.Column(db.String(50), nullable=False)
    interface_name = db.Column(db.String(100))

    def __repr__(self):
        return f"<ArpEntry {self.ip_address} -> {self.mac_address} on Device ID {self.device_id}>"

class RouteEntry(db.Model):
    """
    Represents a routing table entry for a device.
    """
    __tablename__ = 'route_entries'
    route_id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.device_id'), nullable=False)
    destination_network = db.Column(db.String(50), nullable=False)
    next_hop = db.Column(db.String(50))
    metric = db.Column(db.Integer)
    admin_distance = db.Column(db.Integer)
    interface_name = db.Column(db.String(100))
    route_type = db.Column(db.String(50))
    flags = db.Column(db.String(50))

    def __repr__(self):
        return f"<RouteEntry {self.destination_network} via {self.next_hop} on Device ID {self.device_id}>"
