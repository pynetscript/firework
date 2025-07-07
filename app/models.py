from flask_sqlalchemy import SQLAlchemy
import json
from sqlalchemy.types import TypeDecorator, Text
from datetime import datetime
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

    # Relationship to FirewallRule: A user can request many firewall rules.
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

class FirewallRule(db.Model):
    """
    Model for network firewall rule requests.
    """
    id = db.Column(db.Integer, primary_key=True)
    source_ip = db.Column(db.String(50), nullable=False)
    destination_ip = db.Column(db.String(50), nullable=False)
    protocol = db.Column(db.String(10), nullable=False)
    # Using JSONEncodedList for 'ports' to allow multiple ports or ranges
    ports = db.Column(JSONEncodedList, nullable=False)

    status = db.Column(db.String(50), default='Pending') # e.g., Pending, Approved, Implemented, Denied, Cancelled
    rule_description = db.Column(db.Text, nullable=True)

    # Fields for approval workflow
    approval_status = db.Column(db.String(20), default='Pending') # Pending, Approved, Denied, Cancelled
    approver_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    approver = db.relationship('User', foreign_keys=[approver_id]) # Relationship to the approver User
    approver_comment = db.Column(db.Text, nullable=True)

    # Fields for implementation workflow
    implementer_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=True)
    implementer = db.relationship('User', foreign_keys=[implementer_id]) # Relationship to the implementer User
    implementer_comment = db.Column(db.Text, nullable=True)

    # Store lists of firewalls relevant to the request as JSON
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
    id = db.Column(db.Integer, primary_key=True)
    sequence = db.Column(db.Integer, unique=True, nullable=False)
    rule_name = db.Column(db.String(100), nullable=False)
    enabled = db.Column(db.Boolean, default=True)
    source_ip = db.Column(db.String(50), nullable=True)
    destination_ip = db.Column(db.String(50), nullable=True)
    protocol = db.Column(db.String(10), nullable=True)
    destination_port = db.Column(db.String(50), nullable=True) # Storing as string to handle ranges/any
    description = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

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
            'created_at': self.created_at.isoformat() if self.created_at else None,
            'updated_at': self.updated_at.isoformat() if self.updated_at else None
        }

class Device(db.Model):
    """
    Represents a network device (router, switch, firewall).
    Corresponds to the 'devices' table in the old SQLite schema.
    """
    __tablename__ = 'devices'
    device_id = db.Column(db.Integer, primary_key=True)
    hostname = db.Column(db.String(255), unique=True, nullable=False)
    device_type = db.Column(db.String(50)) # e.g., Router, Switch, Firewall

    # Relationships to other network data tables
    interfaces = db.relationship('Interface', backref='device', lazy='dynamic')
    arp_entries = db.relationship('ArpEntry', backref='device', lazy='dynamic')
    route_entries = db.relationship('RouteEntry', backref='device', lazy='dynamic')

    def __repr__(self):
        return f"<Device {self.hostname} ({self.device_type})>"

class Interface(db.Model):
    """
    Represents an interface on a network device.
    Corresponds to the 'interfaces' table in the old SQLite schema.
    """
    __tablename__ = 'interfaces'
    interface_id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.device_id'), nullable=False)
    name = db.Column(db.String(100), nullable=False)
    ipv4_address = db.Column(db.String(50))
    ipv4_subnet = db.Column(db.String(50)) # Store as string, e.g., "24" for /24
    mac_address = db.Column(db.String(50))
    description = db.Column(db.Text)
    status = db.Column(db.String(50)) # e.g., "up/up"
    type = db.Column(db.String(50)) # e.g., Ethernet, Loopback

    def __repr__(self):
        return f"<Interface {self.name} on Device ID {self.device_id}>"

class ArpEntry(db.Model):
    """
    Represents an ARP table entry for a device.
    Corresponds to the 'arp_entries' table in the old SQLite schema.
    """
    __tablename__ = 'arp_entries'
    arp_id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.device_id'), nullable=False)
    ip_address = db.Column(db.String(50), nullable=False)
    mac_address = db.Column(db.String(50), nullable=False)
    interface_name = db.Column(db.String(100)) # The interface associated with this ARP entry

    def __repr__(self):
        return f"<ArpEntry {self.ip_address} -> {self.mac_address} on Device ID {self.device_id}>"

class RouteEntry(db.Model):
    """
    Represents a routing table entry for a device.
    Corresponds to the 'route_entries' table in the old SQLite schema.
    """
    __tablename__ = 'route_entries'
    route_id = db.Column(db.Integer, primary_key=True)
    device_id = db.Column(db.Integer, db.ForeignKey('devices.device_id'), nullable=False)
    destination_network = db.Column(db.String(50), nullable=False) # e.g., "192.168.1.0/24" or "0.0.0.0/0"
    next_hop = db.Column(db.String(50))
    metric = db.Column(db.Integer)
    admin_distance = db.Column(db.Integer)
    interface_name = db.Column(db.String(100)) # Outgoing interface for the route
    route_type = db.Column(db.String(50)) # e.g., "connected", "static", "ospf"
    flags = db.Column(db.String(50)) # e.g., "C", "S*", "O" from Cisco

    def __repr__(self):
        return f"<RouteEntry {self.destination_network} via {self.next_hop} on Device ID {self.device_id}>"
