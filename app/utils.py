from datetime import datetime, timezone
from app.models import db, ActivityLogEntry
import psutil
import ipaddress
import socket
import logging

app_logger = logging.getLogger(__name__)

def log_activity(event_type, description, user=None, username=None, user_id=None, related_resource_id=None, related_resource_type=None):
    """
    Records an activity entry into the database.
    """
    logged_user_id = None
    logged_username = "System"

    if user:
        logged_user_id = user.id
        logged_username = user.username
    elif username:
        logged_username = username
        logged_user_id = user_id

    try:
        new_log = ActivityLogEntry(
            timestamp=datetime.now(timezone.utc),
            user_id=logged_user_id,
            username=logged_username,
            event_type=event_type,
            description=description,
            related_resource_id=related_resource_id,
            related_resource_type=related_resource_type
        )
        db.session.add(new_log)
        db.session.commit()
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"Failed to log activity: {e}", exc_info=True)

def get_default_interface():
    """
    Finds the name of the primary network interface by checking the default gateway.
    Returns the interface name as a string or None if not found.
    """
    try:
        gws = psutil.net_if_addrs()
        for interface_name, addresses in gws.items():
            for addr in addresses:
                if addr.family == socket.AF_INET and addr.address:
                    # A simple heuristic: check for a non-loopback, non-private IP
                    # or an interface with a non-zero address
                    ip_obj = ipaddress.ip_address(addr.address)
                    if not ip_obj.is_loopback and not ip_obj.is_private:
                        return interface_name

        # Fallback: Find the interface with a default route
        # (This is more robust but requires additional logic)
        for interface_name in psutil.net_io_counters(pernic=True).keys():
            if interface_name != 'lo' and interface_name.startswith('en'):
                return interface_name

    except Exception as e:
        app_logger.error(f"Error determining default network interface: {e}")
        return None
