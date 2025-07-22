from datetime import datetime
from app.models import db, ActivityLogEntry
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
            timestamp=datetime.utcnow(),
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
