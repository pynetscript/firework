from flask import abort, flash, redirect, url_for, request
from flask_login import current_user
from app.utils import log_activity
from functools import wraps
import logging

app_logger = logging.getLogger(__name__)

def roles_required(*roles):
    """
    Decorator to restrict access to a route based on user roles.
    Example: @roles_required('admin', 'superadmin')
    """
    def wrapper(fn):
        @wraps(fn)
        def decorated_view(*args, **kwargs):
            if not current_user.is_authenticated:
                app_logger.warning(f"Unauthorized access attempt by unauthenticated user to {request.path}")
                flash(f"Please log in to access this page.", 'warning')
                return redirect(url_for('auth.login', next=request.url))

            if not current_user.has_role(*roles):
                app_logger.warning(f"Unauthorized access attempt by user {current_user.username} (Role: {current_user.role}) to {request.path}. Required roles: {roles}")
                flash(f"You do not have the necessary permissions to access this page.", 'danger')
                abort(403)
            return fn(*args, **kwargs)
        return decorated_view
    return wrapper

def no_self_approval(f):
    """
    Decorator to prevent an approver from approving their own FirewallRule requests.
    Assumes the route function takes `rule_id` as an argument.
    """
    @wraps(f)
    def decorated_function(*args, **kwargs):
        from app.models import FirewallRule
        rule_id = kwargs.get('rule_id')
        if not rule_id:
            app_logger.error("no_self_approval decorator used on a route without rule_id argument.")
            abort(500)

        rule = FirewallRule.query.get(rule_id)
        if not rule:
            app_logger.warning(f"Attempted self-approval check for non-existent rule ID: {rule_id}")
            abort(404)

        if current_user.is_authenticated and current_user.id == rule.requester_id:
            app_logger.warning(f"Self-approval attempt detected for rule ID {rule_id} by user {current_user.username} (ID: {current_user.id}).")

            log_activity(
                event_type='APPROVAL_FAILED',
                description=(
                    f"User attempted to self-approve his own request ID {rule_id} on path {request.path}."
                ),
                user=current_user
            )
            abort(403)

        return f(*args, **kwargs)
    return decorated_function
