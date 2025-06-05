from flask import Blueprint, render_template, redirect, url_for, flash, request
from app.models import db, User
from flask_login import login_required, current_user
from app.decorators import roles_required # Import our custom roles decorator
import logging

admin_bp = Blueprint('admin', __name__, url_prefix='/admin') # Added url_prefix for /admin/

app_logger = logging.getLogger(__name__)

@admin_bp.route('/users/add', methods=['GET', 'POST'])
@login_required
@roles_required('superadmin') # Only superadmin can access this page
def add_user():
    """Allows a superadmin to add new users with specified roles."""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'requester') # Default to 'requester' if not provided

        if not username or not password or not email:
            flash('Username, email, and password are required.', 'error')
            app_logger.warning(f"Superadmin {current_user.username} attempted to add user with missing fields.")
            return render_template('user_add.html', username=username, email=email, role=role, allowed_roles=get_allowed_roles())

        if User.query.filter_by(username=username).first():
            flash('Username already taken.', 'error')
            app_logger.warning(f"Superadmin {current_user.username} attempted to add user with duplicate username: {username}.")
            return render_template('user_add.html', username=username, email=email, role=role, allowed_roles=get_allowed_roles())
        if User.query.filter_by(email=email).first():
            flash('Email already registered.', 'error')
            app_logger.warning(f"Superadmin {current_user.username} attempted to add user with duplicate email: {email}.")
            return render_template('user_add.html', username=username, email=email, role=role, allowed_roles=get_allowed_roles())

        new_user = User(username=username, email=email, role=role)
        new_user.set_password(password)
        db.session.add(new_user)
        db.session.commit()

        flash(f"User {username} registered successfully as '{new_user.role}'!", 'success')
        app_logger.info(f"Superadmin {current_user.username} added new user: {username} (ID: {new_user.id}, Role: {new_user.role}).")
        return redirect(url_for('admin.add_user')) # Redirect back to the add user page

    # For GET request, render the add user form
    app_logger.info(f"Superadmin {current_user.username} accessing add user page.")
    return render_template('user_add.html', allowed_roles=get_allowed_roles())

def get_allowed_roles():
    # Helper to provide all available roles for superadmin
    return ['superadmin', 'admin', 'implementer', 'approver', 'requester']

