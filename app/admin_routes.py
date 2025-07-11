from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, jsonify
from app.models import db, User, FirewallRule
from flask_login import login_required, current_user
from app.decorators import roles_required
import logging

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

app_logger = logging.getLogger(__name__)

#######################################################################
#                         HELPER FUNCTIONS                            #
#######################################################################

def get_allowed_roles():
    """Helper to provide all available roles for superadmin to assign."""
    return ['superadmin', 'admin', 'implementer', 'approver', 'requester']

#######################################################################
#                        USER ADMIN ROUTES                            #
#######################################################################

@admin_bp.route('/users', methods=['GET'])
@login_required # Ensures user is logged in
@roles_required('superadmin') # Only superadmin can view all users
def user_list():
    """Displays a list of all users with options to add, edit, or delete."""
    users = User.query.order_by(User.id).all()
    app_logger.info(f"Superadmin {current_user.username} viewing all users.")
    return render_template('user_list.html', users=users)

@admin_bp.route('/users/add', methods=['GET', 'POST'])
@login_required
@roles_required('superadmin') # Only superadmin can access this page
def add_user():
    """Allows a superadmin to add new users with specified roles."""
    if request.method == 'POST':
        username = request.form.get('username')
        email = request.form.get('email')
        password = request.form.get('password')
        role = request.form.get('role', 'requester')

        errors = []
        if not username: errors.append('Username is required.')
        if not email: errors.append('Email is required.')
        if not password: errors.append('Password is required.')

        if User.query.filter_by(username=username).first():
            errors.append('Username already taken.')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')

        if errors:
            for error in errors:
                flash(error, 'error')
            app_logger.warning(f"Superadmin {current_user.username} failed to add user due to validation errors: {', '.join(errors)}")
            return render_template('user_add.html', username=username, email=email, role=role, allowed_roles=get_allowed_roles())

        try:
            new_user = User(username=username, email=email, role=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash(f"User {username} registered successfully as '{new_user.role}'!", 'success')
            app_logger.info(f"Superadmin {current_user.username} added new user: {username} (ID: {new_user.id}, Role: {new_user.role}).")
            return redirect(url_for('admin.user_list'))
        except Exception as e:
            db.session.rollback()
            flash(f"Failed to add user: {str(e)}", 'error')
            app_logger.error(f"Superadmin {current_user.username} failed to add user due to unexpected error: {e}", exc_info=True)
            return render_template('user_add.html', username=username, email=email, role=role, allowed_roles=get_allowed_roles())

    app_logger.info(f"Superadmin {current_user.username} accessing add user page.")
    return render_template('user_add.html', allowed_roles=get_allowed_roles())

@admin_bp.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('superadmin') # Only superadmin can edit users
def edit_user(user_id):
    """Allows superadmin to edit an existing user's details and role."""
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        # Check if the user is attempting to change their own role
        if user.id == current_user.id and request.form.get('role') != current_user.role:
            flash("You cannot change your own role.", 'error')
            app_logger.warning(f"Superadmin {current_user.username} attempted to change their own role.")
            return redirect(url_for('admin.edit_user', user_id=user.id))

        original_username = user.username
        original_email = user.email

        user.username = request.form.get('username', user.username)
        user.email = request.form.get('email', user.email)
        user.first_name = request.form.get('first_name')
        user.last_name = request.form.get('last_name')
        user.role = request.form.get('role', user.role)

        new_password = request.form.get('password')
        if new_password:
            user.set_password(new_password)
            flash('User password updated successfully!', 'success')
            app_logger.info(f"Superadmin {current_user.username} changed password for user {user.username} (ID: {user.id}).")

        errors = []
        if not user.username: errors.append('Username is required.')
        if not user.email: errors.append('Email is required.')

        # Check for username/email uniqueness if they were changed
        if user.username != original_username and User.query.filter_by(username=user.username).first():
            errors.append('New username is already taken.')
        if user.email != original_email and User.query.filter_by(email=user.email).first():
            errors.append('New email is already registered.')

        if errors:
            for error in errors:
                flash(error, 'error')
            db.session.rollback()
            app_logger.warning(f"Superadmin {current_user.username} failed to edit user {original_username} due to validation errors: {', '.join(errors)}")
            return render_template('user_edit.html', user=user, allowed_roles=get_allowed_roles())

        try:
            db.session.commit()
            flash(f"User {user.username} updated successfully!", 'success')
            app_logger.info(f"Superadmin {current_user.username} updated user {user.username} (ID: {user.id}).")
            return redirect(url_for('admin.user_list'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating user: {e}", 'error')
            app_logger.error(f"Superadmin {current_user.username} failed to update user {user.username} (ID: {user.id}): {e}", exc_info=True)
            return render_template('user_edit.html', user=user, allowed_roles=get_allowed_roles())

    app_logger.info(f"Superadmin {current_user.username} accessing edit page for user ID: {user_id}.")
    return render_template('user_edit.html', user=user, allowed_roles=get_allowed_roles())

#@admin_bp.route('/users/delete/<int:user_id>', methods=['POST'])
#@login_required # Ensures user is logged in
#@roles_required('superadmin') # Only superadmin can delete users
#def delete_user(user_id):
#    """Allows superadmin to delete a user."""
#    user = User.query.get_or_404(user_id)
#
#    if user.id == current_user.id:
#        flash("You cannot delete your own account.", 'error')
#        app_logger.warning(f"Superadmin {current_user.username} attempted to delete their own account (ID: {user_id}).")
#        return redirect(url_for('admin.user_list'))
#
#    FirewallRule.query.filter_by(requester_id=user.id).update({'requester_id': None})
#
#    try:
#        db.session.delete(user)
#        db.session.commit()
#        flash(f"User '{user.username}' deleted successfully.", 'success')
#        app_logger.info(f"Superadmin {current_user.username} deleted user '{user.username}' (ID: {user_id}).")
#    except Exception as e:
#        db.session.rollback()
#        flash(f"Error deleting user: {e}", 'error')
#        app_logger.error(f"Superadmin {current_user.username} failed to delete user '{user.username}' (ID: {user_id}): {e}", exc_info=True)
#
#    return redirect(url_for('admin.user_list'))

@admin_bp.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required # Ensures user is logged in
@roles_required('superadmin') # Only superadmin can delete users
def delete_user(user_id):
    """Allows superadmin to delete a user."""
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You cannot delete your own account.", 'error')
        app_logger.warning(f"Superadmin {current_user.username} attempted to delete their own account (ID: {user_id}).")
        # Return JSON error for client-side handling
        return jsonify({"status": "error", "message": "You cannot delete your own account."}), 400

    # Ensure FirewallRule is imported and handled if necessary
    FirewallRule.query.filter_by(requester_id=user.id).update({'requester_id': None})

    try:
        db.session.delete(user)
        db.session.commit()
        app_logger.info(f"Superadmin {current_user.username} deleted user '{user.username}' (ID: {user_id}).")
        return jsonify({"status": "success", "message": f"User '{user.username}' deleted successfully."}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"Superadmin {current_user.username} failed to delete user '{user.username}' (ID: {user_id}): {e}", exc_info=True)
        return jsonify({"status": "error", "message": f"Error deleting user: {str(e)}"}), 500
