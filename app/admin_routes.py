from flask import Blueprint, render_template, redirect, url_for, flash, request, abort, jsonify
from app.models import db, User, FirewallRule, ActivityLogEntry
from app.utils import log_activity
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
@login_required
@roles_required('superadmin')
def user_list():
    """Displays a list of all users with options to add, edit, or delete."""
    users = User.query.order_by(User.id).all()
    return render_template('user_list.html', users=users)

@admin_bp.route('/users/add', methods=['GET', 'POST'])
@login_required
@roles_required('superadmin')
def add_user():
    """Allow superadmin to add new users with specified roles."""
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
            errors.append('Username already registered.')
        if User.query.filter_by(email=email).first():
            errors.append('Email already registered.')

        if errors:
            for error in errors:
                flash(error, 'error')
            app_logger.warning(f"User {current_user.username} failed to add user due to validation errors: {', '.join(errors)}")
            return render_template('user_add.html', username=username, email=email, role=role, allowed_roles=get_allowed_roles())

        try:
            new_user = User(username=username, email=email, role=role)
            new_user.set_password(password)
            db.session.add(new_user)
            db.session.commit()
            flash(f"User {username} registered successfully as '{new_user.role}'!", 'success')
            app_logger.info(f"User {current_user.username} added new user: {username} (ID: {new_user.id}, Role: {new_user.role}).")
            log_activity(
                event_type='USER_CREATED',
                description=f"User '{new_user.username}' (ID: {new_user.id}) with role '{new_user.role}' created.",
                user=current_user,
                related_resource_id=new_user.id,
                related_resource_type='User'
            )
            return redirect(url_for('admin.user_list'))
        except Exception as e:
            db.session.rollback()
            flash(f"Failed to add user: {str(e)}", 'error')
            app_logger.error(f"User {current_user.username} failed to add user due to unexpected error: {e}", exc_info=True)
            return render_template('user_add.html', username=username, email=email, role=role, allowed_roles=get_allowed_roles())

    return render_template('user_add.html', allowed_roles=get_allowed_roles())

@admin_bp.route('/users/edit/<int:user_id>', methods=['GET', 'POST'])
@login_required
@roles_required('superadmin')
def edit_user(user_id):
    """Allow superadmin to edit an existing user's details and role."""
    user = User.query.get_or_404(user_id)

    if request.method == 'POST':
        # Check if the user is attempting to change their own role
        if user.id == current_user.id and request.form.get('role') != current_user.role:
            flash("You cannot change your own role.", 'error')
            app_logger.warning(f"User {current_user.username} attempted to change their own role.")
            return redirect(url_for('admin.edit_user', user_id=user.id))

        original_username = user.username
        original_email = user.email
        original_role = user.role
        original_first_name = user.first_name
        original_last_name = user.last_name

        user.username = request.form.get('username', user.username)
        user.email = request.form.get('email', user.email)
        user.first_name = request.form.get('first_name')
        user.last_name = request.form.get('last_name')
        user.role = request.form.get('role', user.role)

        new_password = request.form.get('password')
        password_changed = False
        if new_password:
            user.set_password(new_password)
            flash('User password updated successfully!', 'success')
            log_activity(
                event_type='USER_PASSWORD_CHANGED',
                description=f"Password for user '{user.username}' (ID: {user.id}) changed.",
                user=current_user,
                related_resource_id=user.id,
                related_resource_type='User'
            )
            app_logger.info(f"User {current_user.username} changed password for user {user.username} (ID: {user.id}).")
            password_changed = True

        errors = []
        if not user.username: errors.append('Username is required.')
        if not user.email: errors.append('Email is required.')

        # Check for username/email uniqueness if they were changed
        if user.username != original_username and User.query.filter_by(username=user.username).first():
            errors.append('New username is already registered.')
        if user.email != original_email and User.query.filter_by(email=user.email).first():
            errors.append('New email is already registered.')

        if errors:
            for error in errors:
                flash(error, 'error')
            db.session.rollback()
            app_logger.warning(f"User {current_user.username} failed to edit user {original_username} due to validation errors: {', '.join(errors)}")
            return render_template('user_edit.html', user=user, allowed_roles=get_allowed_roles())

        try:
            changes_made = False
            change_details = []

            if user.username != original_username:
                change_details.append(f"username changed from '{original_username}' to '{user.username}'")
                changes_made = True
            if user.email != original_email:
                change_details.append(f"email changed from '{original_email}' to '{user.email}'")
                changes_made = True
            if user.first_name != original_first_name:
                change_details.append(f"first name changed from '{original_first_name}' to '{user.first_name}'")
                changes_made = True
            if user.last_name != original_last_name:
                change_details.append(f"last name changed from '{original_last_name}' to '{user.last_name}'")
                changes_made = True
            if user.role != original_role:
                change_details.append(f"role changed from '{original_role}' to '{user.role}'")
                changes_made = True
            if password_changed:
                change_details.append("password reset")
                changes_made = True

            db.session.commit()
            flash(f"User {user.username} updated successfully!", 'success')
            app_logger.info(f"User {current_user.username} updated user {user.username} (ID: {user.id}).")
            if changes_made:
                log_activity(
                    event_type='USER_UPDATED',
                    description=f"User '{user.username}' (ID: {user.id}) updated. Changes: {'; '.join(change_details) if change_details else 'No specific data changes other than password.'}",
                    user=current_user,
                    related_resource_id=user.id,
                    related_resource_type='User'
                )
            return redirect(url_for('admin.user_list'))
        except Exception as e:
            db.session.rollback()
            flash(f"Error updating user: {e}", 'error')
            app_logger.error(f"User {current_user.username} failed to update user {user.username} (ID: {user.id}): {e}", exc_info=True)
            return render_template('user_edit.html', user=user, allowed_roles=get_allowed_roles())

    return render_template('user_edit.html', user=user, allowed_roles=get_allowed_roles())

@admin_bp.route('/users/delete/<int:user_id>', methods=['POST'])
@login_required
@roles_required('superadmin')
def delete_user(user_id):
    """Allow superadmin to delete a user."""
    user = User.query.get_or_404(user_id)

    if user.id == current_user.id:
        flash("You cannot delete your own account.", 'error')
        app_logger.warning(f"{current_user.username} attempted to delete their own account (ID: {user_id}).")
        log_activity(
            event_type='UNAUTHORIZED_SELF_DELETE_ATTEMPT',
            description=f"Attempted to delete their own account (ID: {user_id}).",
            user=current_user,
            related_resource_id=user_id,
            related_resource_type='User'
        )
        return jsonify({"status": "error", "message": "You cannot delete your own account."}), 400

    FirewallRule.query.filter_by(requester_id=user.id).update({'requester_id': None})

    try:
        username_deleted = user.username
        db.session.delete(user)
        db.session.commit()
        app_logger.info(f"{current_user.username} deleted user '{user.username}' (ID: {user_id}).")
        log_activity(
            event_type='USER_DELETED',
            description=f"User '{username_deleted}' (ID: {user_id}) deleted.",
            user=current_user,
            related_resource_id=user_id,
            related_resource_type='User'
        )
        return jsonify({"status": "success", "message": f"User '{user.username}' deleted successfully."}), 200
    except Exception as e:
        db.session.rollback()
        app_logger.error(f"User {current_user.username} failed to delete user '{user.username}' (ID: {user_id}): {e}", exc_info=True)
        log_activity(
            event_type='USER_DELETE_FAILED',
            description=f"Failed to delete user '{user.username}' (ID: {user_id}): {str(e)}",
            user=current_user,
            related_resource_id=user_id,
            related_resource_type='User'
        )
        return jsonify({"status": "error", "message": f"Error deleting user: {str(e)}"}), 500
