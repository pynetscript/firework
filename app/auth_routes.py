from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from app.models import db, User
from app.routes import log_activity
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime, timezone
import logging

auth = Blueprint('auth', __name__)

app_logger = logging.getLogger(__name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        flash(f"You are already logged in.", 'info')
        app_logger.info(f"Attempted to access login page while already authenticated: User ID {current_user.id}")
        return redirect(url_for('routes.home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.now(timezone.utc)
            db.session.commit()
            flash(f"Logged in successfully!", 'success')
            app_logger.info(f"User {username} (ID: {user.id}) logged in successfully.")

            log_activity(
                event_type='USER_LOGIN',
                description=f"User {user.username} logged in.",
                user=user,
                related_resource_type='User',
                related_resource_id=user.id
            )

            next_page = request.args.get('next')
            return redirect(next_page or url_for('routes.home'))
        else:
            flash(f"Invalid username or password.", 'error')
            app_logger.warning(f"Failed login attempt for username: {username}.")
            return render_template('login.html', username=username)

    return render_template('login.html')

@auth.route('/logout')
@login_required
def logout():
    username = current_user.username
    user_id = current_user.id

    app_logger.info(f"User {current_user.username} (ID: {current_user.id}) logged out.")
    logout_user()
    flash(f"You have been logged out.", 'info')

    log_activity(
        event_type='USER_LOGOUT',
        description=f"User {username} logged out.",
        user_id=user_id,
        username=username,
        related_resource_type='User',
        related_resource_id=user_id
    )

    return redirect(url_for('auth.login'))
