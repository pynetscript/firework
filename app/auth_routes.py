from flask import Blueprint, render_template, redirect, url_for, flash, request, jsonify
from app.models import db, User
from flask_login import login_user, logout_user, login_required, current_user
from datetime import datetime
import logging

auth = Blueprint('auth', __name__)

# Get the Flask app logger
app_logger = logging.getLogger(__name__)

@auth.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        # If user is already logged in, redirect to home or dashboard
        flash('You are already logged in.', 'info')
        app_logger.info(f"Attempted to access login page while already authenticated: User ID {current_user.id}")
        return redirect(url_for('routes.home'))

    if request.method == 'POST':
        username = request.form.get('username')
        password = request.form.get('password')

        user = User.query.filter_by(username=username).first()

        if user and user.check_password(password):
            login_user(user)
            user.last_login = datetime.utcnow()
            db.session.commit()
            flash('Logged in successfully!', 'success')
            app_logger.info(f"User {username} (ID: {user.id}) logged in successfully.")
            # Redirect to the page the user was trying to access, or home
            next_page = request.args.get('next')
            return redirect(next_page or url_for('routes.home'))
        else:
            flash('Invalid username or password.', 'error')
            app_logger.warning(f"Failed login attempt for username: {username}.")
            # Return to login form if login fails
            return render_template('login.html', username=username) # Pass username back to pre-fill

    return render_template('login.html')

@auth.route('/logout')
@login_required # Ensure only logged-in users can logout
def logout():
    app_logger.info(f"User {current_user.username} (ID: {current_user.id}) logged out.")
    logout_user()
    flash('You have been logged out.', 'info')
    return redirect(url_for('auth.login'))

