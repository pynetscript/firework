from flask import Flask, redirect, url_for, render_template, request, flash
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
from logging.handlers import RotatingFileHandler
from flask_login import LoginManager, current_user
import logging
import os
import sys

from app.models import db, User

OUTPUTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'outputs')

if not os.path.exists(OUTPUTS_DIR):
    os.makedirs(OUTPUTS_DIR)

def create_app():
    app = Flask(__name__)

    # Check for required environment variables at startup
    secret_key = os.environ.get('SECRET_KEY')
    database_url = os.environ.get('DATABASE_URL')

    # Terminate the application immediately if secrets are not set
    if not secret_key:
        print("ERROR: SECRET_KEY environment variable is not set.", file=sys.stderr)
        sys.exit(1)
    if not database_url:
        print("ERROR: DATABASE_URL environment variable is not set.", file=sys.stderr)
        sys.exit(1)

    app.config['SECRET_KEY'] = secret_key
    app.config['SQLALCHEMY_DATABASE_URI'] = database_url

    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

    db.init_app(app)
    migrate = Migrate(app, db)

    login_manager = LoginManager()
    login_manager.init_app(app)
    login_manager.login_view = 'auth.login'
    login_manager.login_message = 'Please log in to access this page.'
    login_manager.login_message_category = 'warning'

    @login_manager.user_loader
    def load_user(user_id):
        return User.query.get(int(user_id))

    log_file_path = os.path.join(app.root_path, '..', 'firework_app.log')
    handler = RotatingFileHandler(log_file_path, maxBytes=1 * 1024 * 1024 * 1024, backupCount=1)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.INFO)
    logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)

    @app.errorhandler(404)
    def page_not_found(e):
        app.logger.warning(f"404 Not Found: {request.path} from IP {request.remote_addr}")
        if not current_user.is_authenticated:
            # If not logged in, redirect to login page (silent)
            return redirect(url_for('auth.login'))
        else:
            # If logged in, redirect to /
            return redirect(url_for('routes.home'))

    from app.routes import routes
    from app.admin_routes import admin_bp
    from app.auth_routes import auth

    app.register_blueprint(routes)
    app.register_blueprint(admin_bp)
    app.register_blueprint(auth)

    if os.environ.get('WERKZEUG_RUN_MAIN') == 'true' or os.environ.get('FLASK_RUN_FROM_CLI') == 'true':
        app.logger.info("Database URI configured.")
        app.logger.info(f"Current working directory: {app.root_path}")
        app.logger.info("Application started. Secrets loaded from environment variables.")

    return app
