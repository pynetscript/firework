from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate
import logging
from logging.handlers import RotatingFileHandler
import os
from flask_login import LoginManager

from app.models import db, User
# No need to import NetworkAutomationService here anymore, routes.py will handle its own instance.
# from app.services.network_automation import NetworkAutomationService 

OUTPUTS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..', 'outputs')
if not os.path.exists(OUTPUTS_DIR):
    os.makedirs(OUTPUTS_DIR)

def create_app():
    app = Flask(__name__)
    app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or 'firework'

    app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or \
        'postgresql://firework:firework@localhost:5432/fireworkdb'

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
    handler = RotatingFileHandler(log_file_path, maxBytes=100000, backupCount=10)
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    handler.setFormatter(formatter)
    app.logger.addHandler(handler)
    app.logger.setLevel(logging.DEBUG)
    logging.getLogger('sqlalchemy.engine').setLevel(logging.WARNING)

    app.logger.info(f"Database URI configured: {app.config['SQLALCHEMY_DATABASE_URI']}")
    app.logger.info(f"Current working directory: {app.root_path}")

    # Register blueprints (these imports will instantiate the blueprint objects)
    from app.routes import routes
    from app.admin_routes import admin_bp
    from app.auth_routes import auth

    # This is crucial:
    # Instead of attaching network_automation_service here directly to the blueprint,
    # we will rely on the `get_network_automation_service()` helper in routes.py
    # to lazily instantiate or fetch it when it's first needed within a request.
    # This avoids the blueprint being "registered" too early by virtue of this assignment.

    app.register_blueprint(routes)
    app.register_blueprint(admin_bp)
    app.register_blueprint(auth)

    return app
