from flask import Flask
from app.models import db
from app.routes import routes
import logging
from logging.handlers import RotatingFileHandler
import os

def create_app():
    # Determine the project root (one level up from 'app' directory)
    project_root = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))

    # Define the absolute path for the SQLite database
    db_path = os.path.join(project_root, 'network.db')

    app = Flask(
        __name__,
        static_folder=os.path.join(project_root, 'static'),
        static_url_path='/static'
    )
    # Use the absolute path for SQLALCHEMY_DATABASE_URI
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{db_path}'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
    # Set a secret key for session management (required for flash messages)
    # In a production environment, this should be a strong, randomly generated string
    # and ideally loaded from an environment variable or secure config.
    app.config['SECRET_KEY'] = 'your_super_secret_key_here_change_this_in_production' 

    db.init_app(app)
    app.register_blueprint(routes)

    # --- Configure File Logging ---
    log_dir = '/var/log/firework'
    if not os.path.exists(log_dir):
        try:
            os.makedirs(log_dir)
        except OSError as e:
            print(f"ERROR: Failed to create log directory {log_dir}: {e}")
            pass

    try:
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, 'app.log'),
            maxBytes=1024 * 1024,
            backupCount=5
        )
        formatter = logging.Formatter(
            '%(asctime)s [%(levelname)s] %(name)s: %(message)s'
        )
        file_handler.setFormatter(formatter)
        file_handler.setLevel(logging.INFO)

        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)

        werkzeug_logger = logging.getLogger('werkzeug')
        werkzeug_logger.addHandler(file_handler)
        werkzeug_logger.setLevel(logging.INFO)

        app.logger.info("Firework application started and comprehensive file logging configured successfully.")
        app.logger.info(f"Database URI configured: {app.config['SQLALCHEMY_DATABASE_URI']}")
        app.logger.info(f"Current working directory: {os.getcwd()}")

    except Exception as e:
        app.logger.error(f"Failed to set up file logging: {e}")
    # --- End File Logging Configuration ---

    return app
