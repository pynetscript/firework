#!/usr/bin/env python3
from app import create_app
from app.models import db
from flask_migrate import Migrate

app = create_app()

migrate = Migrate(app, db)

if __name__ == '__main__':
    # Make Flask listen on all available network interfaces
    # WARNING: Do NOT use 0.0.0.0 in a production environment without proper security measures.
    app.run(debug=True, host='0.0.0.0')
