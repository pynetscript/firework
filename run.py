#!/usr/bin/env python3
from app import create_app
from app.models import db
from flask_migrate import Migrate

app = create_app()

migrate = Migrate(app, db)

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')
