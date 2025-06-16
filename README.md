# Reset and envionment
./clean.sh

# Setup the python venv, install dependencies and setup the db.
sudo ./setup.sh

# Populate users in db
./populate_db.sh

# Start services
./start_firework.sh

# Stop services
./stop_firework.sh

# Verify users in db
psql -h localhost -U firework -d fireworkdb -c "SELECT username, email, role FROM \"user\";"
