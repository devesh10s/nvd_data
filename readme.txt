https://github.com/devesh10s/nvd_data.git

cd nvd_data

sudo apt install postgresql-client postgresql libpqxx-dev libssl-dev -y

# Create PSQL User

sudo -u postgres bash -c "psql -c \"CREATE USER vajra WITH PASSWORD 'admin';\""

# Create database
sudo -u postgres psql -c 'create database nvd;'

# Create tables
sudo -u postgres psql -d nvd -a -f ~/nvd_data/sql/create_tables.sql



To compile the code -------------------------------------------------
g++ -std=c++11 -o nvd nvd_data.cpp -lcurl -lpqxx -lpq



To set cronjob ------------------------------------------------------
crontab -e

00 1 * * * /home/devesh/nvd/nvd.sh >> /home/devesh/nvd/nvd.log 2>&1

