cd nvd


To compile the code -------------------------------------------------
g++ -std=c++11 -o nvd nvd_data.cpp -lcurl -lpqxx -lpq



To set cronjob ------------------------------------------------------
crontab -e

00 1 * * * /home/devesh/nvd/nvd.sh >> /home/devesh/nvd/nvd.log 2>&1

