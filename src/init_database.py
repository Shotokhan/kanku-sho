import json
import sys
import os

from sqlite_functions import init_database


if __name__ == "__main__":
    if len(sys.argv) < 2:
        config_name = 'config.JSON'
    else:
        config_name = sys.argv[1]
    with open(config_name, 'r') as f:
        config = json.load(f)
    traffic_db = config['traffic_db']['db_name']
    db_name = traffic_db.split("/")[-1]
    traffic_dir = os.listdir("/".join(traffic_db.split("/")[:-1]))
    if db_name not in traffic_dir:
        init_database(traffic_db)
    else:
        print("init_database.py: Database already initialized.")
