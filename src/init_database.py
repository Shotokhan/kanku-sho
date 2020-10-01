import json

from sqlite_functions import init_database


if __name__ == "__main__":
    with open('config.JSON', 'r') as f:
        config = json.load(f)
    traffic_db = config['traffic_db']
    init_database(traffic_db['db_name'])
