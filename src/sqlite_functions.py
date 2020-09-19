import sys
import json

import sqlite3
from datetime import datetime
from pyshark_functions import serialize_parameters
from pyshark_functions import read_json
from util_timer import timer_func


def str_to_time_int(data_string, time_string):
    date = datetime.strptime(data_string, time_string)
    return int(date.timestamp())


def open_database(db_name):
    conn = sqlite3.connect(db_name)
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


def close_database(conn):
    conn.commit()
    conn.close()


def init_database(db_name):
    conn = open_database(db_name)
    cursor = conn.cursor()
    p_key = "id INTEGER PRIMARY KEY AUTOINCREMENT"
    f_key = lambda field, referenced: "FOREIGN KEY({}) REFERENCES {}(id) ON DELETE CASCADE".format(field, referenced)
    cursor.execute('CREATE TABLE capture_file ({}, timestamp INTEGER, user TEXT, host TEXT, flag_regex TEXT, '
                   'interface TEXT);'.format(p_key))
    cursor.execute('CREATE TABLE stream ({}, number INTEGER, capture_file_ID INTEGER, local_port TEXT, '
                   'remote_port TEXT, remote_IP TEXT, protocol TEXT, type TEXT, flag_sn INTEGER, '
                   '{});'.format(p_key, f_key("capture_file_ID", "capture_file")))
    cursor.execute('CREATE TABLE payload ({}, type TEXT, data BLOB, stream_ID INTEGER, '
                   'sequence_number INTEGER, {});'.format(p_key, f_key("stream_ID", "stream")))
    cursor.execute('CREATE TABLE http ({}, payload_ID INTEGER, status_code TEXT, method TEXT, '
                   'parameters TEXT, URI TEXT, {});'.format(p_key, f_key("payload_ID", "payload")))
    close_database(conn)


@timer_func
def insert_capture_dict(db_name, capture_dict, capture_config):
    # depth first to handle well the id part
    time_string = capture_config['time_string']
    conn = open_database(db_name)
    cap_id = insert_capture_header(conn, capture_dict, time_string)
    for stream in list(capture_dict['streams'].values()):
        stream_id = insert_stream_header(conn, stream, cap_id)
        for payload in stream['payloads']:
            payload_id = insert_payload(conn, payload, stream_id)
            if 'http' in payload.keys():
                insert_http_header(conn, payload['http'], payload_id)
    close_database(conn)


def insert_capture_header(conn, capture_dict, time_string):
    query = 'INSERT INTO capture_file (timestamp, user, host, flag_regex, interface) VALUES (?, ?, ?, ?, ?);'
    q_format = (str_to_time_int(capture_dict['timestamp'], time_string), capture_dict['user'],
                capture_dict['host'], capture_dict['flag_regex'], capture_dict['interface'])
    cap_id = query_db(conn, query, q_format)
    conn.commit()
    return cap_id


def insert_stream_header(conn, stream, cap_id):
    query = 'INSERT INTO stream (number, capture_file_ID, local_port, remote_port, remote_IP, protocol, ' \
            'type, flag_sn) VALUES (?, ?, ?, ?, ?, ?, ?, ?);'
    q_format = (stream['number'], cap_id, stream['local_port'], stream['remote_port'], stream['remote_ip'],
                stream['protocol'], stream['type'], stream['flag_sn'])
    stream_id = query_db(conn, query, q_format)
    conn.commit()
    return stream_id


def insert_payload(conn, payload, stream_id):
    query = 'INSERT INTO payload (type, data, stream_ID, sequence_number) VALUES (?, ?, ?, ?);'
    q_format = (payload['type'], payload['data'], stream_id, payload['sequence_number'])
    payload_id = query_db(conn, query, q_format)
    conn.commit()
    return payload_id


def insert_http_header(conn, http, payload_id):
    query = 'INSERT INTO http (method, URI, parameters, status_code, payload_ID) VALUES (?, ?, ?, ?, ?);'
    params = serialize_parameters(http['parameters'])
    q_format = (http['method'], http['URI'], params, http['status_code'], payload_id)
    http_id = query_db(conn, query, q_format)
    conn.commit()
    return http_id


def query_db(conn, query, q_format=None):
    cursor = conn.cursor()
    try:
        if q_format is not None:
            cursor.execute(query, q_format)
        else:
            cursor.execute(query)
        if query.upper().startswith("SELECT"):
            return cursor.fetchall()
        elif query.upper().startswith("INSERT"):
            return cursor.lastrowid
        else:
            return []
    except ValueError or TypeError:
        return []


def build_query_with_placeholders(base_query, conds, params):
    # useful for queries that can have one or more parameters
    # example of conds and params:
    # conds = {"low_timestamp": "timestamp > ?", "high_timestamp": "timestamp < ?", "id": "id = ?"}
    # params = {"low_timestamp": 123456789}
    # note that a date must be converted to an integer timestamp
    try:
        checks = [conds[param] for param in sorted(list(params.keys()))]
        query = base_query + " WHERE " + " AND ".join(checks) + ";"
        q_format = tuple([value for value in [params[param] for param in sorted(list(params.keys()))]])
    except KeyError:
        print("KeyError: params = {}".format(params), file=sys.stderr)
        query = base_query + ";"
        q_format = None
    return query, q_format


def do_query_with_placeholders(db_name, base_query, conds, params=None):
    if params is None:
        params = {}
    conn = open_database(db_name)
    if len(list(params.keys())) > 0:
        query, q_format = build_query_with_placeholders(base_query, conds, params)
        result = query_db(conn, query, q_format)
    else:
        result = query_db(conn, base_query + ";")
    return result


def query_capture_files(db_name, params=None):
    base_query = "SELECT id, datetime(timestamp, 'unixepoch', 'localtime'), user, host, flag_regex, " \
                 "interface FROM capture_file"
    conds = {"low_timestamp": "timestamp > ?", "high_timestamp": "timestamp < ?", "user": "user = ?",
             "host": "host = ?", "id": "id = ?"}
    return do_query_with_placeholders(db_name, base_query, conds, params)


def query_streams(db_name, params=None):
    base_query = "SELECT s.id, s.number, c.id, c.host, s.local_port, s.remote_IP, s.remote_port, " \
                 "s.protocol, s.type, s.flag_sn FROM stream s INNER JOIN capture_file c ON " \
                 "s.capture_file_ID = c.id"
    conds = {"number": "s.number = ?", "capture_file_ID": "s.capture_file_ID = ?",
             "local_port": "s.local_port = ?", "remote_port": "s.remote_port = ?", "id": "s.id = ?",
             "remote_IP": "s.remote_IP = ?", "type": "s.type = ?", "protocol": "s.protocol = ?"}
    return do_query_with_placeholders(db_name, base_query, conds, params)


def query_payloads(db_name, stream_id, stream_protocol):
    conn = open_database(db_name)
    q_format = (stream_id,)
    if stream_protocol == 'tcp':
        query = "SELECT sequence_number, type, data, id FROM payload WHERE stream_ID = ? " \
                "ORDER BY sequence_number;"
    else:
        query = "SELECT p.sequence_number, p.type, p.data, h.method, h.URI, h.parameters, h.status_code," \
                " p.id FROM payload p INNER JOIN http h ON p.id = h.payload_id WHERE p.stream_ID = ? " \
                "ORDER BY p.sequence_number;"
    return query_db(conn, query, q_format)


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Error: usage python sqlite_functions.py <json_file>")
    else:
        with open('config.JSON', 'r') as f:
            config = json.load(f)
        traffic_db = config['traffic_db']
        capture_config = config['capture']
        db_name = traffic_db['db_name']
        json_filename = sys.argv[1]
        indexed_traffic = read_json(json_filename)
        insert_capture_dict(db_name, indexed_traffic, capture_config)