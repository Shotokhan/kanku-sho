import sys
import json
import urllib.parse

from pyshark_functions import serialize_parameters, order_payloads, export_parameters
from util_raw_data import decode_raw, decompress_blob
from sqlite_functions import query_capture_files, query_streams, query_payloads, query_services_stats, \
    query_possible_http_exploits, query_possible_tcp_exploits


def get_capture_files(db_name, params=None):
    result = query_capture_files(db_name, params)
    dict_result = [{"id": row[0], "timestamp": row[1], "user": row[2], "host": row[3], "flag_regex": row[4],
                    "interface": row[5]} for row in result]
    return dict_result


def get_streams(db_name, params=None):
    result = query_streams(db_name, params)
    dict_result = [{"id": row[0], "number": row[1], "capture_file_ID": row[2], "local_ip": row[3],
                    "local_port": row[4], "remote_ip": row[5], "remote_port": row[6], "protocol": row[7],
                    "type": row[8], "flag_sn": row[9]} for row in result]
    return dict_result


def get_stream_with_payloads(db_name, stream_id, plaintext=False):
    try:
        stream = get_streams(db_name, {"id": stream_id})[0]
    except IndexError:
        return {}
    result = query_payloads(db_name, stream['id'], stream['protocol'])
    dec = lambda data: decode_raw(decompress_blob(data), printable=True) if plaintext else data
    pars = lambda parameters: urllib.parse.unquote_plus(parameters) if plaintext else export_parameters(parameters)
    if stream['protocol'] == 'tcp':
        dict_result = [{"sequence_number": row[0], "type": row[1], "data": dec(row[2]),
                        "id": row[3]} for row in result]
    else:
        dict_result = [{"sequence_number": row[0], "type": row[1], "data": dec(row[2]),
                        "id": row[7], "http": {"method": row[3], "URI": urllib.parse.unquote_plus(row[4]),
                                               "parameters": pars(row[5]), "status_code": row[6]}} for row in result]
    stream['payloads'] = dict_result
    return stream


def get_services_stats(db_name):
    stats = query_services_stats(db_name)
    dict_stats = [{"local_port": row[0], "protocol": row[1], "flags_out": row[2],
                   "Related": {"name": "Streams", "value": row[0], "query_parameter": "local_port",
                               "action": "/search_stream"}} for row in stats]
    return dict_stats


def get_possible_http_exploits(db_name):
    exploits = query_possible_http_exploits(db_name)
    clean = lambda r: urllib.parse.unquote_plus(r)
    dict_http_exploits = [{"local_port": row[0], "sequence_number": row[1], "uri": clean(row[2]), "method": row[3],
                           "parameters": clean(row[4]), "Related": {"name": "Stream",
                                                                    "value": row[5],
                                                                    "query_parameter": "id",
                                                                    "action": "/show_stream"}} for row in exploits]
    return dict_http_exploits


def get_possible_tcp_exploits(db_name):
    exploits = query_possible_tcp_exploits(db_name)
    dec = lambda data: decode_raw(decompress_blob(data), printable=True)
    dict_tcp_exploits = [{"local_port": row[0], "sequence_number": row[1], "payload": dec(row[2]),
                          "Related": {"name": "Stream", "value": row[3], "query_parameter": "id",
                                      "action": "/show_stream"}} for row in exploits]
    return dict_tcp_exploits


def prepare_stream_for_printing(stream, host):
    # for test purposes; each application defines its own print rule
    prepared = []
    payloads = order_payloads(stream)
    port = lambda p: stream['local_port'] if p['type'] == 'request' else stream['remote_port']
    ip = lambda p: host if p['type'] == 'request' else stream['remote_ip']
    for payload in payloads:
        p_type = "{} to {}:{}".format(payload['type'], ip(payload), port(payload))
        if stream['protocol'] == 'tcp':
            out_tuple = (p_type, decode_raw(decompress_blob(payload['data']), printable=True))
        elif payload['type'] == 'request':
            http = payload['http']
            data = "{} {}".format(http['method'], http['URI'])
            params = serialize_parameters(http['parameters'])
            if len(params) > 0:
                data += "\nParameters: {}".format(params)
            out_tuple = (p_type, data)
        else:
            http = payload['http']
            data = "Status code: {}\n".format(http['status_code'])
            data += decode_raw(decompress_blob(payload['data']), printable=True)
            out_tuple = (p_type, data)
        prepared.append(out_tuple)
    return prepared


def print_stream(prepared, outfile=sys.stdout):
    # for test purposes; each application defines its own print rule
    for _tuple in prepared:
        print("-------------- {} --------------".format(str.upper(_tuple[0])), file=outfile)
        print(_tuple[1], file=outfile)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Error, usages:")
        print("python interface.py <stream_number>")
        print("python interface.py <stream_number> <outfile>")
    else:
        with open('config.JSON', 'r') as f:
            config = json.load(f)
        global_config = config['global']
        host = global_config['host']
        db_name = config['traffic_db']['db_name']
        stream_num = sys.argv[1]
        data = get_capture_files(db_name)[0]
        stream = get_streams(db_name, {"number": stream_num})[0]
        stream = get_stream_with_payloads(db_name, stream['id'])
        printable = prepare_stream_for_printing(stream, host)
        if len(sys.argv) > 2:
            outfile = sys.argv[2]
            with open(outfile, 'w') as f:
                print_stream(printable, f)
        else:
            print_stream(printable)
