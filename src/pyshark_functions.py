import json
import sys
import time

import pyshark
from pyshark.capture.capture import TSharkCrashException
from contextlib import suppress
import urllib.parse

import util_regex
from util_raw_data import *
from util_timer import timer_func


@timer_func
def pcap_scraping(pcap_file, global_config, capture_config):
    # It doesn't actually suppress the "Exception ignored" message, but the code works
    with suppress(TSharkCrashException):
        pcap = read_pcap(pcap_file)
        data = pcap_analysis(pcap, global_config, capture_config)
        pcap.close()
    return data


def read_pcap(pcap_file):
    pcap = pyshark.FileCapture(pcap_file)
    return pcap


def pcap_analysis(pcap, global_config, capture_config):
    host = global_config['host']
    flag_regex = global_config['flag_regex']
    time_str = capture_config['time_string']
    try:
        timestamp = str(util_regex.search_timestamps(pcap.input_filename, time_str)[0])
    except IndexError:
        timestamp = time.strftime(time_str, time.localtime())
    out = {'timestamp': timestamp,
           'user': global_config['user'],
           'host': host,
           'flag_regex': flag_regex,
           'interface': capture_config['remote_interface'],
           'streams': classify_streams(pcap, host, flag_regex)}
    return out


def read_http(http_pkt, _placeholder=None):
    out = {'http': {'method': "", 'URI': "", 'parameters': {}, 'status_code': ""}, 'type': "", 'data': b''}
    tcp_pkt = http_pkt.tcp
    http_pkt = http_pkt.http
    if is_http_request(http_pkt):
        out['http']['method'] = str(http_pkt.request_method)
        out['http']['URI'] = str(http_pkt.request_uri)
        out['type'] = 'request'
        if is_http_post_or_put(http_pkt):
            out['http']['parameters'] = export_parameters(http_pkt)
        try:
            full_data = decode_raw(str(tcp_pkt.payload.raw_value))
            token = '\r\n\r\n'  # http standard, but someone doesn't follow it
            # only need headers here
            try:
                headers = full_data.split(token)[0]
                out['data'] = headers
            except KeyError:
                token = '\n\n'
                try:
                    headers = full_data.split(token)[0]
                    out['data'] = headers
                except KeyError:
                    out['data'] = full_data
        except AttributeError:
            out['data'] = ""
        out['data'] = encode_raw(out['data'])
    else:
        out['type'] = 'response'
        if is_a_response_object(http_pkt):
            try:
                # out['data'] = encode_raw(str(http_pkt.file_data))
                # headers + file_data
                t1, t2 = '\n\n', '\r\n\r\n'
                out['data'] = encode_raw(decode_raw(str(tcp_pkt.payload.raw_value)).replace(t1, t2))
            except AttributeError:
                out['data'] = encode_raw(str(""))
            out['http']['status_code'] = str(http_pkt.response_code)
        else:
            out['http']['status_code'] = '500'
    return out


def read_tcp(tcp_pkt, local_port):
    out = {'data': b'', 'type': ""}
    tcp_pkt = tcp_pkt.tcp
    if contains_data(tcp_pkt):
        # alignment of encoding with decoding
        out['data'] = encode_raw(decode_raw(str(tcp_pkt.payload.raw_value)))
        if is_tcp_request(tcp_pkt, local_port):
            out['type'] = 'request'
        else:
            out['type'] = 'response'
    else:
        out['data'] = "no payload"
    return out


def is_tcp_request(tcp_pkt, local_port):
    # the concept of 'request' in TCP has meaning only if you know the port of the service
    if str(tcp_pkt.dstport) == local_port:
        return True
    else:
        return False


def contains_data(tcp_pkt):
    # this is used for TCP streams
    if 'payload' in dir(tcp_pkt):
        return True
    else:
        return False


def is_a_response_object(http_pkt):
    # some HTTP responses in pyshark only allow access to raw data, without status codes etc
    # Precondition: it is an HTTP response
    if 'response_code' in dir(http_pkt):
        return True
    else:
        return False


def is_http_request(http_pkt):
    # returns TRUE if it is a request, FALSE if it is a response
    if 'request_method' in dir(http_pkt):
        return True
    else:
        return False


def is_http_post_or_put(http_pkt):
    # check if there are parameters in input
    # Precondition: it is an HTTP request
    if 'file_data' in dir(http_pkt):
        return True
    else:
        return False


def export_parameters(http_pkt):
    # export input parameters to a dictionary
    # Precondition: it is an HTTP post
    parameters = {}
    try:
        assignments = str(http_pkt.file_data).split('&')
    except AttributeError:
        assignments = http_pkt.split('&')
    for ass in assignments:
        try:
            pair = ass.split('=')
            parameters[pair[0]] = pair[1]
        except IndexError:
            return parameters
    return parameters


def serialize_parameters(parameters):
    # serialize dictionary of parameters to URL string of parameters
    return '&'.join(['='.join([key, parameters[key]]) for key in parameters])


def get_streams(pcap):
    streams = set()
    try:
        for packet in pcap:
            if 'tcp' in dir(packet):
                streams.add(str(packet.tcp.stream))
    except TSharkCrashException:
        pass
    return list(streams)


def classify_streams(pcap, local_host, flag_regex):
    stream_nums = get_streams(pcap)
    classification = {stream: {"type": "no regex", "flag_sn": 1000000000000000000, "number": stream,
                               "protocol": "tcp", "tcp": [], "http": []} for stream in stream_nums}
    try:
        for packet in pcap:
            if 'tcp' in dir(packet):
                stream = packet.tcp.stream
                if 'http' in dir(packet):
                    if classification[stream]['protocol'] != 'http':
                        classification[stream]['protocol'] = 'http'
                        classification[stream]['tcp'] = []
                    classification[stream]['http'].append(packet)
                elif classification[stream]['protocol'] == 'tcp':
                    classification[stream]['tcp'].append(packet)
    except TSharkCrashException:
        pass
    for stream in stream_nums:
        stream_net_params(classification, stream, local_host)
    for stream in stream_nums:
        create_payloads(classification[stream])
        check_for_flag(classification[stream], flag_regex)
        if classification[stream]['type'] == "no regex":
            classification.pop(stream)
    # return [classification[stream] for stream in classification.keys()]
    return classification


def stream_net_params(classification, stream, local_host):
    stream_type = classification[stream]['protocol']
    srcport = str(classification[stream][stream_type][0].tcp.srcport)
    dstport = str(classification[stream][stream_type][0].tcp.dstport)
    srcip = str(classification[stream][stream_type][0].ip.src)
    dstip = str(classification[stream][stream_type][0].ip.dst)
    if srcip == local_host:
        classification[stream]['local_port'] = srcport
        classification[stream]['remote_port'] = dstport
        classification[stream]['remote_ip'] = dstip
    else:
        classification[stream]['local_port'] = dstport
        classification[stream]['remote_port'] = srcport
        classification[stream]['remote_ip'] = srcip


def create_payloads(stream):
    stream['payloads'] = []
    payload_dict = {}
    proto = stream['protocol']
    get_data = {'http': read_http, 'tcp': read_tcp}
    previous_type = None
    previous_sn = None
    for i in range(len(stream[proto])):
        payload = get_data[proto](stream[proto][i], stream['local_port'])
        if payload['data'] != "no payload":
            payload['sequence_number'] = i
            if previous_type is None:
                previous_sn = payload['sequence_number']
                previous_type = payload['type']
                payload_dict[previous_sn] = payload
            elif payload['type'] != previous_type or payload['type'] == 'request':
                payload_dict[previous_sn]['data'] = compress_blob(payload_dict[previous_sn]['data'])
                previous_sn = payload['sequence_number']
                previous_type = payload['type']
                payload_dict[previous_sn] = payload
            else:
                payload_dict[previous_sn]['data'] += payload['data']
    else:
        if previous_sn is not None:
            payload_dict[previous_sn]['data'] = compress_blob(payload_dict[previous_sn]['data'])
    stream.pop('tcp')
    stream.pop('http')
    stream['payloads'] = [payload_dict[sn] for sn in sorted(payload_dict.keys())]


def check_for_flag(stream, flag_regex):
    for payload in stream['payloads']:
        if stream['type'] != "no regex" and payload['sequence_number'] > stream['flag_sn']:
            continue
        data = decode_raw(decompress_blob(payload['data']))
        if util_regex.check_for_flag(flag_regex, data):
            if payload['type'] == 'request':
                stream['type'] = "regex in"
            else:
                stream['type'] = "regex out"
            stream['flag_sn'] = payload['sequence_number']
        elif 'http' in payload.keys():
            # unquote_plus if there are '+' representing spaces and if the regex has spaces
            params = urllib.parse.unquote(serialize_parameters(payload['http']['parameters']))
            uri = urllib.parse.unquote(payload['http']['URI'])
            if util_regex.check_for_flag(flag_regex, params + " " + uri):
                stream['type'] = "regex in"
                stream['flag_sn'] = payload['sequence_number']


def write_json(data, filename):
    # Warning: this function modifies the dict, replacing the compressed data with its base64 representation
    # The base64 representation is less compressed
    for stream_num in data['streams'].keys():
        for payload in data['streams'][stream_num]['payloads']:
            payload['data'] = encode_b64(payload['data'])
    with open(filename, 'w') as outfile:
        json.dump(data, outfile)


def read_json(filename):
    # Complementary of write_json, restores the dict
    with open(filename, 'r') as f:
        data = json.load(f)
    for stream_num in data['streams'].keys():
        for payload in data['streams'][stream_num]['payloads']:
            payload['data'] = decode_b64(payload['data'])
    return data


def order_payloads(stream):
    payload_dict = {payload['sequence_number']: payload for payload in stream['payloads']}
    ordered_payloads = [payload_dict[sn] for sn in sorted(payload_dict.keys())]
    return ordered_payloads


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Error: usage python pyshark_functions.py <pcap_file>")
    else:
        with open('config.JSON', 'r') as f:
            config = json.load(f)
        global_config = config['global']
        capture_config = config['capture']
        pcap_filename = sys.argv[1]
        data = pcap_scraping(pcap_filename, global_config, capture_config)
        write_json(data, 'test_pyshark_functions.JSON')

