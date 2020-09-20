from flask import Flask, render_template, request, Response
import json
import html
from interface import get_capture_files, get_streams, get_stream_with_payloads
from util_code_generation import generate_from_stream
from sqlite_functions import str_to_time_int


app = Flask(__name__)

with open('config.JSON', 'r') as f:
    config = json.load(f)
db_name = config['traffic_db']['db_name']


def pop_null(params_dict):
    new_params = {}
    for key in list(params_dict.keys()):
        if params_dict[key] != '':
            new_params[key] = params_dict[key]
    return new_params


@app.route("/")
def main():
    return render_template('index.html')


@app.route("/search_capture", methods=['GET', 'POST'])
def search_capture():
    if request.method == 'POST':
        params = request.form.to_dict()
        params = pop_null(params)
        if "low_timestamp" in list(params.keys()):
            try:
                params['low_timestamp'] = str_to_time_int(params['low_timestamp'], "%Y-%m-%d")
            except ValueError:
                params.pop('low_timestamp')
        if "high_timestamp" in list(params.keys()):
            try:
                params['high_timestamp'] = str_to_time_int(params['high_timestamp'], "%Y-%m-%d")
            except ValueError:
                params.pop('high_timestamp')
        cap_files = get_capture_files(db_name, params)
        return render_template('search_capture.html', cap_list=cap_files)
    return render_template('search_capture.html')


@app.route("/search_stream", methods=['GET', 'POST'])
def search_stream():
    if request.method == 'POST':
        params = request.form.to_dict()
        params = pop_null(params)
        streams = get_streams(db_name, params)
        return render_template('search_stream.html', stream_list=streams)
    return render_template('search_stream.html')


@app.route("/show_stream", methods=['POST'])
def show_stream():
    params = request.form.to_dict()
    params = pop_null(params)
    try:
        stream_id = params['id']
        stream = get_stream_with_payloads(db_name, stream_id, plaintext=True)
    except (KeyError, IndexError):
        return render_template('show_stream_tcp.html')
    if stream['protocol'] == 'http':
        xss_escape = lambda s: s.replace("<", "&lt").replace(">", "&gt")
        for payload in stream['payloads']:
            payload['data'] = html.escape(payload['data'])
            payload['http']['URI'] = xss_escape(payload['http']['URI'])
            payload['http']['parameters'] = xss_escape(payload['http']['parameters'])
        return render_template('show_stream_http.html', stream=stream)
    else:
        return render_template('show_stream_tcp.html', stream=stream)


@app.route("/generate_code_from_stream", methods=['POST'])
def generate_code():
    params = request.form.to_dict()
    params = pop_null(params)
    try:
        stream_id = params['stream_id']
        stream = get_stream_with_payloads(db_name, stream_id)
        generated_code = generate_from_stream(stream, config['global'])
        return Response(generated_code, mimetype='text/plain')
    except (KeyError, IndexError):
        return Response('Error: invalid input', mimetype='text/plain')


if __name__ == "__main__":
    app.debug = config['flask']['debug']
    app.run(host=config['flask']['host'], port=config['flask']['port'])
