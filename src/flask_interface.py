from flask import Flask, render_template, request, Response
import json
import html
import sys
from interface import get_capture_files, get_streams, get_stream_with_payloads, get_services_stats, \
    get_possible_http_exploits, get_possible_tcp_exploits
from util_code_generation import generate_from_stream
from sqlite_functions import str_to_time_int
from util_flask import redirect_post_to_get


app = Flask(__name__)

global config
global db_name


@app.route("/")
def main():
    return render_template('index.html')


@app.route("/search_capture", methods=['GET', 'POST'])
def search_capture():
    if request.method == 'POST':
        return redirect_post_to_get(request)
    elif request.method == 'GET':
        params = request.args.to_dict()
    else:
        return render_template('search_capture.html', params={})
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
    return render_template('search_capture.html', cap_list=cap_files, params=params)


@app.route("/search_stream", methods=['GET', 'POST'])
def search_stream():
    if request.method == 'POST':
        return redirect_post_to_get(request)
    elif request.method == 'GET':
        params = request.args.to_dict()
    else:
        return render_template('search_stream.html', params={})
    streams = get_streams(db_name, params)
    return render_template('search_stream.html', stream_list=streams, params=params)


@app.route("/show_stream", methods=['GET', 'POST'])
def show_stream():
    if request.method == 'POST':
        return redirect_post_to_get(request)
    elif request.method == 'GET':
        params = request.args.to_dict()
    else:
        return "Method not allowed"
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


@app.route("/generate_code_from_stream", methods=['GET', 'POST'])
def generate_code():
    if request.method == 'POST':
        return redirect_post_to_get(request)
    elif request.method == 'GET':
        params = request.args.to_dict()
    else:
        return "Method not allowed"
    try:
        stream_id = params['stream_id']
        stream = get_stream_with_payloads(db_name, stream_id)
        generated_code = generate_from_stream(stream, config['global'])
        return Response(generated_code, mimetype='text/plain')
    except (KeyError, IndexError):
        return Response('Error: invalid input', mimetype='text/plain')


@app.route("/show_insights", methods=['GET'])
def show_insights():
    insights = get_services_stats(db_name)
    return render_template('insights.html', insights=insights, name="Insights")


@app.route("/show_http_exploits", methods=['GET'])
def show_http_exploits():
    params = request.args.to_dict()
    limit, offset = params.get('limit'), params.get('offset')
    insights = get_possible_http_exploits(db_name, limit, offset)
    return render_template('insights.html', insights=insights, name="Possible HTTP exploits", limit=limit or 1000,
                           offset=offset or "")


@app.route("/show_tcp_exploits", methods=['GET'])
def show_tcp_exploits():
    params = request.args.to_dict()
    limit, offset = params.get('limit'), params.get('offset')
    insights = get_possible_tcp_exploits(db_name, limit, offset)
    return render_template('insights.html', insights=insights, name="Possible TCP exploits", limit=limit or 1000,
                           offset=offset or "")


if __name__ == "__main__":
    global db_name
    global config
    if len(sys.argv) < 2:
        config_name = 'config.JSON'
    else:
        config_name = sys.argv[1]
    with open(config_name, 'r') as f:
        config = json.load(f)
    if 'run' in config.keys():
        if not config['run']['flask_interface']:
            print("flask_interface.py: exiting because of run configuration.")
            exit(0)
    db_name = config['traffic_db']['db_name']
    app.debug = config['flask']['debug']
    app.run(host=config['flask']['host'], port=config['flask']['port'])
