# Dumb script to generate some traffic on localhost including the flag regex; generate flags offline and pass a file

import os
import json
import random
import time


def run_server(flag_filename):
    os.system("touch {}".format(flag_filename))
    os.system("python -m SimpleHTTPServer 8000 &")


def make_request(req_type, flag):
    reqs = {
        "get": "curl -X GET localhost:8000",
        "options": "curl -X OPTIONS localhost:8000",
        "post": "curl -X POST --data 'flag={}' localhost:8000".format(flag)
    }
    os.system(reqs[req_type])


if __name__ == "__main__":
    with open('config.JSON', 'r') as f:
        config = json.load(f)
    with open('random_flags', 'r') as f:
        flags = f.read().splitlines()
    methods = ["get", "options", "post"]
    round_time = config['global']['round_timeout']
    req_sleep = round_time / 3
    run_server(random.choice(flags))
    time.sleep(5)
    while True:
        make_request(random.choice(methods), random.choice(flags))
        time.sleep(req_sleep)
