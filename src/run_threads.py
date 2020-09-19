from threading import Thread
import json
import sys

from remote_sniffer import remote_sniffing
from analysis_controller import greedy_analysis


class Sniffer(Thread):
    def __init__(self, global_config, capture_config):
        super().__init__()
        self.global_config = global_config
        self.capture_config = capture_config

    def run(self):
        remote_sniffing(self.global_config, self.capture_config)


class Analyser(Thread):
    def __init__(self, global_config, capture_config, traffic_db):
        super().__init__()
        self.global_config = global_config
        self.capture_config = capture_config
        self.traffic_db = traffic_db

    def run(self):
        greedy_analysis(self.global_config, self.capture_config, self.traffic_db)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        config_name = 'config.JSON'
    else:
        config_name = sys.argv[1]
    with open(config_name, 'r') as f:
        config = json.load(f)
    global_config = config['global']
    capture_config = config['capture']
    traffic_db = config['traffic_db']
    sniffer = Sniffer(global_config, capture_config)
    analyser = Analyser(global_config, capture_config, traffic_db)
    sniffer.start()
    analyser.start()
    sniffer.join()
    analyser.join()
