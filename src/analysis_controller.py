import time
from threading import Thread, Lock

from pyshark_functions import *
from util_directory import *
from sqlite_functions import insert_capture_dict


class DatabaseThread(Thread):
    def __init__(self, db_name, capture_dict, capture_config, mutex):
        super().__init__()
        self.db_name = db_name
        self.capture_dict = capture_dict
        self.capture_config = capture_config
        self.mutex = mutex

    def run(self):
        self.mutex.acquire(timeout=240)
        insert_capture_dict(self.db_name, self.capture_dict, self.capture_config)
        try:
            self.mutex.release()
        except RuntimeError:
            print("Tried to unlock an already unlocked mutex", file=sys.stderr)


def analyze_and_index_capture_files(capture_files, global_config, capture_config, traffic_db, mutex):
    for pcap_file in capture_files:
        data = pcap_scraping(pcap_file, global_config, capture_config)
        # write_json(data, pcap_file.split("/")[-1].split(".")[0] + ".JSON")
        db_name = traffic_db['db_name']
        db_thread = DatabaseThread(db_name, data, capture_config, mutex)
        db_thread.start()


def greedy_analysis(global_config, capture_config, traffic_db):
    # SQLite handles well one writer, multiple readers
    mutex = Lock()
    time_str = capture_config['time_string']
    pcap_folder = capture_config['local_pcap_folder']
    target_folder = capture_config['local_pcap_backup']
    preserve_all = capture_config['preserve_all']
    while True:
        capture_files = get_capture_files(pcap_folder)
        move_capture_files(target_folder, capture_files)
        timestamp = "_{}".format(time.strftime(time_str, time.localtime())) if preserve_all else ""
        new_list = ["{}/{}{}".format(target_folder, cap_file.split("/")[-1], timestamp) for cap_file in capture_files]
        print("{} capture files queued".format(len(new_list)))
        analyze_and_index_capture_files(new_list, global_config, capture_config, traffic_db, mutex)
        time.sleep(5)


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
    greedy_analysis(global_config, capture_config, traffic_db)
