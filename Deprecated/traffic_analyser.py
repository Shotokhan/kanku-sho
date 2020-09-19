from util_capture_files import *
from tcp_convs import *
from util_regex import check_for_flag
from time import sleep


def run():
    while 1:
        files = list_dir()
        interesting_files = set()
        files = capture_files(files)
        for file in files:
            convs = tcp_convs(file)
            tcp_convs_rows = convs[1]
            peers = get_peers(tcp_convs_rows)
            exclude_rule = lambda peer: "10.10.17" in peer
            peers = filter_peers(peers, exclude_rule)
            for hosts_pair in peers:
                data = tcp_stream(file, hosts_pair)
                if check_for_flag(data):
                    interesting_files.add(file)
                    report_conv(file, data, hosts_pair, "Interesting_files")
        for file in files:
            if file not in interesting_files:
                move_file(file, "Analysis_done")
            else:
                move_file(file, "Interesting_files")
        sleep(5)


if __name__ == "__main__":
    run()
