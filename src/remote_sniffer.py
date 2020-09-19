import time
import json
import sys

from remote_wrapper import *


def capture_command(port, interface, filename, round_time, run_with_sudo):
    sudo = "sudo " if run_with_sudo else ""
    cap_comm = sudo + "nohup timeout {} tcpdump -s0 -i {} -U -w {} not port {} > /dev/null 2>&1 &"
    return cap_comm.format(round_time, interface, filename, port)


def remote_sniffing(global_config, capture_config):
    prefix = capture_config['cap_filename_prefix']
    interface = capture_config['remote_interface']
    remote_path = capture_config['remote_pcap_folder']
    if remote_path[-1] != "/":
        remote_path += "/"
    local_path = capture_config['local_pcap_folder']
    run_with_sudo = capture_config['run_with_sudo']
    time_string = capture_config['time_string']
    round_time = global_config['round_timeout']
    port = global_config['port']
    sudo = "sudo " if run_with_sudo else ""
    while True:
        timestamp = time.strftime(time_string, time.localtime())
        filename = "{}_{}_{}.pcap".format(prefix, interface, timestamp)
        remote_file_path = remote_path + filename
        cap_comm = capture_command(port, interface, remote_file_path, round_time, run_with_sudo)
        ssh_wrapper(global_config, cap_comm)
        time.sleep(round_time)
        scp_getfile_wrapper(global_config, remote_file_path, local_path)
        ssh_wrapper(global_config, sudo + "rm -f {}".format(remote_file_path))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        config_name = 'config.JSON'
    else:
        config_name = sys.argv[1]
    with open(config_name, 'r') as f:
        config = json.load(f)
    global_config = config['global']
    capture_config = config['capture']
    remote_sniffing(global_config, capture_config)
