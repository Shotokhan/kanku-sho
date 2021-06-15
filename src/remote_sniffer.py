import json
import sys
import time
import os

from remote_wrapper import ssh_wrapper, remote_getfile_wrapper


def capture_command(port, interface, filename, run_with_sudo, num_files, file_size):
    sudo = "sudo " if run_with_sudo else ""
    cap_comm = sudo + "nohup tcpdump -C {} -z bzip2 -W {} -s0 -i {} -U -w {} not port {} > /dev/null 2>&1 &"
    # rotate_seconds = round_time // num_files + base_time
    # putting together -C, -W and -G results in weird things
    return cap_comm.format(file_size, num_files, interface, filename, port)


def remote_sniffing(global_config, capture_config):
    prefix = capture_config['cap_filename_prefix']
    interface = capture_config['remote_interface']
    remote_path = capture_config['remote_pcap_folder']
    if remote_path[-1] != "/":
        remote_path += "/"
    local_path = capture_config['local_pcap_folder']
    if local_path[-1] != "/":
        local_path += "/"
    run_with_sudo = capture_config['run_with_sudo']
    num_files = capture_config['num_circular_files']
    init_sleep_time = capture_config['initial_sleep_time']
    cap_file_size = capture_config['capture_file_size']
    is_local_capture = capture_config['local_capture']
    port = global_config['port']
    sudo = "sudo " if run_with_sudo else ""
    sleep_time = init_sleep_time
    filename = "{}_{}.pcap".format(prefix, interface)
    remote_file_path = remote_path + filename
    cap_comm = capture_command(port, interface, remote_file_path, run_with_sudo, num_files, cap_file_size)
    if not is_local_capture:
        ssh_wrapper(global_config, cap_comm)
    else:
        os.system(cap_comm)
    while True:
        print("Sleep time: {}".format(sleep_time))
        time.sleep(sleep_time)
        start = time.time()
        if not is_local_capture:
            remote_getfile_wrapper(global_config, remote_path + "*.bz2", local_path)
        else:
            os.system("mv {}*.bz2 {}".format(remote_path, local_path))
        end = time.time()
        sleep_time = min(1 + init_sleep_time / (end-start), init_sleep_time)
        os.system('bzip2 -df {}*.bz2'.format(local_path))
        if not is_local_capture:
            ssh_wrapper(global_config, sudo + "rm -f {}".format(remote_file_path + "*.bz2"))


if __name__ == "__main__":
    if len(sys.argv) < 2:
        config_name = 'config.JSON'
    else:
        config_name = sys.argv[1]
    with open(config_name, 'r') as f:
        config = json.load(f)
    if 'run' in config.keys():
        if not config['run']['remote_sniffer']:
            print("remote_sniffer.py: exiting because of run configuration.")
            exit(0)
    global_config = config['global']
    capture_config = config['capture']
    remote_sniffing(global_config, capture_config)
