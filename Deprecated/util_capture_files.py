import subprocess
from util_remote import remote_wrapper


def list_dir():
    command = ["ls"]
    sub = subprocess.run(command, capture_output=True)
    files = sub.stdout.decode('utf-8').split("\n")
    files = list(filter(lambda f: f != '', files))
    return files


def move_file(file, directory):
    command = ["mv", "-f", file, directory]
    subprocess.run(command)


def report_conv(file, data, hosts_pair, path):
    hosts_pair_string = "{},{}".format(hosts_pair[0], hosts_pair[1])
    with open("{}/{}_{}_conv".format(path, file, hosts_pair_string), 'w') as f:
        f.write(data)


def remote_capture(user, host, port, interface, filename, identity_file, timeout):
    remote_command = "sudo nohup timeout {} tcpdump -s0 -i {} -U -w {}.pcap not port 22 &".format(timeout, interface, filename)
    remote_wrapper(user, host, port, identity_file, remote_command)


def remote_delete(user, host, port, filename, identity_file):
    remote_command = "sudo rm -f {}.pcap".format(filename)
    remote_wrapper(user, host, port, identity_file, remote_command)


def capture_files(files_list):
    return list(filter(lambda f: ".pcap" in f, files_list))



