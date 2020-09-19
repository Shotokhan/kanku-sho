import os


def get_capture_files(pcap_folder):
    files = os.listdir(pcap_folder)
    if pcap_folder[-1] != "/":
        pcap_folder += "/"
    capture_files = []
    for file in files:
        if ".pcap" in file:
            capture_files.append(pcap_folder + file)
    return capture_files


def move_capture_files(target_folder, capture_files):
    for file in capture_files:
        command = "mv {} {}".format(file, target_folder)
        os.system(command)
