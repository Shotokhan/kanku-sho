from subprocess_wrapper import subprocess_wrapper


def tshark_wrapper(capture_file, filter_exp):
    command = ["tshark", "-q", "-r", capture_file, "-z", filter_exp]
    return subprocess_wrapper(command)

