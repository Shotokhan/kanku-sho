from subprocess_wrapper import subprocess_wrapper


def remote_wrapper(user, host, port, identity_file, remote_command):
    command = ["ssh", "ssh://{}@{}:{}".format(user, host, port), "-i", identity_file, "'{}'".format(remote_command)]
    return subprocess_wrapper(command)


def grep_file(user, host, port, identity_file, remote_filename_fullpath):
    remote = "{}@{}:{}".format(user, host, "{}.pcap".format(remote_filename_fullpath))
    command = ["scp", "-i", identity_file, "-p", port, remote, "./"]
    return subprocess_wrapper(command)
