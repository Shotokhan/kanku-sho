import os


def ssh_wrapper(global_config, remote_command):
    user = global_config['user']
    host = global_config['host']
    port = global_config['port']
    identity_file = global_config['identity_file']
    command = "ssh -i {} -p {} {}@{} '{}'".format(identity_file, port, user, host, remote_command)
    os.system(command)


def scp_getfile_wrapper(global_config, remote_file_path, local_path):
    user = global_config['user']
    host = global_config['host']
    port = global_config['port']
    identity_file = global_config['identity_file']
    command = "scp -i {} -P {} {}@{}:{} {}".format(identity_file, port, user, host, remote_file_path, local_path)
    os.system(command)