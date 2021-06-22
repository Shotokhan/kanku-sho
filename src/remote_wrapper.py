import os


def ssh_wrapper(global_config, remote_command):
    user = global_config['user']
    host = global_config['host']
    port = global_config['port']
    identity_file = global_config['identity_file']
    command = "ssh -oStrictHostKeyChecking=no -i {} -p {} {}@{} '{}'".format(identity_file, port,
                                                                             user, host, remote_command)
    os.system(command)


def remote_getfile_wrapper(global_config, remote_file_path, local_path):
    user = global_config['user']
    host = global_config['host']
    port = global_config['port']
    identity_file = global_config['identity_file']
    if local_path[0] != '/':
        local_path = '/' + local_path
    command = 'rsync -avz -e "ssh -oStrictHostKeyChecking=no -i {} -p {}" {}@{}:{} {} 2>/dev/null'.format(
                                                                    identity_file, port,
                                                                   user, host, remote_file_path,
                                                                   local_path)
    os.system(command)
