#!/bin/bash
user=$(args[1])
host=$(args[2])
absolute_path=$(args[3])
scp -i remote_VM_ssh_id config_test.JSON $user@$host:$absolute_path
scp -i remote_VM_ssh_id random_flags $user@$host:$absolute_path
scp -i remote_VM_ssh_id test_util.py $user@$host:$absolute_path
scp -i remote_VM_ssh_id sync_with_network.sh $user@$host:$absolute_path
