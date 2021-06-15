#!/bin/bash
# This is intended to run the main modules in Docker, because Docker allows only one CMD at a time
srcPath=/usr/src/app/src
vol=/usr/src/app/volume
config="$vol/config.JSON"
python -u "$srcPath/init_database.py" "$config" > "$vol/init_database_log.txt"
declare -a pids
nohup python -u "$srcPath/flask_interface.py" "$config" > "$vol/flask_interface_log.txt" 2>&1 &
pids[0]=$!
nohup python -u "$srcPath/remote_sniffer.py" "$config" > "$vol/remote_sniffer_log.txt" 2>&1 &
pids[1]=$!
nohup python -u "$srcPath/analysis_controller.py" "$config" > "$vol/analysis_controller_log.txt" 2>&1 &
pids[2]=$!
for pid in ${pids[*]}; do
  wait $pid
done
