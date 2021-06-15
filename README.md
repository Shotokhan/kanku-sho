# kanku-sho 
<br /> <br />
kanku-sho is a tool for the following workflow:
<br />
1) Remote traffic capture over SSH, copy of capture files to local filesystem and erasing of the same files on the remote system.

2) Analysis of capture files using pyshark, with a filtering based on a regular expression that can be found in TCP/HTTP streams.

3) Object relational mapping of the result of the analysis in a SQLite database, using gzip to compress payload data (such as HTML pages).

4) Flask interface to query filtered capture data; one of the features of the interface is the possibility to automatically generate python requests/pwntools code from HTTP/TCP streams. Furthermore, streams are also hallmarked by the fact that the regex comes in or goes out from the "attacked" machine.
<br />
The remote machine should have SSH enabled, and in order for the remote sniffing to work properly, you have to install an identity file on the remote machine.
<br />
If you want, you can also capture local traffic, by configuring "capture" -> "local_capture" -> true in config.JSON (see more later about which config.JSON you should use); in this case, "remote_pcap_folder" will actually be a local folder.
<br />
The task is easy:
<br />
ssh-keygen -f your_path/your_key -t ecdsa -b 521
<br />
ssh-copy-id -i your_path/your_key remote_system_user@remote_system_host
<br /> <br />
Then you change the config.JSON file accordingly.<br />
You can have more workflows operating in parallel on different hosts, either on the same local database or on multiple databases; I suggest to use the same DB because in Flask the configuration file is hard-coded, i.e. you can't pass a configuration file in input, in contrast with the other main modules: they use config.JSON as default, but you can pass another file if you want.
<br /> <br />
The main modules are three:

1) remote_sniffer.py

2) analysis_controller.py

3) flask_interface.py
<br />

# Run with Docker
<br /> <br />
It is the easiest setup. In this case, you don't have to edit the config.JSON that you find in /src folder, but the config.JSON that you find in /volume folder.
<br />
The best thing to do is to put your identity file in the volume, to avoid re-building the image every time. Specify its path in config.JSON, under "global" -> "identity_file".
<br />
Since you may want to execute just the interface, for example, you can specify in "run" dict of config.JSON which modules you want to run (set true if you want to run the module).
<br /> <br />

# Run on the host
<br /> <br />
A little bit harder setup but more performant (Docker adds a layer to a pipeline).
<br /> <br />
Modules (1) and (2) can be executed together by run_threads.py, but depending on your operating system, there could be issues with pyshark.
<br /> <br />
Before using a new database, you have to run init_database.py, which will create a new database with the pre-defined DB schema, with the name defined in config.JSON. The database should be first created with: <br />
sqlite3 db_name <br />
But it is not necessary, since init_database.py should create it if it is not present.
<br /> <br />
I suggest to not install all dependencies directly on your operating system; use a venv instead.
<br />
Create the venv: <br />
python3 -m venv your_venv
<br /> Use the venv (always before run scripts / before using pip): <br />
source your_venv/bin/activate <br />
<br /> Install dependencies in venv: <br />
pip install -r requirements.txt
<br /> To build requirements.txt, I used the following command, and I suggest to you to use the same command if you make some changes to the source code:
<br />
pip freeze > requirements.txt <br />

You are not forced to run all the main modules simultaneously: you could also take some traffic files you already have, put them in a folder, run analysis_controller.py and wait for the database to be ready; then you open flask_interface.py (you can also run the interface while the analysis is in progress) and gain insights from the analysis.
<br /> <br />
You can also connect directly to the sqlite database, see the DB schema, which is similar to the JSON schema.
<br /> <br />
You can pass a single pcap file and get the result of the analysis in a JSON file in the following way: <br />
python pyshark_functions.py pcap_file <br />
It writes, by default, on a file called test_pyshark_functions.JSON
<br /> <br />
At this point, if you use the JSON, you could also try the util_code_generation.py, calling it as main and passing the name of the JSON file and the number of the stream you want to export.
<br /> <br />
You can use the interface.py to build some interfaces other than Flask, such as a CLI, or you can run interface.py as main to get a pretty printing of a stream: you specify a stream number, optionally an outfile (otherwise it prints to standard output) and the interface will connect to database grepping the stream. I built this to test queries, at start, before implementing the Flask interface.
<br /> <br />
You can also use the code in Generate_test_traffic folder, connecting to some Ubuntu server virtual machine, to test all the modules together and start playing with the interface. If you change the flag regex, you have to run generate_flags.py again, because you need a random_flags file. Install the identity file on the Ubuntu server machine as described before, and run copy_test_utils.sh with parameters user, host and absolute path.
<br /> <br />
Note: it is targeted for Linux systems, because of the system calls made by remote_sniffer and analysis_controller; you need to have installed bzip2 and rsync on the analyzer host, and tcpdump on the target host. In addition to that, you need to have installed sqlite3 on the analyzer host.
<br /> <br />
In summary, you have many interfaces for this tool, and you can use it to filter and analyse easily TCP (netcat like) and HTTP streams, to discover attack vectors and build replay attacks.
<br /> <br />
