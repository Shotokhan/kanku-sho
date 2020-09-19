# kanku-sho 
<br /> <br />
kanku-sho is a tool for the following workflow:
<br />
1) Remote traffic capture over SSH, copy of capture files to local filesystem and erasing of the same files on the remote system.
<br />
2) Analysis of capture files using pyshark, with a filtering based on a regular expression that can be found in TCP/HTTP streams.
<br />
3) Object relational mapping of the result of the analysis in a SQLite database, using gzip to compress payload data (such as HTML pages).
<br />
4) Flask interface to query filtered capture data; one of the features of the interface is the possibility to automatically generate python requests/pwntools code from HTTP/TCP streams. Furthermore, streams are also hallmarked by the fact that the regex comes in or goes out from the "attacked" machine.
<br /> <br />
The remote machine should have SSH enabled, and in order for the remote sniffing to work properly, you have to install an identity file on the remote machine.
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
<br />
1) remote_sniffer.py
<br />
2) analysis_controller.py
<br />
3) flask_interface.py
<br /> <br />
(1) and (2) can be executed together by run_threads.py, but depending on your operating system, there could be issues with pyshark.
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
<br /> Since I used this tool in some attack/defense CTF, there are some requirements which are not strictly necessary, such as BeautifulSoup: I used it to write some exploits against web services. So, if you want the minimal set of requirements, maybe with the latest version, I suggest you to erase requirements.txt, open the project with some IDE like PyCharm (Community Edition) and let the IDE find the requirements for you.
<br /> <br />
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
In summary, you have many interfaces for this tool, and you can use it to filter and analyse easily TCP (netcat like) and HTTP streams, to discover attack vectors and build replay attacks.
<br /> <br />