import sys
import time
from util_capture_files import remote_capture
from util_capture_files import remote_delete
from util_remote import grep_file


def run(user, host, port, identity_file, folder_path, traffic_interface, timeout):
    while 1:
        timestamp = time.strftime("%d_%m_%Y_%H:%M", time.localtime())
        filename = "capture_{}_{}".format(traffic_interface, timestamp)
        fullpath_filename = "{}/{}".format(folder_path, filename)
        remote_capture(user, host, port, traffic_interface, fullpath_filename, identity_file, timeout)
        # time.sleep(float(timeout))
        grep_file(user, host, port, identity_file, fullpath_filename)
        remote_delete(user, host, port, fullpath_filename, identity_file)


if __name__ == "__main__":
    if len(sys.argv) != 8:
        print("Bad usage: 7 arguments required, see source code")
    else:
        run(*sys.argv[1:])
