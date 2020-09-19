import subprocess
import os


def subprocess_wrapper(command):
    try:
        sub = subprocess.run(command, capture_output=True)
        if sub.returncode == 0:
            return sub.stdout.decode('utf-8')
        else:
            return sub.stderr.decode('utf-8')
    except:
        print("Exception")
        system_wrapper(command)


def system_wrapper(command):
    os.system(" ".join(command))
