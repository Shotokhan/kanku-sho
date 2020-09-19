import re


def check_for_flag(data):
    # regex = "[0-9A-Z]{31}="
    regex = "flg\{[A-Za-z0-9]{25}\}"
    match = re.search(regex, data)
    if match is not None:
        return True
    else:
        return False


def search_flags(data):
    regex = "flg\{[A-Za-z0-9]{25}\}"
    return re.findall(regex, data)