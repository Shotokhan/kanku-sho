import re


def check_for_flag(regex, data):
    match = re.search(regex, data)
    if match is not None:
        return True
    else:
        return False


def search_flags(regex, data):
    return re.findall(regex, data)


def search_timestamps(data, pattern="%d_%m_%Y_%H:%M:%S"):
    # TODO: refine time_lit_to_regex
    time_lit_to_regex = {
        "%d": '[0-9]{2}', "%m": '[0-9]{2}', "%Y": '[0-9]{4}', "%H": "[0-9]{2}", "%M": "[0-9]{2}",
        "%S": "[0-9]{2}"
    }
    regex = pattern
    for time_lit in list(time_lit_to_regex.keys()):
        regex = regex.replace(time_lit, time_lit_to_regex[time_lit])
    return re.findall(regex, data)
