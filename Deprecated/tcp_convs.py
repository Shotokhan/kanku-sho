from tshark_wrapper import tshark_wrapper


def tcp_convs(capture_file):
    fields = ['Left peer', 'Right peer', 'Right to left frames', 'Right to left bytes', 'Left to right frames',
              'Left to right bytes', 'Total frames', 'Total bytes', 'Relative start', 'Duration']
    oneline = tshark_wrapper(capture_file, "conv,tcp")
    ind = len(oneline) - oneline[-1::-1].find("|") - 1
    oneline = oneline[ind + 1:]
    data = oneline.split(" ")
    data = list(filter(lambda f: f not in ['', '<->'], data))
    data = data[:-1]
    rows = [data[i * len(fields):(i + 1) * len(fields)] for i in range(len(data) // len(fields))]
    return [fields, rows]


def get_peers(tcp_conv_rows):
    peers = []
    for row in tcp_conv_rows:
        hosts_pair = [row[0], row[1]]
        peers.append(hosts_pair)
    return peers


def tcp_stream(capture_file, hosts_pair):
    hosts_pair_string = "{},{}".format(hosts_pair[0], hosts_pair[1])
    stream = tshark_wrapper(capture_file, "follow,tcp,ascii,{}".format(hosts_pair_string))
    delimiters = [hosts_pair[1], "==================================================================="]
    start = stream.find(delimiters[0]) + len(delimiters[0]) + 1
    stop = stream.rfind(delimiters[1]) - 1
    data = stream[start:stop]
    return data


def filter_peers(peers, exclude_rule):
    filtered_list = []
    for hosts_pair in peers:
        if not (exclude_rule(hosts_pair[0]) and exclude_rule(hosts_pair[1])):
            filtered_list.append(hosts_pair)
    return filtered_list
