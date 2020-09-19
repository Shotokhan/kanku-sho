import rstr
import json


def gen_flag(reg):
    return rstr.xeger(reg)


if __name__ == "__main__":
    num_flags = 100
    with open('config.JSON', 'r') as f:
        config = json.load(f)
    regex = config['global']['flag_regex']
    with open("random_flags", 'w') as f:
        for _ in range(num_flags):
            f.write(gen_flag(regex))
            f.write("\n")
