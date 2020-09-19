import binascii
import gzip
import base64


def decode_raw(raw_data, printable=False):
    try:
        data = binascii.unhexlify(raw_data).decode('utf-8')
    except UnicodeDecodeError:
        data = "".join(map(chr, binascii.unhexlify(raw_data)))
    if printable:
        data = "".join([i if 0 < ord(i) < 255 else '.' for i in data])
    return data


def encode_raw(ascii_data):
    try:
        out = binascii.hexlify(ascii_data.encode('utf-8'))
    except TypeError:
        out = binascii.hexlify(ascii_data)
    return out


def compress_blob(hex_data):
    return gzip.compress(hex_data)


def decompress_blob(compressed_data):
    return gzip.decompress(compressed_data)


def encode_b64(bytes_in):
    return base64.b64encode(bytes_in).decode('utf-8')


def decode_b64(b64_string):
    return base64.b64decode(b64_string)

