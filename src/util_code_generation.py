import json
import sys
from urllib.parse import quote_plus

from pyshark_functions import order_payloads
from pyshark_functions import read_json
from util_raw_data import decompress_blob


class CodeCursor:
    def __init__(self, data="", depth=0):
        self.code = data
        self.depth = depth
        
    def addCode(self, data):
        self.code += data
        
    def modifyDepth(self, delta_depth):
        self.depth += delta_depth


class CodeGenerator:
    def __init__(self, library, session_name, open_session, response_name, generate, response_wrapper=None):
        self.library = library
        self.session_name = session_name
        self.open_session = open_session
        self.response_name = response_name
        self.generate = generate
        if response_wrapper is None:
            self.response_wrapper = lambda var: var
        else:
            self.response_wrapper = response_wrapper

    def generate_instruction(self, cursor, instruction_type, params=None):
        if params is None:
            params = []
        return self.generate[instruction_type](cursor, *params)

    def new_session(self, cursor):
        instruction = "{} = {}.{}".format(self.session_name, self.library, self.open_session)
        return self.prepare_instruction(instruction, cursor)

    def import_library(self, cursor):
        instruction = "import {}".format(self.library)
        return self.prepare_instruction(instruction, cursor)

    def get_response_text(self):
        return self.response_wrapper(self.response_name)

    @staticmethod
    def newline(cursor, num_lines=1):
        for _ in range(num_lines):
            cursor.addCode("\n")

    @staticmethod
    def indent(cursor, amount=4, ch=' '):
        cursor.addCode(amount * ch)

    def add_instruction(self, cursor, prepared_instruction):
        if prepared_instruction['instruction'] == "no instruction":
            return
        indent_amount = 4 * prepared_instruction['depth']
        self.indent(cursor, amount=indent_amount)
        cursor.addCode(prepared_instruction['instruction'])
        self.newline(cursor)
        if "delta_depth" in prepared_instruction.keys():
            cursor.modifyDepth(prepared_instruction['delta_depth'])

    def add_multiple_instructions(self, cursor, list_of_prepared_instructions):
        for prepared_instruction in list_of_prepared_instructions:
            self.add_instruction(cursor, prepared_instruction)

    def add_comment(self, cursor, comment):
        instruction = "# {}".format(comment)
        self.add_instruction(cursor, self.prepare_instruction(instruction, cursor))

    @staticmethod
    def prepare_instruction(instruction, cursor, delta_depth=0):
        prepared = {"instruction": instruction, "depth": cursor.depth}
        if delta_depth != 0:
            prepared['delta_depth'] = delta_depth
        return prepared


class RequestsGenerator(CodeGenerator):
    def __init__(self, host, port):
        generate = {
            'request': self.call_method,
            'response': self.check_status_code
        }
        wrapper = lambda var: "{}.text".format(var)
        super().__init__("requests", "session", "Session()", "response", generate, wrapper)
        self.methods = {
            "GET": "{}.get({} + '{}'){}",
            "POST": "{}.post({} + '{}', data={})",
            "PUT": "{}.put({} + '{}', data={})",
            "OPTIONS": "{}.options({} + '{}'){}",
            "HEAD": "{}.head({} + '{}'){}"
        }
        self.url_name = "base_url"
        self.status_code = "status_code"
        self.base_url = "http://{}:{}".format(host, port)

    def new_session(self, cursor):
        # an hack into two instructions without the need for a list
        temp_cursor = CodeCursor("", cursor.depth)
        prepared = super().new_session(cursor)
        self.add_instruction(temp_cursor, prepared)
        instruction = "{} = '{}'".format(self.url_name, self.base_url)
        prepared = self.prepare_instruction(instruction, temp_cursor)
        self.add_instruction(temp_cursor, prepared)
        prepared = self.prepare_instruction(temp_cursor.code, temp_cursor)
        return prepared

    def call_method(self, cursor, method, uri, parameters=None):
        safe_chars = "/?=&@+"
        if parameters is None:
            parameters = {}
        if len(parameters.keys()) == 0:
            parameters = ""
        '''
        # Parameters should already be url encoded
        else:
            for par_name in parameters.keys():
                parameters[par_name] = quote_plus(parameters[par_name], safe=safe_chars)
        '''
        uri = quote_plus(uri, safe=safe_chars)
        method_call = self.methods[method].format(self.session_name, self.url_name, uri, str(parameters))
        instruction = "{} = {}".format(self.response_name, method_call)
        return self.prepare_instruction(instruction, cursor)

    def check_status_code(self, cursor, status_code):
        if status_code[0] != "3":
            instruction = "if {}.{} == {}:".format(self.response_name, self.status_code, status_code)
            return self.prepare_instruction(instruction, cursor, 1)
        else:
            return self.prepare_instruction("no instruction", cursor, 0)


class PwntoolsGenerator(CodeGenerator):
    def __init__(self, host, port):
        generate = {
            'request': self.send_line,
            'response': self.receive_line
        }
        open_session = "remote('{}', {})".format(host, port)
        super().__init__("pwn", "session", open_session, "response", generate)

    def send_line(self, cursor, line):
        instruction = "{}.sendline({})".format(self.session_name, line)
        return self.prepare_instruction(instruction, cursor)

    def receive_line(self, cursor, timeout=2):
        instruction = "{} = {}.recvrepeat({})".format(self.response_name, self.session_name, timeout)
        return self.prepare_instruction(instruction, cursor)


class ReGenerator(CodeGenerator):
    def __init__(self, flag_regex):
        generate = {
            'find_flags': self.find_flags
        }
        super().__init__("re", "known_flags", "set()", "flags", generate)
        self.flag_regex = flag_regex

    def new_session(self, cursor):
        instruction = "{} = {}".format(self.session_name, self.open_session)
        return self.prepare_instruction(instruction, cursor)

    def find_flags(self, cursor, resp_text):
        instruction = "{} |= set({}.findall('{}', {}))".format(self.session_name, self.library, self.flag_regex, resp_text)
        return self.prepare_instruction(instruction, cursor)


def get_params_from_stream(stream):
    get_params_func = {
        'tcp': get_params_from_TCP_stream,
        'http': get_params_from_HTTP_stream
    }
    # I have to make sure that the payloads are ordered
    ordered_payloads = order_payloads(stream)
    return get_params_func[stream['protocol']](ordered_payloads)


def get_params_from_TCP_stream(ordered_payloads):
    out = []
    for payload in ordered_payloads:
        if payload['type'] == 'request':
            uncompressed_hex = decompress_blob(payload['data'])
            data = [uncompressed_hex]
        else:
            data = []
        out.append({"type": payload['type'],
                    "sequence_number": payload['sequence_number'],
                    "data": data})
    return out


def get_params_from_HTTP_stream(ordered_payloads):
    out = []
    for payload in ordered_payloads:
        if payload['type'] == 'request':
            parameters = payload['http']['parameters']
            data = [payload['http']['method'], payload['http']['URI'], parameters]
        else:
            data = [payload['http']['status_code']]
        out.append({"type": payload['type'],
                    "sequence_number": payload['sequence_number'],
                    "data": data})
    return out


def generate_from_stream(stream, global_config):
    generator_class = {
        'tcp': PwntoolsGenerator,
        'http': RequestsGenerator
    }
    cursor = CodeCursor()
    params = get_params_from_stream(stream)
    host = global_config['host']
    port = stream['local_port']
    generator = generator_class[stream['protocol']](host, port)
    stream_type = stream['type']  # regex in or out?
    flag_regex = global_config['flag_regex']
    generator.add_comment(cursor, "Code generated according to traffic, from stream {}".format(stream['number']))
    generator.add_comment(cursor, "Check for possible refactoring of parameters and nested instructions")
    flag_sn = stream['flag_sn']
    if stream_type == "regex out":
        re_generator = ReGenerator(flag_regex)
        generator.add_instruction(cursor, generator.import_library(cursor))
        generator.add_instruction(cursor, re_generator.import_library(cursor))
        generator.newline(cursor, 2)
        generator.add_instruction(cursor, generator.new_session(cursor))
        generator.add_instruction(cursor, re_generator.new_session(cursor))
        for payload in params:
            generator.add_instruction(cursor, generator.generate_instruction(cursor, payload['type'], payload['data']))
            if payload['sequence_number'] >= flag_sn and payload['type'] == 'response':
                generator.add_instruction(cursor, re_generator.find_flags(cursor, generator.get_response_text()))
    else:
        generator.add_instruction(cursor, generator.import_library(cursor))
        generator.newline(cursor, 2)
        generator.add_instruction(cursor, generator.new_session(cursor))
        for payload in params:
            generator.add_instruction(cursor, generator.generate_instruction(cursor, payload['type'], payload['data']))
            if payload['sequence_number'] >= flag_sn and payload['type'] == 'response':
                generator.add_instruction(cursor, generator.prepare_instruction("print('flag in')", cursor))
    return cursor.code


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Error: usage python util_code_generation.py <json_file> <stream_num>")
    else:
        with open('config.JSON', 'r') as f:
            config = json.load(f)
        global_config = config['global']
        json_filename = sys.argv[1]
        stream_num = sys.argv[2]
        indexed_traffic = read_json(json_filename)
        stream = indexed_traffic['streams'][stream_num]
        code = generate_from_stream(stream, global_config)
        print(code)
