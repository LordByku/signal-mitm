import logging
import subprocess
import sys
import os
import copy

def try_run(cmd: str):
    try:
        res = subprocess.run(cmd, shell=True, check=True, stdout=open(os.devnull, "wb"))
        # print(res.returncode)
    except subprocess.CalledProcessError as e:
        print(f"cmd failed: {e}\n{cmd}")


def try_run_sudo(cmd: str):
    logging.debug(f"trying to run command with sudo: {cmd}")
    try_run(f"sudo {cmd}")


def signal_handler(sig, frame):
    print("You pressed Ctrl+C!")
    sys.exit(0)


def open_terminal(command: str):
    os.system(f"gnome-terminal -- {command} &")


def strip_uuid_and_id(path: str):
    path = path.lower()
    words = path.split(":")

    if len(words) > 1:
        return tuple(words)
    else:
        return tuple(["aci", words[0]])


def json_join_public(data1: list[dict], data2: dict):
    result = copy.deepcopy(data1)
    for item in result:
        key_id = str(item["keyId"])
        if key_id in data2:
            item["privateKey"] = data2[key_id]
    return result


# array1 = [
#     {"keyId": "id1", "value1": "value1a"},
#     {"keyId": "id2", "value1": "value1b"},
# ]
# array2 = {
#     "id1": "value2a",
#     "id2": "value2b",
# }
# print(json_join_public(array1, array2))

class ColorHandler(logging.StreamHandler):
    # https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
    GRAY8 = "38;5;8"
    GRAY7 = "38;5;7"
    ORANGE = "33"
    RED = "31"
    WHITE = "0"

    def emit(self, record):
        # Don't use white for any logging, to help distinguish from user print statements
        level_color_map = {
            logging.DEBUG: self.GRAY8,
            logging.INFO: self.GRAY7,
            logging.WARNING: self.ORANGE,
            logging.ERROR: self.RED,
        }

        csi = f"{chr(27)}["  # control sequence introducer
        color = level_color_map.get(record.levelno, self.WHITE)

        print(f"{csi}{color}m{record.msg}{csi}m")