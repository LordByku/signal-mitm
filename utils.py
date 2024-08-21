import base64
import hashlib
import hmac
import logging
import logging
import subprocess
import sys
import os
from dataclasses import dataclass, fields, is_dataclass, asdict
from schemas import *
import json
from typing import TypeVar, Type, Any


### TODO: probably remove later
def b64encbytes(msg):
    # base64 encoding helper function
    return base64.encodebytes(msg).decode("utf-8").strip()


def b64enc(msg: bytes) -> str:
    return base64.b64encode(msg).decode("ascii")


def hmac_sha256(key: bytes, msg: bytes):
    result = hmac.new(key, msg, digestmod=hashlib.sha256).hexdigest()
    return result


####


def try_run(cmd: str):
    try:
        res = subprocess.run(cmd, shell=True, check=True, stdout=open(os.devnull, "wb"))
        logging.debug(f"exit code: {res.returncode}")
    except subprocess.CalledProcessError as e:
        print(f"cmd failed: {e}\n{cmd}")


def try_run_sudo(cmd: str):
    logging.debug(f"trying to run command with sudo: {cmd}")
    try_run(f"sudo {cmd}")


def signal_handler(_sig, _frame):
    print("You pressed Ctrl+C!")
    sys.exit(0)


class PushTransportDetails:
    @staticmethod
    def get_stripped_padding_message_body(message_with_padding):
        padding_start = 0
        for i in range(len(message_with_padding) - 1, -1, -1):
            if message_with_padding[i] == 0x80:
                padding_start = i
                break
            elif message_with_padding[i] != 0x00:
                print("Padding byte is malformed, returning unstripped padding.")
                return message_with_padding
        stripped_message = message_with_padding[:padding_start]
        return stripped_message

    @staticmethod
    def get_padded_message_body(message_body):
        """To quote the original devs:

        NOTE: This is dumb.  We have our own padding scheme, but so does the cipher.
        The +1 -1 here is to make sure the Cipher has room to add one padding byte,
        otherwise it'll add a full 16 extra bytes.
        """
        padded_message_length = (
                PushTransportDetails.get_padded_message_length(len(message_body) + 1) - 1
        )
        padded_message = bytearray(padded_message_length)
        padded_message[: len(message_body)] = message_body
        padded_message[len(message_body)] = 0x80
        return bytes(padded_message)

    @staticmethod
    def get_padded_message_length(message_length):
        message_length_with_terminator = message_length + 1
        message_part_count = message_length_with_terminator // 160

        if message_length_with_terminator % 160 != 0:
            message_part_count += 1

        return message_part_count * 160


def open_terminal(command: str):
    os.system(f"gnome-terminal -- {command} &")


def strip_uuid_and_id(path: str) -> tuple[str, str]:
    path = path.lower()
    words = path.split(":")

    if len(words) > 1:
        return words[0], words[1]
    else:
        return "aci", words[0]


def json_join_public(data1: list[dict], data2: dict):
    for item in data1:
        keyId = str(item["keyId"])
        if keyId in data2:
            item["privateKey"] = data2[keyId]
    return data1


# array1 = [
#     {"keyId": "id1", "value1": "value1a"},
#     {"keyId": "id2", "value1": "value1b"},
# ]
# array2 = {
#     "id1": "value2a",
#     "id2": "value2b",
# }
# print(json_join_public(array1, array2))


T = TypeVar("T")


def json_to_dataclass(dc_cls: Type[T], json_str) -> T:
    """
    Convert a JSON string to an instance of a specified dataclass.

    :param dc_cls: The dataclass type to instantiate.
    :param json_str: The JSON string to parse.
    :return: An instance of dc_cls populated with data from json_str.
    """
    # Ensure dc_cls is indeed a dataclass
    if not is_dataclass(dc_cls):
        raise ValueError(f"{dc_cls} must be a dataclass")

    parsed_json = json.loads(json_str)

    # Prepare constructor arguments, respecting default values if not present in JSON
    ctor_args = {}
    for field in fields(dc_cls):
        if field.name in parsed_json:
            field_value = parsed_json[field.name]
            # If the field type is also a dataclass, recursively parse it
            if is_dataclass(field.type):
                ctor_args[field.name] = json_to_dataclass(
                    field.type, json.dumps(field_value)
                )
            else:
                ctor_args[field.name] = field_value
        elif hasattr(field, "default"):
            ctor_args[field.name] = field.default
        elif hasattr(field, "default_factory"):
            ctor_args[field.name] = field.default_factory()

    return dc_cls(**ctor_args)


def dataclass_to_json(instance: T) -> str:
    # Convert the dataclass instance to a dictionary
    instance_dict = asdict(instance)
    # Serialize the dictionary to a JSON string
    return json.dumps(instance_dict)


def update_dataclass(instance, updates: dict):
    """
    Update the attributes of a dataclass instance based on a dictionary *in-place*.

    :param instance: The dataclass instance to update.
    :param updates: A dictionary containing the updates.
    """
    for key, value in updates.items():
        if hasattr(instance, key):
            setattr(instance, key, value)

# # Use case
# @dataclass
# class ThirdPartyClass:
#     name: str
#     age: int
#     is_active: bool = False  # with a default value
#
#
# json_string = '{"name": "John Doe", "age": 30}'
# instance = json_to_dataclass(ThirdPartyClass, json_string)
# print(instance)
# # json_string = dataclass_to_json(instance)
# print(json_string)

# from playhouse.sqlite_ext import SqliteExtDatabase
# database = SqliteExtDatabase(config.DB_NAME)
# database.connect()
# from database import LegitBundle, MitMBundle
# # print()
#
# record = MitMBundle.select().where(MitMBundle.fakeLastResortKyber['keyId'] == 42069)
# for r in record:
#     print(r.fakeLastResortKyber['publicKey'])

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