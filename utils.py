import logging
import subprocess
import sys
import os
import copy

from typing import Type, TypeVar
from dataclasses import dataclass, fields, is_dataclass, asdict
import json
from signal_protocol import kem
from signal_protocol.state import KyberPreKeyRecord
from signal_protocol.curve import KeyPair
from signal_protocol.identity_key import IdentityKeyPair
import signal_protocol.helpers as helpers
from protos.gen.storage_pb2 import SignedPreKeyRecordStructure
import random

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
    # # Convert the dataclass instance to a dictionary
    # instance_dict = asdict(instance)
    # # Serialize the dictionary to a JSON string
    # return json.dumps(instance_dict)
    result = {}
    for field in fields(instance):
        if is_dataclass(field.type):
            # todo: this goes a bit crazy when unwrapping optionals instead of dicts
            # print(field.name)
            result[field.name] = json.loads(dataclass_to_json(getattr(instance, field.name)))
            # result[field.name] = asdict(getattr(instance, field.name))
        else:
            result[field.name] = getattr(instance, field.name)
    return json.dumps(result)

TIME_DURATION_UNITS = (
    ('week', 60 * 60 * 24 * 7),
    ('day', 60 * 60 * 24),
    ('hour', 60 * 60),
    ('min', 60),
    ('sec', 1)
)


def human_time_duration(seconds):
    if seconds == 0:
        return 'inf'
    parts = []
    for unit, div in TIME_DURATION_UNITS:
        amount, seconds = divmod(int(seconds), div)
        if amount > 0:
            parts.append('{} {}{}'.format(amount, unit, "" if amount == 1 else "s"))
    return ', '.join(parts)



def make_kyber_record(key_id: int, ts: int, kp: kem.KeyPair, signature: bytes):
    sss = SignedPreKeyRecordStructure()
    sss.id = key_id
    sss.public_key = kp.get_public().serialize()
    sss.private_key = kp.get_private().serialize()
    sss.signature = signature
    sss.timestamp = ts
    return KyberPreKeyRecord.deserialize(sss.SerializeToString())

def generate_pre_key_json(alice_identity_key_pair: IdentityKeyPair):

    pub_keys, priv_keys = helpers.create_keys_data(100, alice_identity_key_pair,
                                                                  prekey_start_at=random.randint(1,2**16),
                                                                  kyber_prekey_start_at=random.randint(1,2**16))
    keys = json_join_public(pub_keys, priv_keys)
    return keys

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

