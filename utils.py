import subprocess
import sys
import os


def try_run(cmd: str):
    try:
        res = subprocess.run(cmd, shell=True, check=True, stdout=open(os.devnull, "wb"))
        print(res.returncode)
    except subprocess.CalledProcessError as e:
        print(f"cmd failed: {e}\n{cmd}")


def try_run_sudo(cmd: str):
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
        padded_message_length = PushTransportDetails.get_padded_message_length(len(message_body) + 1) - 1
        padded_message = bytearray(padded_message_length)
        padded_message[:len(message_body)] = message_body
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
