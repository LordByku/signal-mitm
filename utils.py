import logging
import subprocess
import sys
import os


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
