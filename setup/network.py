import sys
from shell import execute

def network_setup():
    # TODO: implement
    pass

def shutdown():
    # TODO: implement
    pass


def teardown():
    shutdown()
    execute(["sudo", "pkill mitmproxy"])


def signal_handler(sig, frame):
    print("You pressed Ctrl+C!")
    teardown()  # kill this mess
    sys.exit(0)
