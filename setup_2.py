import subprocess
import os
import sys
import signal
from itertools import product
from database import *
from pathlib import Path

import config

from utils import *

class NetworkHandler:
    def __init__():
        pass

    def setup(self):
        allow_forward = [
            "sysctl -w net.ipv4.ip_forward=1",
            "sysctl -w net.ipv6.conf.all.forwarding=1",
            "sysctl -w net.ipv4.conf.all.send_redirects=0",
        ]

        [try_run_sudo(cmd) for cmd in allow_forward]

        try_run_sudo(
            f"create_ap --freq-band 2.4 --daemon {config.INTERNET_IFACE} {config.AP_IFACE} {config.AP_SSID} {config.AP_PASSWORD}"
        )

        [
            try_run_sudo(
                f"{cmd} -t nat -A PREROUTING -i ap0 -p tcp --dport {port} -j REDIRECT --to-port {config.MITMPROXY_LISTEN_PORT}"
            )
            for (cmd, port) in product(["iptables", "ip6tables"], [80, 443])
        ]

    def shutdown(self):
        remove_forward = [
            "sysctl -w net.ipv4.ip_forward=0",
            "sysctl -w net.ipv6.conf.all.forwarding=0",
            "sysctl -w net.ipv4.conf.all.send_redirects=1",
        ]

        [try_run_sudo(cmd) for cmd in remove_forward]

        try_run_sudo(f"create_ap --stop {config.INTERNET_IFACE}")

        try_run_sudo("iptables -t nat -F")
        try_run_sudo("ip6tables -t nat -F")


def setup_db():
    database = SqliteDatabase(config.DB_NAME)
    database.connect()
    create_tables()


def teardown():
    NetworkHandler().shutdown()
    try_run_sudo("pkill mitmproxy")


def signal_handler(sig, frame):
    print("You pressed Ctrl+C!")
    teardown()  # kill this mess
    sys.exit(0)


def setup():
    NetworkHandler().setup()
    setup_db()
    mitm = rf"mitmproxy --mode transparent --showhost --ssl-insecure --ignore-hosts {config.IGNORE_HOSTS}"  # -s intercept.py'
    # mitm = r'mitmproxy --mode wireguard --showhost --ssl-insecure --ignore-hosts ".*google\w*\.com"'# -s intercept.py'
    os.system(f"gnome-terminal -- {mitm} &")


if __name__ == "__main__":
    signal.signal(signal.SIGINT, signal_handler)
    # handler  receives signal number and stack frame
    print("started")
    setup()
    signal.pause()
