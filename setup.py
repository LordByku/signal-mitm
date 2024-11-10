import logging
import sys
import time
import signal
from itertools import product

from setup.network import network_setup, signal_handler
from setup.shell import execute, get_term, ColorHandler
from db.database import create_tables

import config


class NetworkHandler:
    def __init__(self):
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
    create_tables()


def setup():
    network_setup()
    logging.info("Network is up.\n")
    setup_db()
    logging.info("DB is up.\n")
    args = ' '.join(sys.argv[1:])
    mitm = rf"mitmproxy --mode transparent --showhost --ssl-insecure --ignore-hosts {config.IGNORE_HOSTS} {args}  -s implementation.py"  # -s implementation.py"
    if "-w" not in args:
        flow_name = f"autosaved_{int(time.time())}.flow"
        logging.warning(f"Logging flow automatically to: {flow_name}")
        mitm += rf" -w {flow_name}"
    logging.warning(f"Starting mitmproxy as: {mitm}")
    logging.warning("mitmproxy started in another window. Press (CTRL+C) in this terminal to stop it.")


if __name__ == "__main__":
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logger.addHandler(ColorHandler())

    signal.signal(signal.SIGINT, signal_handler)
    # handler  receives signal number and stack frame
    logging.debug("Running setup...")
    setup()
    signal.pause()
