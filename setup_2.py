import subprocess
import os
import sys
import signal
from itertools import product
from database import *
from pathlib import Path


def try_run(cmd: str):
    try:
        res = subprocess.run(cmd, shell=True, check=True, stdout=open(os.devnull, "wb"))
        # print(res.returncode)
    except subprocess.CalledProcessError as e:
        print(f"cmd failed: {e}\n{cmd}")

def try_run_sudo(cmd: str):
    try_run(f"sudo {cmd}")

def setup_db():
    database.create_tables([User, Device, LegitBundle, MitMBundle, Session, Messages])


def teardown():
    # Kill me with a smile, bby
    remove_forward = [
        "sysctl -w net.ipv4.ip_forward=0",
        "sysctl -w net.ipv6.conf.all.forwarding=0",
        "sysctl -w net.ipv4.conf.all.send_redirects=1",
    ]

    [try_run_sudo(cmd) for cmd in remove_forward]

    try_run_sudo("create_ap --stop wlp0s20f3")

    try_run_sudo("iptables -t nat -F")
    try_run_sudo("ip6tables -t nat -F")
    try_run_sudo("pkill mitmproxy")



def signal_handler(sig, frame):
    print("You pressed Ctrl+C!")
    teardown()  # kill this mess
    sys.exit(0)

def setup():
    # Set all the crap needed
    allow_forward = [
        "sysctl -w net.ipv4.ip_forward=1",
        "sysctl -w net.ipv6.conf.all.forwarding=1",
        "sysctl -w net.ipv4.conf.all.send_redirects=0",
    ]

    [try_run_sudo(cmd) for cmd in allow_forward]

    try_run_sudo(
        "create_ap --freq-band 2.4 --daemon wlp0s20f3 wlp0s20f0u5u1 DummyHotspot 1234567890"
    )

    [
        try_run_sudo(
            f"{cmd} -t nat -A PREROUTING -i ap0 -p tcp --dport {port} -j REDIRECT --to-port 8080"
        )
        for (cmd, port) in product(["iptables", "ip6tables"], [80, 443])
    ]

    setup_db()
    mitm = r'mitmproxy --mode transparent --showhost --ssl-insecure --ignore-hosts "(.*google\w*\.com)|(.*hcaptcha\.com)|(.*signalcaptchas\.org)"'# -s intercept.py'
    #mitm = r'mitmproxy --mode wireguard --showhost --ssl-insecure --ignore-hosts ".*google\w*\.com"'# -s intercept.py'

    os.system(f"gnome-terminal -- {mitm} &")