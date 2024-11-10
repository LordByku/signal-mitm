import sys
from itertools import product

from shell import execute
from plumbum import local
from ..conf.configuration import const

sysctl = local['sysctl']
iptables = local["iptables"]
ip6tables = local["ip6tables"]


def network_setup(verbose=False):
    allow_forward = [
        sysctl["-w", "net.ipv4.ip_forward=1"],
        sysctl["-w", "net.ipv6.conf.all.forwarding=1"],
        sysctl["-w", "net.ipv4.conf.all.send_redirects=0"]
    ]
    [execute(cmd, retcodes=None, sudo=True, log=verbose) for cmd in allow_forward]
    [
        execute(
            cmd["-t", "nat", "-A", "PREROUTING", "-i", "ap0", "-p", "tcp", "--dport", port, "-j",
                "REDIRECT", "--to-port", const["mitmproxy_listen_port"]],
            retcodes=None,
            sudo=True,
            log=verbose
        )
        for (cmd, port) in product([iptables, ip6tables], [80, 443])
    ]


def shutdown(verbose_logging):
    remove_forward = [
        sysctl["-w", "net.ipv4.ip_forward=0"],
        sysctl["-w", "net.ipv6.conf.all.forwarding=0"],
        sysctl["-w", "net.ipv4.conf.all.send_redirects=1"]
    ]
    [execute(cmd, retcodes=None, sudo=True, log=verbose_logging) for cmd in remove_forward]
    [execute(cmd["-t", "nat", "-F"], retcodes=None, sudo=True, log=verbose_logging) for cmd in (iptables, ip6tables)]


def teardown(verbose_logging):
    shutdown(verbose_logging)
    pkill = local["pkill"]
    execute(pkill["mitmproxy"], retcodes=(0 , 1), sudo=True, log=verbose_logging)


def signal_handler(sig, frame):
    print("You pressed Ctrl+C!")
    # TODO: propagate verbose logging from cli arg, or configs
    teardown(True)  # kill this mess
    sys.exit(0)
