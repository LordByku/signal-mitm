import sys
from itertools import product

from .shell import execute
from plumbum import local

sysctl = local["sysctl"]
iptables = local["iptables"]
ip6tables = local["ip6tables"]

def create_kea_dhcp_config(const, conf, verbose=False):
    """
        Creates the kea-dhcp config file with the entries configured in the constants
        and config file and copies it to '/etc/kea'.
        Assumes cwd = root (./conf/kea-dhcp4.conf, exists)
    :param const:
    :param conf:
    :param verbose:
    :return:
    """
    sed = local['sed']
    cp = local['cp']
    mv = local['mv']
    execute(cp['./conf/kea-dhcp4.conf', "."])
    execute(sed["-i" ,f"s/{const["dhcp_interface_placeholder"]}/{conf["ap_iface"]}", "kea-dhcp4.conf"])
    execute(sed["-i" ,f"s/{const["dhcp_subnet_placeholder"]}/{const["ap_subnet"]}", "kea-dhcp4.conf"])
    execute(sed["-i", f"s/{const["dhcp_pool_placeholder"]}/{const["dhcp_pool_format_string"].format(const["dhcp_pool_lower"], const["dhcp_pool_upper"])}", "kea-dhcp4.conf"])
    execute(sed["-i" ,f"s/{const["dhcp_server_ip_placeholder"]}/{const["dhcp_server_ip"]}", "kea-dhcp4.conf"])
    execute(mv["kea-dhcp4.conf", "/etc/kea/."], sudo=True)

def network_setup(const, verbose=False):
    allow_forward = [
        sysctl["-w", "net.ipv4.ip_forward=1"],
        sysctl["-w", "net.ipv6.conf.all.forwarding=1"],
        sysctl["-w", "net.ipv4.conf.all.send_redirects=0"],
    ]
    [execute(cmd, retcodes=None, sudo=True, log=verbose) for cmd in allow_forward]
    [
        execute(
            cmd[
                "-t",
                "nat",
                "-A",
                "PREROUTING",
                "-i",
                "ap0",
                "-p",
                "tcp",
                "--dport",
                port,
                "-j",
                "REDIRECT",
                "--to-port",
                const["mitmproxy_listen_port"],
            ],
            retcodes=None,
            sudo=True,
            log=verbose,
        )
        for (cmd, port) in product([iptables, ip6tables], [80, 443])
    ]


def shutdown(verbose_logging):
    remove_forward = [
        sysctl["-w", "net.ipv4.ip_forward=0"],
        sysctl["-w", "net.ipv6.conf.all.forwarding=0"],
        sysctl["-w", "net.ipv4.conf.all.send_redirects=1"],
    ]
    [
        execute(cmd, retcodes=None, sudo=True, log=verbose_logging)
        for cmd in remove_forward
    ]
    [
        execute(cmd["-t", "nat", "-F"], retcodes=None, sudo=True, log=verbose_logging)
        for cmd in (iptables, ip6tables)
    ]


def teardown(verbose_logging):
    shutdown(verbose_logging)
    pkill = local["pkill"]
    execute(pkill["mitmproxy"], retcodes=(0, 1), sudo=True, log=verbose_logging)


def signal_handler(sig, frame):
    print("You pressed Ctrl+C!")
    # TODO: propagate verbose logging from cli arg, or configs
    teardown(True)  # kill this mess
    sys.exit(0)
