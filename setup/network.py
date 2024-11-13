import sys
import logging
from itertools import product

from conf.configuration import config
from .shell import execute
from plumbum import local

sysctl = local["sysctl"]
iptables = local["iptables"]
ip6tables = local["ip6tables"]


def install_kea(verbose=False):
    """
    Installs kea if not found by 'apt' (assumes apt)
    :return:
    """
    apt = local["apt"]
    apt_get = local["apt-get"]
    # do an update to fetch packages if necessary
    execute(apt_get["update"], sudo=True, log=verbose)
    logging.info("Checking if kea is installed...")
    stdout = execute(apt["list", "kea"], log=verbose, retcodes=(0,1))
    if 'installed' not in stdout:
        logging.info("Installing kea...")
        execute(apt['-y', 'install', 'kea', 'kea-doc'], sudo=True, log=verbose)
    else:
        logging.info("Kea installed, skipping.")


def configure_kea(const, conf, verbose=False):
    """
        Creates the kea-dhcp config file with the entries configured in the constants
        and config file and copies it to '/etc/kea', binds the server addr to the ap interface.
        Assumes cwd = root (./conf/kea-dhcp4.conf, exists)
    :param const:
    :param conf:
    :param verbose:
    :return:
    """
    sed = local['sed']
    cp = local['cp']
    mv = local['mv']
    ip = local['ip']
    systemctl = local['systemctl']

    #Create kea config
    logging.info("Creating kea-dhcp4-server configuration...")
    execute(cp['./conf/kea-dhcp4.conf', "."])
    execute(sed["-i" ,f"s/{const["dhcp_interface_placeholder"]}/{conf["ap_iface"]}", "kea-dhcp4.conf"])
    execute(sed["-i" ,f"s/{const["dhcp_subnet_placeholder"]}/{const["ap_subnet"]}", "kea-dhcp4.conf"])
    execute(sed["-i", f"s/{const["dhcp_pool_placeholder"]}/{const["dhcp_pool_format_string"].format(const["dhcp_pool_lower"], const["dhcp_pool_upper"])}", "kea-dhcp4.conf"])
    execute(sed["-i" ,f"s/{const["dhcp_server_ip_placeholder"]}/{const["dhcp_server_ip"]}", "kea-dhcp4.conf"])
    execute(mv["kea-dhcp4.conf", "/etc/kea/."], sudo=True)

    #Set up the router ip on the ap interface
    execute(ip["addr", "add", f"{const["dhcp_server_ip"]}/{const["ap_subnet"].split("/")[-1]}", "dev", config["ap_iface"]], sudo=True, log=verbose)

    #reload kea-server
    execute(systemctl["reload", "kea-dhcp4-server"], sudo=True, log=verbose)


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
