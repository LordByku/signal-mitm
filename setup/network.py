import string
import sys
import logging
from itertools import product
from pathlib import Path

from conf import Config
from setup.shell import execute
from setup.pm import get_package_manager
from plumbum import local

sysctl = local["sysctl"]
iptables = local["iptables"]
ip6tables = local["ip6tables"]


def install_kea(verbose=False):
    """
    Installs kea if not found by 'apt' (assumes apt)
    :return:
    """
    pm = get_package_manager()
    if not pm.is_installed("kea"):
        pm.update()
        pm.install_kea()
    else:
        print("kea is already installed, skipping reinstall...")


def configure_kea(conf: Config, verbose=False):
    """
        Creates the kea-dhcp config file with the entries configured in the constants
        and config file and copies it to '/etc/kea', binds the server addr to the ap interface.
        Assumes cwd = root (./conf/kea-dhcp4.conf.tpl, exists)
    :param conf:
    :param verbose:
    :return:
    """
    mv = local["mv"]
    ip = local["ip"]
    systemctl = local["systemctl"]

    # Create kea config
    logging.info("Creating kea-dhcp4-server configuration...")

    conf_dir = Path(__file__).resolve().parent.parent / "conf"
    print(conf_dir)
    kea_template = conf_dir / "kea-dhcp4.conf.tpl"
    kea_conf = conf_dir / "kea-dhcp4.conf"

    with kea_template.open("r") as file:
        config_data = file.read()

    config_template = string.Template(config_data)
    substitutions = {
        "ap_interface": conf.ap.iface,
        "ap4_subnet": conf.dhcp.subnet,
        "dhcp_pool_range": f"{conf.dhcp.pool_lower} - {conf.dhcp.pool_upper}",
        # "dhcp_pool_range": conf["dhcp"].get(
        #     "pool_range", f"{conf['dhcp']['pool_lower']} - {conf['dhcp']['pool_upper']}"
        # ),  ## todo: COMPUTE THIS in config
        "dhcp_server_ip": conf.dhcp.server_ip,
    }

    config_data = config_template.safe_substitute(substitutions)

    remaining_tokens = list(config_template.pattern.finditer(config_data))
    for match in remaining_tokens:
        token = match.group(0)
        if token in config_data:
            raise AttributeError(f"Config missing value for {token}")

    with kea_conf.open("w") as file:
        file.write(config_data)
        print("wrote data")

    execute(mv[str(kea_conf), "/etc/kea/."], as_sudo=True)

    # # Set up the router ip on the ap interface
    execute(
        ip[
            "addr",
            "add",
            # f"{conf['dhcp']['server_ip']}/{conf['ap']['subnet'].split("/")[-1]}",
            f"{conf.dhcp.server_ip}/{str(conf.dhcp.subnet).split("/")[-1]}",
            "dev",
            conf.ap.iface,
        ],
        as_sudo=True,
        log=verbose,
        retcodes=(0, 2),
    )
    #

    # (local["sudo"]["tee"][conf["kea"]["pw_filepath"]] << conf["kea"]["api_pw"]).run()
    (local["sudo"]["tee"][conf.kea.pw_filepath] << conf.kea.api_pw).run()
    # Set the ownership
    # local['sudo']['chown', 'root:_kea', '/etc/kea/kea-api-password'].run()
    # Set the permissions
    local["sudo"]["chmod", "0640", conf.kea.pw_filepath].run()

    # reload kea-server
    execute(systemctl["enable", conf.kea.systemd_service], as_sudo=True, log=verbose)
    execute(
        systemctl["restart", conf.kea.systemd_service], as_sudo=True, log=verbose
    )


def network_setup(const, verbose=False):
    allow_forward = [
        sysctl["-w", "net.ipv4.ip_forward=1"],
        sysctl["-w", "net.ipv6.conf.all.forwarding=1"],
        sysctl["-w", "net.ipv4.conf.all.send_redirects=0"],
    ]
    [execute(cmd, retcodes=None, as_sudo=True, log=verbose) for cmd in allow_forward]
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
            as_sudo=True,
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
        execute(cmd, retcodes=None, as_sudo=True, log=verbose_logging)
        for cmd in remove_forward
    ]
    [
        execute(
            cmd["-t", "nat", "-F"], retcodes=None, as_sudo=True, log=verbose_logging
        )
        for cmd in (iptables, ip6tables)
    ]


def teardown(verbose_logging):
    shutdown(verbose_logging)
    pkill = local["pkill"]
    execute(pkill["mitmproxy"], retcodes=(0, 1), as_sudo=True, log=verbose_logging)


def signal_handler(_sig, _frame):
    print("You pressed Ctrl+C!")
    # TODO: propagate verbose logging from cli arg, or configs
    teardown(True)  # kill this mess
    sys.exit(0)
