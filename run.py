import logging
import signal
import sys
import time

from plumbum import local

from conf import config
from setup.network import network_setup, signal_handler, install_kea, configure_kea
from setup.shell import ColorHandler, get_term


def setup_db():
    # create_tables()
    pass


def setup(verbose_logging=False, script="implementation.py"):
    network_setup(config, verbose_logging)
    logging.info("Network is up.\n")
    setup_db()
    logging.info("DB is up.\n")
    args = " ".join(sys.argv[1:])
    addon = None
    if "-w" not in args:
        flow_name = f"autosaved_{int(time.time())}.flow"
        logging.warning(f"Logging flow automatically to: {flow_name}")
        addon = rf" -w {flow_name}"
    # TODO: fix the automatic flow logging
    # if addon:
    # start_mitm = mitmproxy["--mode", "transparent", "--showhost", "--ssl-insecure", "--ignore-host", IGNORE_HOSTS, args, "-s", script, addon]
    # else:
    # mitmproxy = local["mitmproxy"]
    # start_mitm = mitmproxy["--mode", "transparent", "--showhost", "--ssl-insecure", "--ignore-host", IGNORE_HOSTS, args, "-s", script]
    # terminal = local[get_term()]
    # logging.warning(f"Starting mitmproxy with: {start_mitm}")
    # open_new_mitm_terminal = (terminal["--", start_mitm])
    # execute(open_new_mitm_terminal)
    logging.warning(
        "mitmproxy started in another window. Press (CTRL+C) in this terminal to stop it."
    )
    mitm = rf"mitmproxy --mode transparent --showhost --ssl-insecure --ignore-hosts {config['IGNORE_HOSTS']} {args}  -s {script}"
    import os

    os.system(f"{get_term()} -- {mitm} &")


if __name__ == "__main__":
    logger = logging.getLogger()
    logger.setLevel(logging.DEBUG)
    logging.getLogger("plumbum.local").setLevel(logging.WARNING)
    sh = logging.StreamHandler()
    formatter = logging.Formatter("[%(name)s] %(levelname)s %(module)s:\n\t%(message)s")
    sh.setFormatter(formatter)
    logger.addHandler(ColorHandler(sh))
    signal.signal(signal.SIGINT, signal_handler)
    verbose = True

    # configure_kea(config, verbose)
    install_kea(verbose)
    configure_kea(config, verbose)
    # # handler  receives signal number and stack frame
    # logging.debug("Running setup...")
    # # TODO: propagate logging from cli arg or configs
    # setup(True, "tcp-simple.py")
    # signal.pause()
