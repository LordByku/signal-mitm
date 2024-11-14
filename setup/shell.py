import inspect
import logging
import shutil
import sys
import os
from collections import namedtuple
from typing import Optional
from plumbum.cmd import sudo

run_command_counter = 0
from plumbum.commands.base import ConcreteCommand

ExecResult = namedtuple("ExecResult", ["retcode", "stdout", "stderr"])


def execute(
    cmd: ConcreteCommand,
    retcodes: Optional[tuple[int, ...]] = None,
    as_sudo=False,
    log=False,
) -> str | ExecResult:
    """
    Executes and logs a plumbum command.
    See: https://plumbum.readthedocs.io/en/latest/local_commands.html
    If anything is passed for expected retcodes, returns:
         retcode, stdout, stderr
    else returns:
         None, stdout, None
    :param cmd: the plumbum command to execute, can be either a LocalCommand (via local['cmd']) or RemoteCommand (rem['cmd'])
    :param retcodes: None or a tuple of accepted return codes
    :param as_sudo: Execute as superuser (might request a prompt if the process does not have `euid=0`)
    :param log: turn logging of the command on or off
    :return: ExecResult - retcode, stdout, stderr (if retcode is not None) OR (None, stdout, None)
    """
    global run_command_counter

    def log_command() -> None:
        if log:

            def formatstring_stdout(stdout_arg):
                # Empty strings are 'falsy'
                return f"\nOutput:\n {stdout_arg}" if stdout_arg.strip() else ""

            # inspect.stack()[1][3] is the name of the calling function
            # https://docs.python.org/3/library/inspect.html#the-interpreter-stack
            logging.info(
                f"function:{inspect.currentframe().f_back.f_back.f_code.co_name}, line {inspect.currentframe().f_back.f_back.f_lineno} \n{cmd} {formatstring_stdout(stdout)}"
            )

    logging.debug(f"Command nr: {run_command_counter} \n{cmd}\nRetcodes: {retcodes}")
    run_command_counter = run_command_counter + 1
    if as_sudo:
        (rc, stdout, stderr) = sudo[cmd].run(retcode=retcodes)
    else:
        (rc, stdout, stderr) = cmd.run(retcode=retcodes)
    if retcodes is None and rc != 0:
        log_command()
        logging.critical(
            f"UNEXPECTED ERROR:\nrc: {rc}\nstdout: {stdout}\nstderr: {stderr}\n"
        )
        exit(1)
    log_command()
    if retcodes is None:
        return ExecResult(None, stdout, None)
    else:
        return ExecResult(rc, stdout, stderr)


def get_term() -> str:
    """get the preferred terminal to enhance portability

    todo: actually find a way to do this.
    There is `settings` but that only works on gnome and $TERM is a bit
    useless since everyone pretends to be `xterm-256color`
    """

    terminals = [
        "gnome-terminal",
        "konsole",
        "xfce4-terminal",
        "xterm",
        "terminator",
        "lxterminal",
    ]
    for terminal in terminals:
        if shutil.which(terminal):
            return terminal
    return "gnome-terminal"


def signal_handler(_sig, _frame):
    print("You pressed Ctrl+C!")
    sys.exit(0)


def open_terminal(command: str):
    os.system(f"gnome-terminal -- {command} &")


def check_or_request_sudo() -> None:
    euid = os.geteuid()
    if euid != 0:
        print("Script not running as root. Requesting sudo..")
        args = ["sudo", sys.executable] + sys.argv + [os.environ]
        # the next line replaces the currently-running process with the sudo
        os.execlpe("sudo", *args)


class ColorHandler(logging.StreamHandler):
    # https://en.wikipedia.org/wiki/ANSI_escape_code#Colors
    GRAY8 = "38;5;8"
    GRAY7 = "38;5;7"
    ORANGE = "33"
    RED = "31"
    WHITE = "0"

    def __init__(self, stream: logging.StreamHandler):
        super().__init__()
        self.formatter = stream.formatter

    def emit(self, record):
        # Don't use white for any logging, to help distinguish from user print statements
        level_color_map = {
            logging.DEBUG: self.GRAY8,
            logging.INFO: self.GRAY7,
            logging.WARNING: self.ORANGE,
            logging.ERROR: self.RED,
        }

        csi = f"{chr(27)}["  # control sequence introducer
        color = level_color_map.get(record.levelno, self.WHITE)
        message = self.formatter.format(record)

        print(f"{csi}{color}m{message}{csi}m")
