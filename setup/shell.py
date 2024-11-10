import inspect
import logging
import shutil

run_command_counter = 0

def execute(cmd, retcodes: tuple[int, ...] = None, log=True):
    """
    Executes and logs a plumbum command.
    See: https://plumbum.readthedocs.io/en/latest/local_commands.html
    If anything is passed for expected retcodes, returns:
        retcode, stdout, stderr
    else returns:
        stdout
    :param cmd: the plumbum command to execute
    :param retcodes: None or a tuple of accepted return codes
    :param log: turn logging of the command on or off
    :return: retcode, stdout, stderr (if retcode is not None) OR stdout
    """
    global run_command_counter
    def log_command():
        if log:
            def formatstring_stdout(stdout_arg):
                # Empty strings are 'falsy'
                return f"\nOutput:\n {stdout_arg}" if stdout_arg.strip() else ""
            # inspect.stack()[1][3] is the name of the calling function
            # https://docs.python.org/3/library/inspect.html#the-interpreter-stack
            logging.info(f"function:{inspect.currentframe().f_back.f_back.f_code.co_name} \nline: {inspect.currentframe().f_back.f_back.f_lineno} \n{cmd} {formatstring_stdout(stdout)}")

    logging.debug(f"Command nr: {run_command_counter} \n{cmd}\nRetcodes: {retcodes}")
    run_command_counter = run_command_counter + 1
    (rc, stdout, stderr) = cmd.run(retcode=retcodes)
    if retcodes is None and rc != 0:
        log_command()
        logging.critical(f"UNEXPECTED ERROR:\nrc: {rc}\nstdout: {stdout}\nstderr: {stderr}\n")
        exit(1)
    log_command()
    if retcodes is None:
        return stdout
    else:
        return rc, stdout, stderr


def get_term():
    """get the preferred terminal to enhance portability

    todo: actually find a way to do this. there is gsettings but that only works on gnome and $TERM is a bit
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