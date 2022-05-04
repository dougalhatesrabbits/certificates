import time
from helper import run, logger
from subprocess import CalledProcessError
import subprocess

from configparser import ConfigParser
cfg = ConfigParser()
cfg.read('config.ini')


def generate_key(key, cmd, pwd=None):
    logger.debug("*** generate_private_key ***")
    command = cmd.split()
    command.pop(3)
    command.insert(3, key)
    print(pwd)
    if pwd:
        arg = "file:" + pwd
        command.pop(5)
        command.insert(5, arg)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** generate_private_key *** return code: %s", rc)
        time.sleep(1)
        verify_key(key, pwd)
    except OSError as error:
        logger.error("OSError %s", error)
    except CalledProcessError as error:
        logger.error("CalledProcessError %s", error)


def verify_key(key, pwd=None):
    logger.debug("*** verify_private_key ***")
    command = cfg.get('commands', 'cmdVerifyPrivKeyRSA').split()
    command.pop(5)
    command.insert(5, key)
    if pwd:
        arg = "file:" + pwd
        command.pop(7)
        command.insert(7, arg)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_private_key *** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)