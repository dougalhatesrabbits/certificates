import time
from helper import run, logger
from subprocess import CalledProcessError
import subprocess

from configparser import ConfigParser
cfg = ConfigParser()
cfg.read('config.ini')


def generate_rsa_key(key, pwd):
    logger.debug("*** generate_private_key ***")
    command = cfg.get('commands', 'cmdPrivKeyRSA').split()
    arg = "file:" + pwd
    command.pop(3)
    command.insert(3, key)
    command.pop(5)
    command.insert(5, arg)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** generate_private_key *** return code: %s", rc)
        time.sleep(1)
        verify_rsa_key(key, pwd)
    except OSError as error:
        logger.error("OSError %s", error)
    except CalledProcessError as error:
        logger.error("CalledProcessError %s", error)


def verify_rsa_key(key, pwd):
    logger.debug("*** verify_private_key ***")
    command = cfg.get('commands', 'cmdVerifyPrivKeyRSA').split()
    command.pop(5)
    command.insert(5, key)
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


def generate_csr(key, csr, cnf, pwd):
    logger.debug("*** generate_csr ***")
    command = cfg.get('commands', 'cmdCSR').split()

    command.pop(4)
    command.insert(4, key)
    command.pop(6)
    command.insert(6, csr)
    command.pop(8)
    command.insert(8, cnf)
    arg = "file:" + pwd
    command.pop(10)
    command.insert(10, arg)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** generate_csr *** return code: %s", rc)
        time.sleep(1)
        verify_csr(csr)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def verify_csr(csr):
    logger.debug("*** verify_csr ***")

    command = cfg.get('commands', 'cmdVerifyCSR').split()
    command.pop(5)
    command.insert(5, csr)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_csr *** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def generate_x509_cert(csr, key, crt, pwd):
    logger.debug("*** generate_x509_cert ***")

    command = cfg.get('commands', 'cmdX509SelfCert').split()
    command.pop(6)
    command.insert(6, csr)
    command.pop(8)
    command.insert(8, key)
    command.pop(10)
    command.insert(10, crt)
    arg = "file:" + pwd
    command.pop(12)
    command.insert(12, arg)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_private_key *** return code: %s", rc)
        time.sleep(1)
        verify_self_signed_cert(crt)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def verify_self_signed_cert(crt):
    logger.debug("*** verify_self_signed_cert ***")

    command = cfg.get('commands', 'cmdVerifySelfCert').split()
    command.pop(5)
    command.insert(5, crt)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_self_signed_cert *** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)













