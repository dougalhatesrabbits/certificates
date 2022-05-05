import time
import os
from subprocess import Popen, PIPE, CalledProcessError
from helper import run, logger

from configparser import ConfigParser
cfg = ConfigParser()
cfg.read('config.ini')


def create_ca_key(pwd, key):
    logger.debug("*** create_ca_key ***")

    command = cfg.get('root', 'cmd_CAPrivKeyRSA').split()
    arg = "file:" + pwd
    command.pop(4)
    command.insert(4, arg)
    command.pop(6)
    command.insert(6, key)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** create_ca_key *** return code: %s", rc)
        time.sleep(0.1)
        verify_ca_key(key, pwd)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def verify_ca_key(key, pwd):
    logger.debug("*** verify_ca_key ***")
    command = cfg.get('root', 'cmd_CAVerifyPrivKeyRSA').split()
    command.pop(5)
    command.insert(5, key)
    arg = "file:" + pwd
    command.pop(7)
    command.insert(7, arg)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_ca_key *** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def create_ca_cert(key, cert, pwd, ssl):
    logger.debug("*** create_ca_cert ***")

    command = cfg.get('root', 'cmd_X509RootCACert').split()
    command.pop(7)
    command.insert(7, key)
    command.pop(9)
    command.insert(9, cert)
    arg = "file:" + pwd
    command.pop(11)
    command.insert(11, arg)
    command.pop(13)
    command.insert(13, ssl)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** create_ca_cert *** return code: %s", rc)
        time.sleep(0.1)
        verify_ca_cert(cert)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def verify_ca_cert(cert):
    logger.debug("*** verify_self_signed_cert ***")

    command = cfg.get('root', 'cmd_VerifyCACert').split()
    command.pop(5)
    command.insert(5, cert)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_self_signed_cert *** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def sign_server_cert(csr, cacert, cakey, cert, pwd):
    logger.debug("*** sign_server_cert ***")

    command = cfg.get('root', 'cmd_X509SignCert').split()
    command.pop(6)
    command.insert(6, csr)
    command.pop(8)
    command.insert(8, cacert)
    command.pop(10)
    command.insert(10, cakey)
    command.pop(13)
    command.insert(13, cert)
    arg = "file:" + pwd
    command.pop(15)
    command.insert(15, arg)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        sp = Popen(command, stdin=PIPE, stdout=PIPE, stderr=PIPE, text=True)
        sp.communicate(os.linesep.join(["y", "y"]))
        rc = sp.wait()
        output, error = sp.communicate()

        if output:
            logger.debug(output)
        if error:
            logger.error(error)

        logger.debug("*** sign_server_cert *** return code: %s", rc)
        time.sleep(0.1)
        verify_server_cert(cert)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def verify_server_cert(cert):
    logger.debug("*** verify_server_cert***")

    command = cfg.get('self', 'cmd_VerifySelfCert').split()
    command.pop(5)
    command.insert(5, cert)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_server_cert return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)
