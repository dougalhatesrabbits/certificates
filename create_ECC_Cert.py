import time
import os
from subprocess import Popen, PIPE, CalledProcessError
from helper import run, logger

from configparser import ConfigParser
cfg = ConfigParser()
cfg.read('config.ini')


def list_curves():
    logger.debug("*** list_curves ***")
    # Define command as string and then split() into list format
    command = 'openssl ecparam \
               -list_curves'.split()
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** list_curves *** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def list_files(cwd):
    logger.debug("*** list_files ***")
    path = os.path.join(cwd)
    files = (os.listdir(path))
    for root, dirs, files in os.walk(path):
        for file in files:
            if not file.startswith('.'):
                print(root, file)


def generate_ecc_key(key):
    logger.debug("*** generate_ecc_private_key ***")

    command = cfg.get('commands', 'cmdPrivKeyECC').split()
    command.pop(3)
    command.insert(3, key)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** generate_ecc_private_key *** return code: %s", rc)
        time.sleep(1)
        verify_ecc_key(key)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def verify_ecc_key(key):
    logger.debug("*** verify_ecc_private_key ***")

    command = cfg.get('commands', 'cmdVerifyPrivKeyECC').split()
    command.pop(3)
    command.insert(3, key)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_ecc_private_key *** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


# CA cert
# X509 Cert
def generate_ecc_cert(ssl, key, cert):
    logger.debug("*** generate_ca_cert ***")

    command = cfg.get('commands', 'cmdX509CACert').split()
    command.pop(7)
    command.insert(7, ssl)
    command.pop(11)
    command.insert(11, key)
    command.pop(13)
    command.insert(13, cert)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** generate_ca_cert *** return code: %s", rc)
        time.sleep(1)
        verify_cert(cert, key)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def verify_cert(cert, key):
    logger.debug("*** verify_ca_cert 1/3***")

    command = cfg.get('commands', 'cmdVerifySelfCert').split()
    command.pop(5)
    command.insert(5, cert)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_ca_cert 1/3*** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)

    logger.debug("*** verify_ca_cert 2/3***")

    command = cfg.get('commands', 'cmdVerifySelfCert2').split()
    command.pop(5)
    command.insert(5, cert)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_ca_cert 2/3*** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)

    logger.debug("*** verify_ca_cert 3/3***")

    command = cfg.get('commands', 'cmdVerifySelfCert3').split()
    command.pop(4)
    command.insert(4, key)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_ca_cert 3/3*** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)






















