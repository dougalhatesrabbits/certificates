import time
import os
from subprocess import Popen, PIPE, CalledProcessError
from helper import run, logger, verify_rootca_database, verify_crl_serial

from configparser import ConfigParser
cfg = ConfigParser()
cfg.read('config.ini')


def revoke_cert(ssl, cert):
    logger.debug("*** revoke_cert ***")
    command = cfg.get('root', 'cmdRevokeCert').split()
    command.pop(3)
    command.insert(3, ssl)
    command.pop(5)
    command.insert(5, cert)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** revoke_cert *** return code: %s", rc)
        time.sleep(1)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)

    verify_rootca_database(cfg.get('installation', 'indexFile'))


def create_revocation_list(ssl, crl):
    logger.debug("*** generate_revocation_list ***")
    command = cfg.get('root', 'cmd_generateCRL').split()
    command.pop(3)
    command.insert(3, ssl)
    command.pop(6)
    command.insert(6, crl)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** generate_revocation_list *** return code: %s", rc)
        time.sleep(1)
        verify_crl(crl)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def verify_crl(crl):
    logger.debug("*** verify_crl ***")
    command = cfg.get('root', 'cmd_verifyCRL').split()
    command.pop(3)
    command.insert(3, crl)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_crl *** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)

    verify_crl_serial(crl)

