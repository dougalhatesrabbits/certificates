import time
import os
from subprocess import Popen, PIPE, CalledProcessError
from helper import run, logger, verify_rootca_database, verify_crl_serial

from configparser import ConfigParser
cfg = ConfigParser()
cfg.read('config.ini')


def renew_rootca(cert, key, csr, new):
    logger.debug("*** renew_rootca ***")
    command = cfg.get('root', 'cmd_renewCACert1-2').split()
    command.pop(4)
    command.insert(4, cert)
    command.pop(6)
    command.insert(6, key)
    command.pop(8)
    command.insert(8, csr)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** renew_rootca *** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)

    command = cfg.get('root', 'cmd_renewCACert2-2').split()
    command.pop(6)
    command.insert(6, csr)
    command.pop(8)
    command.insert(8, key)
    command.pop(10)
    command.insert(10, new)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** renew_rootca *** return code: %s", rc)
        time.sleep(0.1)
        cert = cfg.get('server', 'serverCert')
        verify_renewca(new, cert)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)

    verify_rootca_database(cfg.get('installation', 'indexFile'))


def verify_renewca(new, cert):
    logger.debug("*** verify_crl ***")
    command = cfg.get('root', 'cmd_verifiyNewCert').split()
    command.pop(3)
    command.insert(3, new)
    command.pop(5)
    command.insert(5, cert)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_crl *** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)

    cert = cfg.get('root', 'rootCert')
    command = "sha256sum cert".split()
    command.pop(1)
    command.insert(1, cert)
    print("Running command:", ' '.join(command))
    run(command)

    newcert = cfg.get('root', 'rootNewCert')
    command = "sha256sum cert".split()
    command.pop(1)
    command.insert(1, newcert)
    print("Running command:", ' '.join(command))
    run(command)

    command = "openssl x509 -noout -text -in orig-cacert.pem".split()
    command.pop(5)
    command.insert(5, cert)
    print("Running command:", ' '.join(command))
    run(command)
    command.pop(5)
    command.insert(5, newcert)
    print("Running command:", ' '.join(command))
    run(command)


def renew_self():
    pass


def renew_server():
    pass