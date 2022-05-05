import time
import os
from subprocess import Popen, PIPE, CalledProcessError
from helper import run, logger

from configparser import ConfigParser
cfg = ConfigParser()
cfg.read('config.ini')


def generate_csr(key, csr, ssl):
    logger.debug("*** generate_csr ***")

    command = cfg.get('server', 'cmd_ServerCSR').split()
    command.pop(4)
    command.insert(4, key)
    command.pop(6)
    command.insert(6, csr)
    command.pop(9)
    command.insert(9, ssl)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** generate_csr *** return code: %s", rc)
        time.sleep(0.1)
        verify_csr(csr)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def verify_csr(csr):
    logger.debug("*** verify_server_csr ***")

    command = cfg.get('self', 'cmd_VerifyCSR').split()
    command.pop(5)
    command.insert(5, csr)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_server_csr *** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


# Server Cert
def generate_cert(key, cacert, csr, cert, ssl):
    logger.debug("*** generate_cert ***")

    command = cfg.get('server', 'cmd_ServerCert').split()
    command.pop(3)
    command.insert(3, key)
    command.pop(5)
    command.insert(5, cacert)
    command.pop(7)
    command.insert(7, csr)
    command.pop(9)
    command.insert(9, cert)
    command.pop(11)
    command.insert(11, ssl)
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

        logger.debug("*** generate_cert *** return code: %s", rc)
        time.sleep(0.1)
        verify_server_cert(cacert, cert, cfg.get('installation', 'indexFile'))
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def verify_server_cert(cacert, srvcert, index):
    logger.debug("*** verify_server_cert ***1/2")

    command = cfg.get('server', 'cmd_VerifyServerCert').split()
    command.pop(3)
    command.insert(3, cacert)
    command.pop(4)
    command.insert(4, srvcert)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_server_cert ***1/2 return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)

    logger.debug("*** verify_server_cert ***2/2")

    command = cfg.get('self', 'cmd_VerifySelfCert').split()
    command.pop(5)
    command.insert(5, srvcert)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_server_cert ***2/2 return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)

    with open(index, "r") as f:
        print("\nIndex file entry\n----------------")
        print(f.read())
