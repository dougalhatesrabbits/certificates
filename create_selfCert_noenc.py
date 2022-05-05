from helper import run, logger
from subprocess import CalledProcessError
import time
from configparser import ConfigParser

cfg = ConfigParser()
cfg.read('config.ini')


def generate_rsa_key(key):
    logger.debug("*** generate_private_key ***")

    command = cfg.get('self', 'cmd_PrivKeyRSA-noenc').split()
    command.pop(3)
    command.insert(3, key)

    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** generate_private_key *** return code: %s", rc)
        time.sleep(0.1)
        verify_rsa_key(key)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def verify_rsa_key(key):
    logger.debug("*** verify_private_key ***")

    command = cfg.get('self', 'cmd_VerifyPrivKeyRSA-noenc').split()
    command.pop(5)
    command.insert(5, key)

    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_private_key *** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def generate_csr(key, csr, ssl):
    logger.debug("*** generate_csr ***")

    command = cfg.get('self', 'cmd_CSR-noenc').split()
    command.pop(4)
    command.insert(4, key)
    command.pop(6)
    command.insert(6, csr)
    command.pop(8)
    command.insert(8, ssl)

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
    logger.debug("*** generate_x509_cert ***")
    command = 'openssl req \
               -noout \
               -text \
               -in server-noenc.csr'.split()
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


def generate_x509_cert(csr, key, crt):
    logger.debug("*** generate_x509_cert ***")

    command = cfg.get('self', 'cmd_X509SelfCert-noenc').split()
    command.pop(6)
    command.insert(6, csr)
    command.pop(8)
    command.insert(8, key)
    command.pop(10)
    command.insert(10, crt)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** generate_x509_cert *** return code: %s", rc)
        time.sleep(0.1)
        verify_self_signed_cert(crt)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def verify_self_signed_cert(crt):
    logger.debug("*** verify_self_signed_cert ***")
    command = 'openssl x509 \
               -noout \
               -text \
               -in server.crt'.split()
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







