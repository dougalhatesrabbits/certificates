import time
import os
from subprocess import Popen, PIPE, CalledProcessError
from helper import run, logger


def revoke_cert(ssl, cert, index):
    logger.debug("*** revoke_cert ***")
    command = "openssl ca \
               -config /root/tls/openssl.cnf \
               -revoke /certs/server-1.crt".split()
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

    with open(index, "r+") as f:
        print("\nIndex file entry\n----------------")
        print(f.read())


def generate_revocation_list(cfg, crl):
    logger.debug("*** generate_revocation_list ***")
    command = "openssl ca \
               -config /root/tls/openssl.cnf \
               -gencrl \
               -out  /root/tls/crl/rootca.crl".split()
    command.pop(3)
    command.insert(3, cfg)
    command.pop(5)
    command.insert(5, crl)
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
    command = 'openssl crl  \
              -in /root/tls/crl/rootca.crl \
              -text \
              -noout'.split()
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

