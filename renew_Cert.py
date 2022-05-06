import time
import os
import difflib
from subprocess import Popen, PIPE, CalledProcessError
from helper import run, run_out, logger, verify_rootca_database, verify_crl_serial

from configparser import ConfigParser
cfg = ConfigParser()
cfg.read('config.ini')


def export_old_csr(cert, key, csr):
    logger.debug("*** export_old_csr ***")
    command = cfg.get('root', 'cmd_exportCSR').split()
    command.pop(4)
    command.insert(4, cert)
    command.pop(6)
    command.insert(6, key)
    command.pop(8)
    command.insert(8, csr)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** export_old_csr *** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def renew_cert(csr, key, new):
    logger.debug("*** renew_root ***")
    command = cfg.get('root', 'cmd_renewCert').split()
    command.pop(6)
    command.insert(6, csr)
    command.pop(8)
    command.insert(8, key)
    command.pop(10)
    command.insert(10, new)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** renew_root *** return code: %s", rc)
        verify_renew(new, cfg.get('server', 'serverCert'))
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def verify_renew(new, cert):
    logger.debug("*** verify_crl ***")
    command = cfg.get('root', 'cmd_verifiyNewCert').split()
    command.pop(3)
    command.insert(3, new)
    command.pop(5)
    command.insert(5, cert)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        print("\n----------------------------Check verify returns an OK---------------------")
        rc = run(command)
        print("---------------------------------------------------------------------------")
        logger.debug("*** verify_crl *** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)

    cert = cfg.get('root', 'rootCert')
    command = "sha256sum cert".split()
    command.pop(1)
    command.insert(1, cert)
    print("\n")
    print("Running command:", ' '.join(command))
    run(command)

    newcert = cfg.get('root', 'rootNewCert')
    command = "sha256sum cert".split()
    command.pop(1)
    command.insert(1, newcert)
    print("Running command:", ' '.join(command))
    run(command)

    print("\n")
    command = "openssl x509 -noout -text -in orig-cacert.pem".split()
    command.pop(5)
    command.insert(5, cert)
    print("Running command:", ' '.join(command))
    run_out(command, '/tmp/old.pem')

    command.pop(5)
    command.insert(5, newcert)
    print("Running command:", ' '.join(command))
    run_out(command, '/tmp/new.pem')

    print("\nChecking that Modulus output matches in both certs")
    print("--------------------------------------------------\n")
    f1 = open("/tmp/old.pem", "r")
    f2 = open("/tmp/new.pem", "r")

    for line1 in f1:
        for line2 in f2:
            if line1 == line2:
                print("Match:", line1, end='')
            break
    f1.close()
    f2.close()
    os.remove('/tmp/old.pem')
    os.remove('/tmp/new.pem')


def renew_self():
    pass


def renew_server():
    pass
