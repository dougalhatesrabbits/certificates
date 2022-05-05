import time
import os
from subprocess import Popen, PIPE, CalledProcessError
from helper import run, logger, verify_rootca_database, verify_crl_serial

from configparser import ConfigParser
cfg = ConfigParser()
cfg.read('config.ini')


def revoke_cert(ssl, cert):
    logger.debug("*** revoke_cert ***")
    command = cfg.get('root', 'cmd_RevokeCert').split()
    command.pop(3)
    command.insert(3, ssl)
    command.pop(5)
    command.insert(5, cert)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** revoke_cert *** return code: %s", rc)
        time.sleep(0.1)
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
        time.sleep(0.1)
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

    # create bundle against revoked cert
    with open(cfg.get('root', 'rootCert'), 'r') as f_in, open('/tmp/test.pem', 'a+') as f:
        cert = f_in.readlines()
        f.writelines(cert)
    with open(cfg.get('root', 'caCrlFile'), 'r') as f_in, open('/tmp/test.pem', 'a+') as f:
        crl = f_in.readlines()
        f.writelines(crl)

    command = "openssl verify -extended_crl -verbose -CAfile /tmp/test.pem -crl_check /certs/server-1.crt".split()
    command.pop(7)
    command.insert(7, cfg.get('server', 'serverCert'))
    print("Running command:", ' '.join(command))
    run(command)
    os.remove('/tmp/test.pem')
    print("\nIf we get an error similar to:")
    print("error 20 at 0 depth lookup: unable to get local issuer certificate\n")
    print("Then this proves the certificate is revoked :-)")


