import time
import os
from subprocess import Popen, PIPE, CalledProcessError
from helper import run, logger


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


def verify_ecc_private_key(key):
    logger.debug("*** verify_ecc_private_key ***")
    command = "openssl ecparam \
               -in private/ec-cakey.pem \
               -text -noout".split()
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


def verify_cert(cert, key):
    logger.debug("*** verify_ca_cert 1/3***")
    command = 'openssl x509 \
               -noout \
               -text \
               -in certs/ec-cacert.pem'.split()

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
    command = 'openssl x509 \
               -noout \
               -pubkey \
               -in certs/ec-cacert.pem'.split()
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
    command = 'openssl pkey \
               -pubout \
               -in private/ec-cakey.pem'.split()
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


def verify_csr(csr):
    logger.debug("*** verify_server_csr ***")
    command = 'openssl req \
               -noout \
               -text \
               -in server.csr'.split()
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


def verify_server_cert(cacert, srvcert, index):
    logger.debug("*** verify_server_cert ***1/2")
    command = 'openssl verify \
               -CAfile /root/tls/certs/ec-cacert.pem server.crt'.split()
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
    command = 'openssl x509 \
               -noout \
               -text \
               -in server.crt'.split()
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

    with open(index, "r+") as f:
        print("\nIndex file entry\n----------------")
        print(f.read())


def generate_ecc_private_key(key):
    logger.debug("*** generate_ecc_private_key ***")
    command = "openssl ecparam \
               -out private/ec-cakey.pem \
               -name prime256v1 \
               -genkey".split()
    command.pop(3)
    command.insert(3, key)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** generate_ecc_private_key *** return code: %s", rc)
        time.sleep(1)
        verify_ecc_private_key(key)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def generate_ecc_ca_cert(ssl, key, cert):
    logger.debug("*** generate_ca_cert ***")
    command = "openssl req -new \
               -x509 \
               -days 3650 \
               -config openssl.cnf \
               -extensions v3_ca \
               -key private/ec-cakey.pem \
               -out certs/ec-cacert.pem".split()
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


def generate_csr(key, csr, cfg):
    logger.debug("*** generate_csr ***")
    command = 'openssl req \
                   -new \
                   -key server.key \
                   -out server.csr \
                   -config tls/self_signed_certificate.cnf'.split()
    command.pop(4)
    command.insert(4, key)
    command.pop(6)
    command.insert(6, csr)
    command.pop(8)
    command.insert(8, cfg)
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


def generate_cert(key, cacert, csr, cert, cfg, index):
    logger.debug("*** generate_cert ***")
    command = 'openssl ca \
              -keyfile /root/tls/private/ec-cakey.pem \
              -cert /root/tls/certs/ec-cacert.pem \
              -in server.csr \
              -out server.crt \
              -config /root/tls/openssl.cnf'.split()
    command.pop(3)
    command.insert(3, key)
    command.pop(5)
    command.insert(5, cacert)
    command.pop(7)
    command.insert(7, csr)
    command.pop(9)
    command.insert(9, cert)
    command.pop(11)
    command.insert(11, cfg)

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
        time.sleep(1)
        verify_server_cert(cacert, cert, index)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)










