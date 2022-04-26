from helper import run, logger
from subprocess import CalledProcessError
import os
import time

# Working area
projectLocation = os.getcwd()
baseTlsLocation = os.path.join(projectLocation, "tls")
opensslConf = os.path.join(baseTlsLocation, "openssl.cnf")

# Self-Signed/CA
privateFolder = os.path.join(baseTlsLocation, "private")
certsFolder = os.path.join(baseTlsLocation, "certs")
caKey = os.path.join(privateFolder, "ec-cakey.pem")
caCertificate = os.path.join(certsFolder, "ec-cacert.pem")
ca_opensslConf = os.path.join(baseTlsLocation, "ca_cert.cnf")
selfKey = os.path.join(privateFolder, "self.key")
selfCertificate = os.path.join(certsFolder, "self.crt")
selfCSR = os.path.join(certsFolder, "self.csr")
self_opensslConf = os.path.join(baseTlsLocation, "self_signed_certificate.cnf")
serialFile = os.path.join(baseTlsLocation, "serial")
indexFile = os.path.join(baseTlsLocation, "index.txt")

# Server
serverFolder = os.path.join(baseTlsLocation, "server_certs")
serverKey = os.path.join(privateFolder, "server.key")
serverCSR = os.path.join(serverFolder, "server.csr")
serverCert = os.path.join(serverFolder, "server.crt")
server_opensslConf = os.path.join(baseTlsLocation, "server_cert.cnf")

# Client
clientFolder = os.path.join(baseTlsLocation, "client_certs")
clientKey = os.path.join(privateFolder, "client.key")
clientCSR = os.path.join(clientFolder, "client.csr")
clientCert = os.path.join(clientFolder, "client.crt")
client_opensslConf = os.path.join(baseTlsLocation, "client_cert.cnf")

# Private key password file (option)
encPasswordFile = os.path.join(privateFolder, "mypass.enc")


def generate_private_key(key):
    logger.debug("*** generate_private_key ***")
    command = 'openssl genrsa \
               -out server-noenc.key 4096'.split()
    # genpkey has superceded genrsa
    # cmd = 'openssl genpkey -passout file:mypass.enc -out server.key 4096'.split()
    command.pop(3)
    command.insert(3, key)

    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** generate_private_key *** return code: %s", rc)
        time.sleep(1)
        verify_private_key(key)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def generate_csr(key, csr, cfg):
    logger.debug("*** generate_csr ***")
    command = 'openssl req \
               -new \
               -key server-noenc.key \
               -out server-noenc.csr \
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


def generate_x509_cert(csr, key, crt):
    logger.debug("*** generate_x509_cert ***")
    command = 'openssl x509 \
               -req \
               -days 365 \
               -in server-noenc.csr \
               -signkey server-noenc.key \
               -out server-noenc.crt'.split()
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
        time.sleep(1)
        verify_self_signed_cert(crt)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def verify_private_key(key):
    logger.debug("*** verify_private_key ***")
    command = 'openssl rsa \
               -noout \
               -text \
               -in server-noenc.key'.split()
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


if __name__ == '__main__':
    generate_private_key(selfKey)
    generate_csr(selfKey, selfCSR, self_opensslConf)
    generate_x509_cert(selfCSR, selfKey, selfCertificate)







