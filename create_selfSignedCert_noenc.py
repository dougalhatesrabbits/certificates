import subprocess
import logging
import sys
import os

projectLocation = os.getcwd()
baseTlsLocation = os.path.join(projectLocation, "tls")
privateFolder = os.path.join(baseTlsLocation, "private")
certsFolder = os.path.join(baseTlsLocation, "certs")
opensslConf = os.path.join(baseTlsLocation, "openssl.cnf")
#opensslConf = os.path.join(baseTlsLocation, "self_signed_certificate.cnf")
encPasswordFile = os.path.join(baseTlsLocation, "mypass.enc")
privateKey = os.path.join(certsFolder, "server-noenc.key")
selfCertificate = os.path.join(certsFolder, "servernoenc.crt")
selfCSR = os.path.join(certsFolder, "server-noenc.csr")

# Log file location
logfile = os.path.join(projectLocation, 'debug.log')
# Define the log format
log_format = (
    '[%(asctime)s] %(levelname)-8s %(name)-12s %(message)s')

# Define basic configuration
logging.basicConfig(
    # Define logging level
    level=logging.DEBUG,
    # Define the format of log messages
    format=log_format,
    # Declare handlers
    handlers=[
        logging.FileHandler(logfile),
        logging.StreamHandler(sys.stdout),
    ]
)
# Define logger name
logger = logging.getLogger("cert_logger")


def run(cmd):
    sp = subprocess.run(cmd,
                        shell=False,
                        check=True,
                        capture_output=True,
                        text=True)
    print("stdout: ", sp.stdout)
    print("stderr: ", sp.stderr)
    logger.error(sp.stderr)


def generate_private_key(key):
    command = 'openssl genrsa \
               -out server-noenc.key 4096'.split()
    # genpkey has superceded genrsa
    # cmd = 'openssl genpkey -passout file:mypass.enc -out server.key 4096'.split()

    command.pop(3)
    command.insert(3, key)

    try:
        print('command in list format:', command)
        run(command)
    except OSError as error:
        logger.error(error)
    except subprocess.CalledProcessError as error:
        logger.error(error)

    verify_private_key(key)


def generate_csr(key, csr, cfg):
    command = 'openssl req \
               -new \
               -key server-noenc.key \
               -out server-noenc.csr \
               -config tls/self_signed_certificate.cnf'.split()
    command.pop(4)
    command.insert(4, key)
    command.pop(6)
    command.insert(6, csr)
    command.pop(10)
    command.insert(10, cfg)

    try:
        print('command in list format:', command)
        run(command)
    except OSError as error:
        logger.error(error)
    except subprocess.CalledProcessError as error:
        logger.error(error)

    verify_csr(csr)


def generate_x509_cert(csr, key, crt):
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
    print('command in list format:', command)
    run(command)
    verify_self_signed_cert(crt)


def verify_private_key(key):
    command = 'openssl rsa \
               -noout \
               -text \
               -in server-noenc.key'.split()
    command.pop(5)
    command.insert(5, key)

    print('command in list format:', command)
    run(command)


def verify_csr(csr):
    command = 'openssl req \
               -noout \
               -text \
               -in server-noenc.csr'.split()
    command.pop(5)
    command.insert(5, csr)
    print('command in list format:', command)
    run(command)


def verify_self_signed_cert(crt):
    command = 'openssl x509 \
               -noout \
               -text \
               -in server.crt'.split()
    command.pop(5)
    command.insert(5, crt)
    print('command in list format:', command)
    run(command)


# ---main---
generate_private_key(privateKey)
generate_csr(privateKey, selfCSR, opensslConf)
generate_x509_cert(selfCSR, privateKey, selfCertificate)







