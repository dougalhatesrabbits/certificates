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
secretFile = os.path.join(baseTlsLocation, "mypass")
clearPasswordFile = os.path.join(projectLocation, secretFile)
encPasswordFile = os.path.join(baseTlsLocation, "mypass.enc")
privateKey = os.path.join(certsFolder, "server.key")
selfCertificate = os.path.join(certsFolder, "server.crt")
selfCSR = os.path.join(certsFolder, "server.csr")

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


def encrypt_password_file(clear, pwd):
    # Define command as string and then split() into list format
    command = "openssl enc \
               -aes256 \
               -pbkdf2 \
               -salt \
               -in mypass \
               -out mypass.enc".split()
    command.pop(6)
    command.insert(6, clear)
    command.pop(8)
    command.insert(8, pwd)
    print('command in list format:', command)
    run(command)


def decrypt_password_file(pwd):
    command = "openssl enc \
               -aes256 \
               -pbkdf2 \
               -salt -d \
               -in mypass.enc".split()
    command.pop(7)
    command.insert(7, pwd)
    try:
        print('command in list format:', command)
        run(command)
    except OSError as error:
        logger.error(error)


def generate_private_key(pwd, key):
    command = 'openssl genrsa \
               -passout file:mypass.enc \
               -out server.key 4096'.split()
    # genpkey has superceded genrsa
    # cmd = 'openssl genpkey -passout file:mypass.enc -out server.key 4096'.split()
    arg = "file:" + pwd
    command.pop(3)
    command.insert(3, arg)
    command.pop(5)
    command.insert(5, key)
    try:
        print('command in list format:', command)
        run(command)
    except OSError as error:
        logger.error(error)
    except subprocess.CalledProcessError as error:
        logger.error(error)

    verify_private_key(key, pwd)


def generate_csr(key, csr, pwd, cfg):
    command = 'openssl req \
               -new \
               -key server.key \
               -out server.csr \
               -passin file:mypass.enc \
               -config tls/self_signed_certificate.cnf'.split()
    command.pop(4)
    command.insert(4, key)
    command.pop(6)
    command.insert(6, csr)
    arg = "file:" + pwd
    command.pop(8)
    command.insert(8, arg)
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


def generate_x509_cert(csr, key, crt, pwd):
    command = 'openssl x509 \
               -req \
               -days 365 \
               -in server.csr \
               -signkey server.key \
               -out server.crt \
               -passin file:mypass.enc'.split()
    command.pop(6)
    command.insert(6, csr)
    command.pop(8)
    command.insert(8, key)
    command.pop(10)
    command.insert(10, crt)
    arg = "file:" + pwd
    command.pop(12)
    command.insert(12, arg)
    print('command in list format:', command)
    run(command)
    verify_self_signed_cert(crt)


def verify_private_key(key, pwd):
    command = 'openssl rsa \
               -noout \
               -text \
               -in server.key \
               -passin file:mypass.enc'.split()
    command.pop(5)
    command.insert(5, key)
    arg = "file:" + pwd
    command.pop(7)
    command.insert(7, arg)
    print('command in list format:', command)
    run(command)


def verify_csr(csr):
    command = 'openssl req \
               -noout \
               -text \
               -in server.csr'.split()
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
#encrypt_password_file(clearPasswordFile, encPasswordFile)
#decrypt_password_file(encPasswordFile)
#generate_private_key(encPasswordFile, privateKey)
#generate_csr(privateKey, selfCSR, encPasswordFile, opensslConf)
generate_x509_cert(selfCSR, privateKey, selfCertificate, encPasswordFile)







