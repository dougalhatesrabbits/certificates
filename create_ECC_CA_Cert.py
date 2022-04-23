import subprocess
import logging
import sys
import os
import shutil

projectLocation = os.getcwd()
baseTlsLocation = os.path.join(projectLocation, "tls")
privateFolder = os.path.join(baseTlsLocation, "private")
certsFolder = os.path.join(baseTlsLocation, "certs")
#opensslConf = os.path.join(baseTlsLocation, "openssl.cnf")
opensslConf = os.path.join(baseTlsLocation, "self_signed_certificate.cnf")
encPasswordFile = os.path.join(baseTlsLocation, "mypass.enc")
privateKey = os.path.join(privateFolder, "ec-cakey.pem")
caCertificate = os.path.join(certsFolder, "ec-cacert.pem")
serialFile = os.path.join(baseTlsLocation, "serial")
indexFile = os.path.join(baseTlsLocation, "index.txt")


# Log file location ------------------------------------------------
logfile = 'debug.log'
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
# Define logger name ------------------------------------------------
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


def list_curves():
    # Define command as string and then split() into list format
    command = 'openssl ecparam -list_curves'.split()
    # Check the list value of cmd
    print('command in list format:', command)
    run(command)


def list_files(cwd):
    # creating list of path
    path = os.path.join(cwd)
    files = (os.listdir(path))
    for root, dirs, files in os.walk(path):
        for file in files:
            if not file.startswith('.'):
                print(root, file)


def verify_ecc_private_key(key):
    command = "openssl ecparam \
               -in private/ec-cakey.pem \
               -text -noout".split()
    command.pop(3)
    command.insert(3, key)
    # Check the list value of cmd
    print('command in list format:', command)
    run(command)


def verify_ca_cert(cert, key):
    command = 'openssl x509 \
               -noout \
               -text \
               -in certs/ec-cacert.pem'.split()

    command.pop(5)
    command.insert(5, cert)
    print('command in list format:', command)
    run(command)

    command = 'openssl x509 \
               -noout \
               -pubkey \
               -in certs/ec-cacert.pem'.split()

    command.pop(5)
    command.insert(5, cert)
    print('command in list format:', command)
    run(command)

    command = 'openssl pkey \
               -pubout \
               -in private/ec-cakey.pem'.split()

    command.pop(4)
    command.insert(4, key)
    print('command in list format:', command)
    run(command)




def generate_ecc_private_key(key):
    command = "openssl ecparam \
               -out private/ec-cakey.pem \
               -name prime256v1 \
               -genkey".split()
    command.pop(3)
    command.insert(3, key)
    # Check the list value of cmd
    print('command in list format:', command)
    run(command)
    verify_ecc_private_key(key)


def generate_ca_cert(ssl, key, cert):
    """
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

    """
    command = 'openssl req -new \
                   -x509 \
                   -days 3650 \
                   -config openssl.cnf \
                   -key private/ec-cakey.pem \
                   -out certs/ec-cacert.pem'.split()

    command.pop(7)
    command.insert(7, ssl)
    command.pop(9)
    command.insert(9, key)
    command.pop(11)
    command.insert(11, cert)

    print('command in list format:', command)
    run(command)
    verify_ca_cert(cert, key)


# ___main___
#list_curves()
#generate_ecc_private_key(privateKey)
generate_ca_cert(opensslConf, privateKey, caCertificate)
#verify_ca_cert(caCertificate)
#list_files(projectLocation)






