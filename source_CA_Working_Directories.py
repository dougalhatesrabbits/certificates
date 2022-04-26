import subprocess
import logging
import sys
import os
import shutil

TODO:
 #Work in progress

#current = os.getcwd()
# ECC locations
#private = "tls/private"
#certs = "tls/certs"
#openssl = "tls/openssl.cnf"
#openssl = "tls/self_signed_certificate.cnf"
projectLocation = os.getcwd()
baseTlsLocation = os.path.join(projectLocation, "tls")
privateFolder = os.path.join(baseTlsLocation, "private")
certsFolder = os.path.join(baseTlsLocation, "certs")
serverFolder = os.path.join(baseTlsLocation, "server_certs")
opensslConf = os.path.join(baseTlsLocation, "openssl.cnf")
secretFile = os.path.join(baseTlsLocation, "mypass")
clearPasswordFile = os.path.join(projectLocation, secretFile)
encPasswordFile = os.path.join(baseTlsLocation, "tls/private/mypass.enc")
privateKey = os.path.join(certsFolder, "server.key")
selfCertificate = os.path.join(certsFolder, "server.crt")
selfCSR = os.path.join(certsFolder, "server.csr")
serial = "tls/serial"
index = "tls/index.txt"
source = "/etc/ssl/openssl.cnf"
backupFile = "tls/openssl.cnf.bak"
tmpFile = "/tmp/openssl.txt"
keyName = "ec-cakey.pem"
certName = "ec-cacert.pem"

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


def sourceWorkingDirectory(cwd, pvt, crt, idx, srl, src, ssl):
    dest = os.path.join(current, ssl)
    path = os.path.join(cwd, pvt)
    mode = 0o666
    # add private dir
    try:
        os.makedirs(path, mode)
    except OSError as error:
        logger.error(error)

    # add certs dir
    path = os.path.join(cwd, crt)
    try:
        os.makedirs(path, mode)
    except OSError as error:
        logger.error(error)

    # add index file
    path = os.path.join(cwd, idx)
    try:
        # touch
        with open(path, 'x') as file_object:
            pass
    except OSError as error:
        logger.error(error)

    # add serial file
    filename = os.path.join(cwd, srl)
    try:
        with open(filename, 'w') as file_object:
            file_object.write("01\n")
    except OSError as error:
        logger.error(error)

    # copy openssl.cnf from say /etc/ssl
    shutil.copyfile(src, dest)


def editSSLConf(cwd, ssl, pvt, back, tmp):
    # --- Edit openssl.cnf

    # backup first
    originalFile = os.path.join(cwd, ssl)
    #dest = os.path.join(cwd, ssl)
    backupLocation = os.path.join(cwd, back)
    try:
        shutil.copyfile(originalFile, backupLocation)
    except OSError as error:
        logger.error(error)

    # now edit original
    input_f = open(originalFile, 'r')
    output_f = open(tmp, 'w')
    privatePath = os.path.join(cwd, pvt)
    #line = []

    with input_f, output_f:
        for lines in input_f:
            line = lines.split()
            if not line or line[0] != 'dir':
                output_f.write(lines)
            else:
                line.pop(2)
                line.insert(2, cwd)
                new_line = ' '.join(line)
                output_f.write(new_line + " \n")

    # update
    try:
        shutil.copyfile(tmp, originalFile)
    except OSError as error:
        logger.error(error)


sourceWorkingDirectory(current, private, certs, index, serial, source, openssl)


#editSSLConf(current, openssl, private, backupFile, tmpFile)

#listFiles(current)