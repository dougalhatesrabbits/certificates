import subprocess
import logging
import sys
import os
import shutil

# getting the current directory
current = os.getcwd()
# ECC locations
private = "tls/private"
certs = "tls/certs"
openssl = "tls/openssl.cnf"

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
                line.insert(2, privatePath)
                new_line = ' '.join(line)
                output_f.write(new_line + " \n")

    # update
    try:
        shutil.copyfile(tmp, originalFile)
    except OSError as error:
        logger.error(error)


def listCurves():
    # Define command as string and then split() into list format
    command = 'openssl ecparam -list_curves'.split()
    # Check the list value of cmd
    print('command in list format:', command)
    run(command)


def listFiles(cwd):
    #cwd = os.getcwd()
    # creating list of path
    path = os.path.join(cwd)
    files = (os.listdir(path))
    for root, dirs, files in os.walk(path):
        for file in files:
            if not file.startswith('.'):
                print(root, file)


def verifyEccPrivateKey(key):
    command = "openssl ecparam -in private/ec-cakey.pem -text -noout".split()
    command.pop(3)
    command.insert(3, key)
    # Check the list value of cmd
    print('command in list format:', command)
    run(command)


def verifyCACert(certLoc):
    command = "openssl x509 \
               -noout \
               -text \
               -in certs/ec-cacert.pem \
               | grep -i algorithm".split()
    command.pop(5)
    command.insert(5, certLoc)
    print('command in list format:', command)
    run(command)


def generateEccPrivateKey(cwd,pvt,key):
    keyLocation = os.path.join(cwd, pvt)
    keyPath = os.path.join(keyLocation, key)
    # Define command as string and then split() into list format
    command = "openssl ecparam \
               -out private/ec-cakey.pem \
               -name prime256v1 \
               -genkey".split()
    command.pop(3)
    command.insert(3, keyPath)
    # Check the list value of cmd
    print('command in list format:', command)
    run(command)
    verifyEccPrivateKey(keyPath)


def generateCACert(cwd, ssl, key, pvt, cert, certLoc):
    config = os.path.join(cwd, ssl)
    print(config)
    keyLocation = os.path.join(cwd, pvt)
    keyPath = os.path.join(keyLocation, key)
    certLocation = os.path.join(cwd, certLoc)
    certPath = os.path.join(certLocation, cert)
    command = "openssl req -new \
               -x509 \
               -days 3650 \
               -config openssl.cnf \
               -extensions v3_ca \
               -key private/ec-cakey.pem \
               -out certs/ec-cacert.pem".split()
    command.pop(7)
    command.insert(7, config)
    command.pop(11)
    command.insert(11, keyPath)
    command.pop(13)
    command.insert(13, certPath)
    print('command in list format:', command)
    run(command)
    verifyCACert(certPath)

# ___main___
#
serial = "tls/serial"
index = "tls/index.txt"
source = "/etc/ssl/openssl.cnf"
sourceWorkingDirectory(current, private, certs, index, serial, source, openssl)

backupFile = "tls/openssl.cnf.bak"
tmpFile = "/tmp/openssl.txt"
editSSLConf(current, openssl, private, backupFile, tmpFile)

#listFiles(current)
#listCurves()

keyName = "ec-cakey.pem"
certName = "ec-cacert.pem"
#generateEccPrivateKey(current, private, keyName)
generateCACert(current, openssl, keyName, private, certName, certs)

#listFiles(current)






