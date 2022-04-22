import subprocess
import logging
import sys

# Log file location
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


def generatePrivateKey():
    # Define command as string and then split() into list format
    command = 'openssl genrsa -passout file:mypass.enc -out server.key 4096'.split()
    # genpkey has superceded genrsa
    # cmd = 'openssl genpkey -passout file:mypass.enc -out server.key 4096'.split()
    # Check the list value of cmd
    print('command in list format:', command)
    run(command)
    verifyPrivateKey()


def generateCSR():
    command = 'openssl req -new -key server.key -out server.csr \
           -passin file:mypass.enc -config self_signed_certificate.cnf'.split()
    print('command in list format:', command)
    run(command)
    verifyCSR()


def generateX509cert():
    command = 'openssl x509 \
                   -req \
                   -days 365 \
                   -in server.csr \
                   -signkey server.key \
                   -out server.crt \
                   -passin file:mypass.enc'.split()
    print('command in list format:', command)
    run(command)
    verifySelfSignedCert()


def verifyPrivateKey():
    command = 'openssl rsa -noout -text -in server.key -passin file:mypass.enc'.split()
    # Check the list value of cmd
    print('command in list format:', command)
    run(command)


def verifyCSR():
    command = 'openssl req -noout -text -in server.csr'.split()
    # Check the list value of cmd
    print('command in list format:', command)
    run(command)


def verifySelfSignedCert():
    command = 'openssl x509 -noout -text -in server.crt'.split()
    # Check the list value of cmd
    print('command in list format:', command)
    run(command)


generatePrivateKey()
generateCSR()
generateX509cert()







