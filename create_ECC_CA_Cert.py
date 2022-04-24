import helper
import os
from subprocess import Popen, PIPE

# Working area
projectLocation = os.getcwd()
baseTlsLocation = os.path.join(projectLocation, "tls")
opensslConf = os.path.join(baseTlsLocation, "openssl.cnf")

# Self-Signed/CA
privateFolder = os.path.join(baseTlsLocation, "private")
certsFolder = os.path.join(baseTlsLocation, "certs")
privateKey = os.path.join(privateFolder, "ec-cakey.pem")
caCertificate = os.path.join(certsFolder, "ec-cacert.pem")
serialFile = os.path.join(baseTlsLocation, "serial")
indexFile = os.path.join(baseTlsLocation, "index.txt")
selfCertificate = os.path.join(certsFolder, "server.crt")
selfCSR = os.path.join(certsFolder, "server.csr")
self_opensslConf = os.path.join(baseTlsLocation, "self_signed_certificate.cnf")
ca_opensslConf = os.path.join(baseTlsLocation, "ca_cert.cnf")

# Server
serverFolder = os.path.join(baseTlsLocation, "server_certs")
serverKey = os.path.join(serverFolder, "server.key")
serverCSR = os.path.join(serverFolder, "server.csr")
serverCert = os.path.join(serverFolder, "server.crt")
server_opensslConf = os.path.join(baseTlsLocation, "server_cert.cnf")

# Client
clientFolder = os.path.join(baseTlsLocation, "client_certs")
clientKey = os.path.join(clientFolder, "client.key")
clientCSR = os.path.join(clientFolder, "client.csr")
clientCert = os.path.join(clientFolder, "client.crt")
client_opensslConf = os.path.join(baseTlsLocation, "client_cert.cnf")

# Private key password file (option)
encPasswordFile = os.path.join(baseTlsLocation, "mypass.enc")


def list_curves():
    # Define command as string and then split() into list format
    command = 'openssl ecparam \
               -list_curves'.split()
    try:
        print('command in list format:', command)
        helper.run(command)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)


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
    try:
        print('command in list format:', command)
        helper.run(command)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)


def verify_ca_cert(cert, key):
    command = 'openssl x509 \
               -noout \
               -text \
               -in certs/ec-cacert.pem'.split()

    command.pop(5)
    command.insert(5, cert)
    try:
        print('command in list format:', command)
        helper.run(command)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)

    command = 'openssl x509 \
               -noout \
               -pubkey \
               -in certs/ec-cacert.pem'.split()
    command.pop(5)
    command.insert(5, cert)
    try:
        print('command in list format:', command)
        helper.run(command)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)
    command = 'openssl pkey \
               -pubout \
               -in private/ec-cakey.pem'.split()

    command.pop(4)
    command.insert(4, key)
    try:
        print('command in list format:', command)
        helper.run(command)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)


def verify_server_csr(csr):
    command = 'openssl req \
               -noout \
               -text \
               -in server.csr'.split()
    command.pop(5)
    command.insert(5, csr)
    try:
        print('command in list format:', command)
        helper.run(command)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)


def verify_server_cert(cacert, srvcert):
    command = 'openssl verify \
               -CAfile /root/tls/certs/ec-cacert.pem server.crt'.split()
    command.pop(3)
    command.insert(3, cacert)
    command.pop(4)
    command.insert(4, srvcert)
    try:
        print('command in list format:', command)
        helper.run(command)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)

    command = 'openssl x509 \
               -noout \
               -text \
               -in server.crt'.split()
    command.pop(5)
    command.insert(5, srvcert)
    try:
        print('command in list format:', command)
        helper.run(command)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)

    with open(indexFile, "r+") as f:
        print("\nIndex file entry\n----------------")
        print(f.read())


def generate_ecc_private_key(key):
    command = "openssl ecparam \
               -out private/ec-cakey.pem \
               -name prime256v1 \
               -genkey".split()
    command.pop(3)
    command.insert(3, key)
    try:
        print('command in list format:', command)
        helper.run(command)
        verify_ecc_private_key(key)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)


def generate_ca_cert(ssl, key, cert):
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
        print('command in list format:', command)
        helper.run(command)
        verify_ca_cert(cert, key)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)


def generate_csr(key, csr, cfg):
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
        print('command in list format:', command)
        helper.run(command)
        verify_server_csr(csr)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)


def generate_cert(key, cacert, csr, cert, cfg):
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
    # run the openssl and input 2 confirmations
    try:
        print('command in list format:', command)
        sp = Popen(command, stdin=PIPE, stdout=PIPE, stderr=PIPE, text=True)
        sp.communicate(os.linesep.join(["y", "y"]))
        # Store the return code in rc variable
        rc = sp.wait()

        # Separate the output and error.
        out, err = sp.communicate()

        print('Return Code:', rc, '\n')
        print('output is: \n', out)
        print('error is: \n', err)
        #helper.run(command)
        #verify_server_cert(cacert, srvcert)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)


if __name__ == '__main__':
    # ---CA---
    # list_curves()
    # generate_ecc_private_key(privateKey)
    # generate_ca_cert(ca_opensslConf, privateKey, caCertificate)
    # ---Server---
    # generate_ecc_private_key(serverKey)
    # generate_csr(serverKey, serverCSR, server_opensslConf)
    # generate_cert(privateKey, caCertificate, serverCSR, serverCert, server_opensslConf)
    # ---Client---
    # generate_ecc_private_key(clientKey)
    # generate_csr(clientKey, clientCSR, client_opensslConf)
     generate_cert(privateKey, caCertificate, clientCSR, clientCert, client_opensslConf)
    # list_files(projectLocation)






