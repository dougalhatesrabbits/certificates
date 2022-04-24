import helper
import os


projectLocation = os.getcwd()
baseTlsLocation = os.path.join(projectLocation, "tls")
privateFolder = os.path.join(baseTlsLocation, "private")
certsFolder = os.path.join(baseTlsLocation, "certs")
serverFolder = os.path.join(baseTlsLocation, "server_certs")
#opensslConf = os.path.join(baseTlsLocation, "openssl.cnf")
#opensslConf = os.path.join(baseTlsLocation, "self_signed_certificate.cnf")
opensslConf = os.path.join(baseTlsLocation, "ca_cert.cnf")
encPasswordFile = os.path.join(baseTlsLocation, "mypass.enc")
privateKey = os.path.join(privateFolder, "ec-cakey.pem")
caCertificate = os.path.join(certsFolder, "ec-cacert.pem")
serialFile = os.path.join(baseTlsLocation, "serial")
indexFile = os.path.join(baseTlsLocation, "index.txt")
selfCertificate = os.path.join(certsFolder, "server.crt")
selfCSR = os.path.join(certsFolder, "server.csr")


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


if __name__ == '__main__':
    list_curves()
    generate_ecc_private_key(privateKey)
    generate_ca_cert(opensslConf, privateKey, caCertificate)
    #list_files(projectLocation)






