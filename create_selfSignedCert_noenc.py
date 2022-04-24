import helper
import os

projectLocation = os.getcwd()
baseTlsLocation = os.path.join(projectLocation, "tls")
privateFolder = os.path.join(baseTlsLocation, "private")
certsFolder = os.path.join(baseTlsLocation, "certs")
#opensslConf = os.path.join(baseTlsLocation, "openssl.cnf")
opensslConf = os.path.join(baseTlsLocation, "self_signed_certificate.cnf")
privateKey = os.path.join(certsFolder, "server-noenc.key")
selfCertificate = os.path.join(certsFolder, "servernoenc.crt")
selfCSR = os.path.join(certsFolder, "server-noenc.csr")


def generate_private_key(key):
    command = 'openssl genrsa \
               -out server-noenc.key 4096'.split()
    # genpkey has superceded genrsa
    # cmd = 'openssl genpkey -passout file:mypass.enc -out server.key 4096'.split()

    command.pop(3)
    command.insert(3, key)

    try:
        print('command in list format:', command)
        helper.run(command)
        verify_private_key(key)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)


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
    command.pop(8)
    command.insert(8, cfg)

    try:
        print('command in list format:', command)
        helper.run(command)
        verify_csr(csr)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)


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
    try:
        print('command in list format:', command)
        helper.run(command)
        verify_self_signed_cert(crt)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)


def verify_private_key(key):
    command = 'openssl rsa \
               -noout \
               -text \
               -in server-noenc.key'.split()
    command.pop(5)
    command.insert(5, key)

    try:
        print('command in list format:', command)
        helper.run(command)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)


def verify_csr(csr):
    command = 'openssl req \
               -noout \
               -text \
               -in server-noenc.csr'.split()
    command.pop(5)
    command.insert(5, csr)
    try:
        print('command in list format:', command)
        helper.run(command)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)


def verify_self_signed_cert(crt):
    command = 'openssl x509 \
               -noout \
               -text \
               -in server.crt'.split()
    command.pop(5)
    command.insert(5, crt)
    try:
        print('command in list format:', command)
        helper.run(command)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)


if __name__ == '__main__':
    generate_private_key(privateKey)
    generate_csr(privateKey, selfCSR, opensslConf)
    generate_x509_cert(selfCSR, privateKey, selfCertificate)







