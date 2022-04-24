import helper
import os

projectLocation = os.getcwd()
baseTlsLocation = os.path.join(projectLocation, "tls")
privateFolder = os.path.join(baseTlsLocation, "private")
certsFolder = os.path.join(baseTlsLocation, "certs")
encPasswordFile = os.path.join(baseTlsLocation, "mypass.enc")
opensslConf = os.path.join(baseTlsLocation, "openssl.cnf")
privateKey = os.path.join(certsFolder, "server.key")
selfCertificate = os.path.join(certsFolder, "server.crt")
selfCSR = os.path.join(certsFolder, "server.csr")


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
        helper.run(command)
        verify_private_key(key, pwd)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)


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
        helper.run(command)
        verify_csr(csr)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)


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
    try:
        print('command in list format:', command)
        helper.run(command)
        verify_self_signed_cert(crt)
    except OSError as error:
        helper.logger.error(error)
    except helper.subprocess.CalledProcessError as error:
        helper.logger.error(error)


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
    generate_private_key(encPasswordFile, privateKey)
    generate_csr(privateKey, selfCSR, encPasswordFile, opensslConf)
    generate_x509_cert(selfCSR, privateKey, selfCertificate, encPasswordFile)








