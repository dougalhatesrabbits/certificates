import time
from helper import run, logger
from subprocess import CalledProcessError


def generate_private_key(pwd, key):
    logger.debug("*** generate_private_key ***")
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
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** generate_private_key *** return code: %s", rc)
        time.sleep(1)
        verify_private_key(key, pwd)
    except OSError as error:
        logger.error("OSError %s", error)
    except CalledProcessError as error:
        logger.error("CalledProcessError %s", error)


def generate_csr(key, csr, pwd, cfg):
    logger.debug("*** generate_csr ***")
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
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** generate_csr *** return code: %s", rc)
        time.sleep(1)
        verify_csr(csr)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def generate_x509_cert(csr, key, crt, pwd):
    logger.debug("*** generate_x509_cert ***")
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
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_private_key *** return code: %s", rc)
        time.sleep(1)
        verify_self_signed_cert(crt)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def verify_private_key(key, pwd):
    logger.debug("*** verify_private_key ***")
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
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_private_key *** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def verify_csr(csr):
    logger.debug("*** verify_csr ***")
    command = 'openssl req \
               -noout \
               -text \
               -in server.csr'.split()
    command.pop(5)
    command.insert(5, csr)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_csr *** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)


def verify_self_signed_cert(crt):
    logger.debug("*** verify_self_signed_cert ***")
    command = 'openssl x509 \
               -noout \
               -text \
               -in server.crt'.split()
    command.pop(5)
    command.insert(5, crt)
    try:
        logger.debug(("Command executed:", ' '.join(command)))
        rc = run(command)
        logger.debug("*** verify_self_signed_cert *** return code: %s", rc)
    except OSError as error:
        logger.error(error)
    except CalledProcessError as error:
        logger.error(error)













