import os.path
from pathlib import Path
import time
from helper import run, logger
from subprocess import CalledProcessError
import subprocess

from configparser import ConfigParser
cfg = ConfigParser()
cfg.read('config.ini')


class certificate:
    """Keys used for CA's and hosts"""
    # self | root | server | client
    type = cfg.get('key', 'type')
    #type = 'root'

    def __init__(self):
        self._name = None
        #self._config = None
        #self._commonName = None
        #self._messageDigest = None
        self._validity = None
        self._type = None
        #self._key = None
        #self._passphrase = None

    @property
    def name(self):
        return self._name

    @name.setter
    def name(self, value):
        parent = Path(value).parent
        if parent.exists():
            self._name = value
        else:
            raise ValueError("Parent folder does not exist")

    @property
    def size(self):
        return self._size

    @size.setter
    def size(self, value):
        if value in (2048, 3072, 4096, 5120, 6144):
            self._size = value
        else:
            raise ValueError("Size invalid")

    @property
    def crypto(self):
        return self._crypto

    @crypto.setter
    def crypto(self, value):
        if value in ('ec', 'rsa', 'des', 'dh'):
            self._crypto = value
        else:
            raise ValueError("Crypto invalid")

    @property
    def cipher(self):
        return self._cipher

    @cipher.setter
    def cipher(self, value):
        if value in ('aes256', 'des3'):
            self._cipher = value
        else:
            raise ValueError("Cipher invalid")

    @property
    def passphrase(self):
        return self._passphrase

    @passphrase.setter
    def passphrase(self, value):
        file = Path(value)
        if file.exists():
            self._passphrase = value
        else:
            raise ValueError("Passphrase invalid")

    def generate_x509_cert(csr, key, crt, pwd):
        logger.debug("*** generate_x509_cert ***")

        command = cfg.get('self', 'cmd_X509SelfCert').split()
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
            time.sleep(0.1)
            certificate.verify_self_signed_cert(crt)
        except OSError as error:
            logger.error(error)
        except CalledProcessError as error:
            logger.error(error)

    def verify_self_signed_cert(cert):
        logger.debug("*** verify_self_signed_cert ***")

        command = cfg.get('self', 'cmd_VerifySelfCert').split()
        command.pop(5)
        command.insert(5, cert)
        try:
            logger.debug(("Command executed:", ' '.join(command)))
            rc = run(command)
            logger.debug("*** verify_self_signed_cert *** return code: %s", rc)
        except OSError as error:
            logger.error(error)
        except CalledProcessError as error:
            logger.error(error)









