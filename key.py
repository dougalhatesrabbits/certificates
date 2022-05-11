import os.path
from pathlib import Path
import time
from helper import run, logger
from subprocess import CalledProcessError
import subprocess

from configparser import ConfigParser
cfg = ConfigParser()
cfg.read('config.ini')


class protectedKey:
    """Keys used for CA's and hosts"""
    # self | root | server | client
    name = None
    type = None

    def __init__(self):
        self._name = None
        self._type = None
        self._size = None
        self._crypto = None
        self._cipher = None
        self._passphrase = None

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
    def type(self):
        return self._type

    @type.setter
    def type(self, value):
        if value in ('self', 'root', 'server', 'client'):
            self._type = value
        else:
            raise ValueError("Type invalid")

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

    #@staticmethod
    def generate(self, cmd):
        logger.debug("*** generate_private_key ***")
        command = cmd.split()
        try:
            logger.debug(("Command executed:", ' '.join(command)))
            rc = run(command)
            logger.debug("*** generate_private_key *** return code: %s", rc)
            time.sleep(0.1)
            #key.verify(newkey, pwd)
        except OSError as error:
            logger.error("OSError %s", error)
        except CalledProcessError as error:
            logger.error("CalledProcessError %s", error)

    def verify(self, cmd):
        logger.debug("*** verify_private_key ***")
        command = cmd.split()
        try:
            logger.debug(("Command executed:", ' '.join(command)))
            rc = run(command)
            logger.debug("*** verify_private_key *** return code: %s", rc)
        except OSError as error:
            logger.error(error)
        except CalledProcessError as error:
            logger.error(error)


#class unprotectedKey(protectedKey):
#    pass


key = protectedKey()
key.name = cfg.get('key', 'name')
key.type = cfg.get('key', 'type')
key.size = cfg.getint('key', 'size')
key.crypto = cfg.get('key', 'public_crypto')
key.cipher = cfg.get('key', 'private_cipher')
key.passphrase = cfg.get('key', 'encPasswordFile')
print(key.name)
print(key.type)
print(key.size)
print(key.crypto)
print(key.cipher)
print(key.passphrase)

key.generate(cfg.get('ca', 'cmd_PrivKeyECC'))
key.verify(cfg.get('ca', 'cmd_VerifyPrivKeyECC'))

