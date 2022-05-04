import os
import logging
import subprocess
import sys
import argparse
from configparser import ConfigParser

cfg = ConfigParser()
cfg.read('config.ini')

projectLocation = os.getcwd()
logfile = os.path.join(projectLocation, 'debug.log')
log_format = (
    "[%(asctime)s] %(levelname)-8s %(name)-12s %(message)s [%(filename)s %(lineno)d]")

parser = argparse.ArgumentParser()

parser.add_argument('-l', '--log',
                    choices=('error', 'warning', 'debug'),
                    dest='level',
                    #default='warning',
                    help='Sets the logging level',
                    type=str
                    )
parser.add_argument('--version', action='version', version='%(prog)s 0.9')
parser.add_argument('-cn', '--common',
                    dest='common',
                    help='Sets the Common Name in openssl config',
                    type=str
                    )
args = parser.parse_args()

logging.basicConfig(
    level=logging.WARNING,
    format=log_format,
    handlers=[
        logging.FileHandler(logfile),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger("cert_logger")

# cli args overrule cfg
if cfg.get('runtime', 'log_level') == 'debug':
    logger.setLevel(logging.DEBUG)
if cfg.get('runtime', 'log_level') == 'warning':
    logger.setLevel(logging.WARNING)
if cfg.get('runtime', 'log_level') == 'error':
    logger.setLevel(logging.ERROR)
if args.level == "debug":
    logger.setLevel(logging.DEBUG)
if args.level == "warning":
    logger.setLevel(logging.WARNING)
if args.level == "error":
    logger.setLevel(logging.ERROR)


# https://docs.python.org/3.8/library/subprocess.html#
def run(cmd):
    rc = 0

    try:
        sp = subprocess.Popen(cmd,
                              shell=False,
                              stdin=subprocess.PIPE,
                              stdout=subprocess.PIPE,
                              stderr=subprocess.PIPE,
                              text=True)
        output, error = sp.communicate(timeout=10)
        rc = sp.wait()
        if rc == 0:
            logger.debug(output)
        else:
            logger.error(error)
    except subprocess.CalledProcessError as e:
        logger.error("CalledProcessError: %s", e.output)
        logger.error("OpenSSL Return code: %s", e.returncode)
    except subprocess.TimeoutExpired as e:
        logger.error("TimeoutExpired: %s", e.output)

    return rc


def verify_rootca_database(index):
    with open(index, "r+") as f:
        print("\nIndex file entry\n----------------")
        print(f.read())


def verify_crl_serial(crl):
    with open(crl, "r+") as f:
        print("\nCRL file entry\n----------------")
        print(f.read())

    with open(cfg.get('installation', 'crlnumberFile'), "r+") as f:
        print("\nCRL index entry\n----------------")
        print(f.read())
