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
    "[%(asctime)s] %(levelname)-8s %(name)-12s %(message)s")

parser = argparse.ArgumentParser()

parser.add_argument('-l', '--log',
                    choices=('error', 'debug'),
                    dest='level',
                    default='error',
                    help='Sets the logging level',
                    type=str
                    )
parser.add_argument('--version', action='version', version='%(prog)s 0.7')
args = parser.parse_args()

logging.basicConfig(
    level=logging.ERROR,
    format=log_format,
    handlers=[
        logging.FileHandler(logfile),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger("cert_logger")

# cli args overrule cfg
if cfg.getboolean('debug', 'log_debug'):
    logger.setLevel(logging.DEBUG)
if args.level == "debug":
    logger.setLevel(logging.DEBUG)


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
