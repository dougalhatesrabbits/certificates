import os
import logging
import subprocess
import sys

TODO: "Encrypt log file possibly. Private keys are password protected with encrypted password file though. " \
      "Only relevant for non password protected key option!"

projectLocation = os.getcwd()
logfile = os.path.join(projectLocation, 'debug.log')
log_format = (
    "[%(asctime)s] %(levelname)-8s %(name)-12s %(message)s")

logging.basicConfig(
    level=logging.DEBUG,
    format=log_format,
    handlers=[
        logging.FileHandler(logfile),
        logging.StreamHandler(sys.stdout),
    ]
)
logger = logging.getLogger("cert_logger")


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
        if output:
            logger.debug(output)
        if error:
            logger.error(error)
    except subprocess.CalledProcessError as e:
        logger.error(e.output)
        logger.error("OpenSSL Return code: %s", e.returncode)
    except subprocess.TimeoutExpired as e:
        logger.error(e.output)

    return rc


