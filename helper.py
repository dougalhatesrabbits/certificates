import os
import logging
import subprocess
import sys

projectLocation = os.getcwd()

logfile = os.path.join(projectLocation, 'debug.log')
log_format = (
    '[%(asctime)s] %(levelname)-8s %(name)-12s %(message)s')

logging.basicConfig(
    level=logging.DEBUG,
    # Define the format of log messages
    format=log_format,
    handlers=[
        logging.FileHandler(logfile),
        logging.StreamHandler(sys.stdout),
    ]
)
# Define logger name
logger = logging.getLogger("cert_logger")


def run(cmd):
    sp = subprocess.run(cmd,
                        shell=False,
                        check=True,
                        capture_output=True,
                        text=True)
    print("stdout: ", sp.stdout)
    print("stderr: ", sp.stderr)
    logger.error(sp.stderr)
