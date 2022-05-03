import os
import shutil
from pathlib import Path
from helper import run, logger
from configparser import ConfigParser

cfg = ConfigParser()
cfg.read('config.ini')


def create_folder(folder):
    mode = 0o744
    if os.path.isdir(folder):
        logger.warning("Folder: %s already exists.", folder)
    else:
        try:
            os.makedirs(folder, mode)
            logger.debug("Created folder: %s", folder)
        except OSError as error:
            logger.warning(error)
        except ConfigParser.InterpolationMissingOptionError as error:
            logger.error(error)


def create_file(file):
    if os.path.isfile(file):
        logger.warning("File: %s already exists", file)
    else:
        # add index file
        if os.path.basename(file) == 'index.txt':
            logger.debug("Creating index file: %s", file)
            try:
                # touch
                with open(file, 'x') as file_object:
                    pass
            except OSError as error:
                logger.error(error)
        # add serial file
        if os.path.basename(file) == 'serial':
            logger.debug("Creating serial file: %s", file)
            try:
                with open(file, 'w') as f:
                    f.write("01")
            except OSError as error:
                logger.error(error)
        # add crlnumber file
        if os.path.basename(file) == 'crlnumber':
            logger.debug("Creating crlnumber file: %s", file)
            try:
                with open(file, 'w') as f:
                    f.write("1000")
            except OSError as error:
                logger.error(error)


def get_source(src, dest):
    shutil.copyfile(src, dest)


def backup_file(file):
    backup = file + ".bak"
    try:
        shutil.copy2(file, backup)
    except OSError as error:
        logger.error(error)


def edit_openssl(ssl, search, replace):
    # backup first
    backup_file(ssl)

    # now edit original
    input_f = open(ssl, 'r')
    output_f = open(cfg.get('misc', 'temp'), 'w')

    with input_f, output_f:
        for lines in input_f:
            line = lines.split()
            if not line or line[0] != search:
                output_f.write(lines)
            else:
                line.pop(2)
                line.insert(2, replace)
                new_line = ' '.join(line)
                output_f.write(new_line + " \n")

    # update
    try:
        shutil.copyfile(cfg.get('misc', 'temp'), ssl)
    except OSError as error:
        logger.error(error)


