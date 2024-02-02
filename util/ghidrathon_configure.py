# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import sys
import json
import logging
import pathlib
import argparse
import importlib.util
from typing import Dict

SUPPORTED_JEP_VERSION = "4.2.0"
PYTHON_HOME_DIR_KEY = "home"
PYTHON_EXECUTABLE_FILE_KEY = "executable"

logger = logging.getLogger(__name__)

handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s")

handler.setFormatter(formatter)

logger.addHandler(handler)
logger.setLevel(logging.INFO)


def main(args):
    """ """
    if args.debug:
        logger.setLevel(logging.DEBUG)

    jep_spec = importlib.util.find_spec("jep")
    if jep_spec is None:
        logger.error(
            "Jep is not installed. Please install Jep using the requirements.txt file before configuring Ghidrathon."
        )
        return -1

    jep_version_file: pathlib.path = pathlib.Path(jep_spec.origin).parent / "version.py"
    if not all((jep_version_file.exists(), jep_version_file.is_file())):
        logger.error(
            "Jep file %s is not valid. Please verify your Jep install is correct before configuring Ghidrathon.",
            jep_version_file,
        )
        return -1

    logger.debug('Verifying Jep version.py file located at "%s".', jep_version_file)

    if SUPPORTED_JEP_VERSION not in jep_version_file.read_text(encoding="utf-8"):
        logger.error(
            "Jep version is not supported. Please install Jep version %s before configuring Ghidrathon.",
            SUPPORTED_JEP_VERSION,
        )
        return -1

    install_path: pathlib.Path = args.ghidrathon_install_directory
    if not all((install_path.exists(), install_path.is_dir())):
        logger.error(
            'Ghidra install directory "%s" is not valid. Please specify the absolute path of your Ghidra install directory.',
            install_path,
        )
        return -1

    ghidrathon_save: Dict[str, str] = {}

    python_path: pathlib.Path = pathlib.Path("None" if not sys.executable else sys.executable)
    if not all((python_path.exists(), python_path.is_file())):
        logger.error(
            'sys.executable value "%s" is not valid. Please verify your Python environment is correct before configuring Ghidrathon.',
            python_path,
        )
        return -1

    ghidrathon_save[PYTHON_EXECUTABLE_FILE_KEY] = str(python_path)
    logger.debug('Using Python interpreter located at "%s".', python_path)

    home_path: pathlib.Path = pathlib.Path("None" if not sys.base_prefix else sys.base_prefix)
    if not all((home_path.exists(), home_path.is_dir())):
        logger.error(
            'sys.base_prefix value "%s" is not valid. Please verify your Python environment is correct before configuring Ghidrathon.',
            home_path,
        )
        return -1

    ghidrathon_save[PYTHON_HOME_DIR_KEY] = str(home_path)
    logger.debug('Using Python home located at "%s".', home_path)

    json_: str = json.dumps(ghidrathon_save)
    save_path: pathlib.Path = install_path / "ghidrathon.save"
    try:
        save_path.write_text(json_, encoding="utf-8")
    except Exception as e:
        logger.error('Failed to write "%s" to "%s" (%s).', json_, save_path, e)
        return -1

    try:
        logger.debug("Python configuration:")
        logger.debug("Python %s", sys.version)

        for k, v in {
            "sys.executable": sys.executable,
            "sys._base_executable": sys._base_executable,
            "sys.prefix": sys.prefix,
            "sys.base_prefix": sys.base_prefix,
            "sys.exec_prefix": sys.exec_prefix,
            "sys.base_exec_prefix": sys.base_exec_prefix,
        }.items():
            logger.debug('%s: "%s"', k, v)
    except Exception as e:
        logger.error(
            "Failed to verify Python environment (%s). Please verify your Python environment is correct before configuring Ghidrathon.",
            e,
        )
        return -1

    logger.debug('Wrote "%s" to "%s".', json_, save_path)
    logger.info(
        "Ghidrathon has been configured to use this Python interpreter. Please restart Ghidra for these changes to take effect."
    )

    return 0


if __name__ == "__main__":
    """ """
    parser: argparse.ArgumentParser = argparse.ArgumentParser(
        description="Configure the running Python interpreter for Ghidrathon"
    )

    parser.add_argument(
        "ghidrathon_install_directory", type=pathlib.Path, help="Absolute path of Ghidra install directory"
    )
    parser.add_argument("-d", "--debug", action="store_true", help="Show debug messages")

    sys.exit(main(parser.parse_args()))
