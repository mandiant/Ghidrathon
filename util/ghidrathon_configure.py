# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import argparse
import pathlib
import logging
import sys


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

    install_path: pathlib.Path = args.ghidrathon_install_directory
    if not all((install_path.exists(), install_path.is_dir())):
        logger.error('"%s" does not exist or is not a directory.', str(install_path))
        return

    save_path: pathlib.Path = install_path / "ghidrathon.save"
    try:
        save_path.write_text(sys.executable, encoding="utf-8")
        logger.debug('Wrote "%s" to "%s".', sys.executable, str(save_path))
        logger.info("Please restart Ghidra for these changes to take effect.")
    except Exception as e:
        logger.error('Failed to write "%s" to "%s" (%s).', sys.executable, str(save_path), e)
        return -1

    return 0


if __name__ == "__main__":
    """ """
    parser: argparse.ArgumentParser = argparse.ArgumentParser(description="Configure the running Python interpreter for Ghidrathon")

    parser.add_argument("ghidrathon_install_directory", type=pathlib.Path, help="Absolute path of Ghidra install directory")
    parser.add_argument("-d", "--debug", action="store_true", help="Show debug messages")

    sys.exit(main(parser.parse_args()))
