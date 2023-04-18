# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import subprocess
import argparse
import logging
import shutil
import glob
import sys

from pathlib import Path

JEP_PY_FOLDER_NAME = "jep"
JEP_OS_LIB_NAME_WINDOWS = "jep.dll"
JEP_OS_LIB_NAME_LINUX = "libjep.so"
JEP_OS_LIB_NAME_DARWIN = "jep.cpython-%d%d-darwin.so" % sys.version_info[:2]

GHIDRA_JAVA_LIB_PATH = "lib"
GHIDRA_OS_LIB_PATH_WINDOWS = "os/win_x86_64/jep.dll"
GHIDRA_OS_LIB_PATH_LINUX = "os/linux_x86_64/libjep.so"
GHIDRA_OS_LIB_PATH_DARWIN = "os/mac_x86_64/libjep.so"


logger = logging.getLogger(__name__)

handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s")

handler.setFormatter(formatter)

logger.addHandler(handler)
logger.setLevel(logging.INFO)


def find_jep_dir():
    """attempt to locate Jep Python module directory

    we use naive method of checking each path in sys.path for a folder named jep
    """
    for path in sys.path:
        jep_dir = Path(path) / JEP_PY_FOLDER_NAME
        logger.debug("Checking if %s exists" % jep_dir)
        if jep_dir.is_dir():
            return jep_dir
    return Path()


def main(args):
    """ """
    if args.debug:
        logger.setLevel(logging.DEBUG)

    if sys.platform in ("darwin",):
        logger.debug("Detected macOS")

        os_lib_name = JEP_OS_LIB_NAME_DARWIN
        os_lib_path = Path(GHIDRA_OS_LIB_PATH_DARWIN)
    elif sys.platform in ("win32", "cygwin"):
        logger.debug("Detected Windows OS")

        os_lib_name = JEP_OS_LIB_NAME_WINDOWS
        os_lib_path = Path(GHIDRA_OS_LIB_PATH_WINDOWS)
    else:
        logger.debug("Detected Linux OS")

        os_lib_name = JEP_OS_LIB_NAME_LINUX
        os_lib_path = Path(GHIDRA_OS_LIB_PATH_LINUX)

    logger.info("Searching for Jep Python module directory")

    if args.path:
        jep_dir = Path(args.path)
        if not jep_dir.is_dir():
            logger.error("Python module directory %s does not exist!" % args.path)
            return -1
    else:
        jep_dir = find_jep_dir()
        if not jep_dir:
            logger.error("Could not find Jep Python module directory!")
            return -1

    logger.info("Found Jep Python module directory at %s" % jep_dir)

    try:
        jep_java_lib_name = glob.glob(str(Path(jep_dir) / "*.jar"), recursive=False)[0]
    except IndexError:
        logger.error("Could not find Jep JAR file in directory %s" % jep_dir)
        return -1

    logger.info("Copying %s and %s to extension folders" % (os_lib_name, jep_java_lib_name))

    # copy the Jep JAR file to the appropriate extension folder
    logger.debug("Copying %s to %s" % (Path(jep_dir) / jep_java_lib_name, Path(GHIDRA_JAVA_LIB_PATH)))
    try:
        shutil.copy(Path(jep_dir) / jep_java_lib_name, Path(GHIDRA_JAVA_LIB_PATH), follow_symlinks=True)
    except Exception as e:
        logger.error("%s" % e)
        return -1

    # copy the Jep OS-dependent file to the appopriate extension folder
    logger.debug("Copying %s to %s" % (Path(jep_dir) / os_lib_name, os_lib_path))
    try:
        shutil.copy(Path(jep_dir) / os_lib_name, os_lib_path, follow_symlinks=True)
    except Exception as e:
        logger.error("%s" % e)
        return -1

    logger.info("Done")

    return 0


if __name__ == "__main__":
    """ """
    parser = argparse.ArgumentParser(
        description="Locate Jep module directory and copy necessary files to Ghidrathon extension directories."
    )

    parser.add_argument("-p", "--path", type=str, help="Full path to Jep Python module directory")
    parser.add_argument("-d", "--debug", action="store_true", help="Show debug messages")

    sys.exit(main(parser.parse_args()))
