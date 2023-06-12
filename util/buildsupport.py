# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import os
import subprocess
import argparse
import logging
import shutil
import glob
import sys
import platform
import zipfile
import tempfile
import re

from pathlib import Path

JEP_PY_FOLDER_NAME = "jep"
JEP_OS_LIB_NAME_WINDOWS = "jep.dll"
JEP_OS_LIB_NAME_LINUX = "libjep.so"
JEP_OS_LIB_NAME_DARWIN = "jep.cpython-%d%d-darwin.so" % sys.version_info[:2]
JEP_OS_LIB_NAME_DARWIN_M1 = "libjep.jnilib"

GHIDRA_JAVA_LIB_PATH = "lib"
GHIDRA_OS_LIB_PATH_WINDOWS = "os/win_x86_64/jep.dll"
GHIDRA_OS_LIB_PATH_LINUX = "os/linux_x86_64/libjep.so"
GHIDRA_OS_LIB_PATH_DARWIN = "os/mac_x86_64/libjep.so"
GHIDRA_OS_LIB_PATH_DARWIN_M1 = "os/mac_arm_64/libjep.jnilib"

RE_DIST_NAME = re.compile(r"ghidra_(?P<version>[\d\.]+)_PUBLIC_\d+_(?P<name>.+)\.zip")

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

def rename_jep_jnilib(zip_path):
    """renames libjep.jnilib to jep.dll for Mac M1"""
    # creates a temporary directory, extracts contents of distro to it
    # renames os/mac_arm_64/libjep.jnilib to jep.dll
    # overwrites distro with new zipfile
    # inefficient because renaming files in zipfiles is annoying
    logger.debug("Renaming jep binaries in distro...")
    name = os.path.basename(zip_path)
    match = RE_DIST_NAME.search(name)
    if not match:
        logger.error(f"Ghidrathon archive not found! {name}")
        return -1
    ghidra_version = match.group('version')
    ghidrathon_name = match.group('name')
    with tempfile.TemporaryDirectory() as tmpdirname:
        tmpdir = Path(tmpdirname)
        with zipfile.ZipFile(zip_path, mode='r') as distro:
            distro.extractall(tmpdirname)
        os.remove(zip_path)
        os.rename(
            f"{tmpdirname}/{ghidrathon_name}/os/mac_arm_64/libjep.jnilib",
            f"{tmpdirname}/{ghidrathon_name}/os/mac_arm_64/jep.dll"
        )
        logger.debug("repacking distro...")
        with zipfile.ZipFile(zip_path, mode='w') as newdistro:
            for path in tmpdir.rglob(f'*'):
                logger.debug(str(path.relative_to(tmpdir)))
                newdistro.write(path, arcname=path.relative_to(tmpdir))
    logger.info("renamed jep binaries.")
    return 0


def pre_build(args):
    """Locate Jep module directory and copy necessary files to Ghidrathon extension directories."""
    if args.debug:
        logger.setLevel(logging.DEBUG)

    if sys.platform in ("darwin",):
        logger.debug("Detected macOS")
        arch = platform.machine()
        if arch == "arm64":
            logger.debug("Detected M1")
            os_lib_name = JEP_OS_LIB_NAME_DARWIN_M1
            os_lib_path = Path(GHIDRA_OS_LIB_PATH_DARWIN_M1)
        else:
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


def post_build(args):
    """do post-build actions (install to ghidra, etc.)"""
    logger.info("Running post-build script")
    if args.debug:
        logger.setLevel(logging.DEBUG)

    distro_path = max(glob.glob("dist/*.zip"), key=os.path.getctime)

    if sys.platform == 'darwin' and platform.machine() == 'arm64':
        logger.info("Detected Mac M1")
        # do file rewrites for Mac M1
        # get most recently built distribution
        rename_jep_jnilib(distro_path)

    if args.ghidra_dir:
        # extract distro to Ghidra/extensions
        extensions_dir = Path(args.ghidra_dir) / 'Ghidra' / 'Extensions'
        with zipfile.ZipFile(distro_path, mode='r') as distro:
            distro.extractall(extensions_dir)


if __name__ == "__main__":
    """ """
    parser = argparse.ArgumentParser(
        description="pre-build and post-build support scripts"
    )
    parser.add_argument("-d", "--debug", action="store_true", help="Show debug messages")

    subparsers = parser.add_subparsers(dest="script", help='sub-command help')
    
    pre_parser = subparsers.add_parser('prebuild', help="run prebuild script (configure jep native binaries)")
    pre_parser.add_argument("-p", "--path", type=str, help="Full path to Jep Python module directory")
    
    post_parser = subparsers.add_parser('postbuild', help="run postbuild script")
    post_parser.add_argument("--ghidra-install-dir", type=str, dest="ghidra_dir", default=None,
        help="ghidra install directory (automatically install Ghidrathon extension if provided)")

    args = parser.parse_args()

    if args.script == 'prebuild':
        sys.exit(pre_build(args))
    elif args.script == 'postbuild':
        sys.exit(post_build(args))
