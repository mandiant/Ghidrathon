# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import sys
import os
import glob
import logging
import shutil

from pathlib import Path

JEP_PY_PACKAGE_NAME = "jep"
JEP_OS_LIB_NAMES = {
    "darwin": ("jep",    "so"),
    "linux":  ("libjep", "so"),
    "win32":  ("jep",    "dll"),
    "cygwin": ("jep",    "dll"),
}

GHIDRA_JAVA_LIB_PATH = "lib"
GHIDRA_OS_LIB_PATH = "os"
GHIDRA_OS_LIB_NAMES = {
    "darwin": "mac_",
    "linux":  "linux_",
    "win32":  "win_",
    "cygwin": "win_",
}


logger = logging.getLogger(__name__)

handler = logging.StreamHandler()
formatter = logging.Formatter("%(asctime)s %(levelname)-8s %(message)s")

handler.setFormatter(formatter)

logger.addHandler(handler)
logger.setLevel(logging.INFO)


def pathglob(root, pattern):
    return [root / fn for fn in glob.glob(pattern, root_dir=str(root))]

def find_package_files(pkgname, pattern, fallback_dir = None):
    """attempt to locate file(s) in package resources,
    using importlib.metadata, pkg_resources and finally a naive search"""
    try:
        import importlib.metadata
    except ImportError:
        pass
    else:
        pkg_files = importlib.metadata.files(pkgname)
        if pkg_files is not None:
            return [f.locate() for f in pkg_files if f.match(pattern)]

    try:
        import pkg_resources
    except ImportError:
        pass
    else:
        dist = pkg_resources.get_distribution(pkgname)
        if dist:
            pkg_dir = Path(dist.location) / dist.key
            return pathglob(pkg_dir, pattern)

    for path in sys.path:
        pkg_dir = Path(path) / pkgname
        logger.debug("Checking if %s exists" % pkg_dir)
        if pkg_dir.is_dir():
            return pathglob(pkg_dir, pattern)

    if fallback_dir:
        return pathglob(fallback_dir, pattern)
    raise ValueError("could not determine paths for package %s" % pkgname)


def copyfile(src, dest):
    logger.info("Copying %s to %s" % (src, dest))
    shutil.copy(str(src), str(dest), follow_symlinks=True)

def main(args):
    """ """
    if args.debug:
        logger.setLevel(logging.DEBUG)
    if args.path:
        fallback_dir = Path(args.path)
    else:
        fallback_dir = None

    # Get Jep OS names
    if sys.platform in JEP_OS_LIB_NAMES:
        jep_os_lib_prefix, jep_os_lib_ext = JEP_OS_LIB_NAMES[sys.platform]
    else:
        logger.error("Unsupported platform: %s" % sys.platform)
        return -1

    # Get Ghidra names
    ghidra_lib_path = Path(GHIDRA_JAVA_LIB_PATH)
    if sys.platform in GHIDRA_OS_LIB_NAMES:
        ghidra_os_lib_path = Path(GHIDRA_OS_LIB_PATH) / (GHIDRA_OS_LIB_NAMES[sys.platform] + os.uname().machine)
    else:
        logger.error("Unsupported platform: %s" % sys.platform)
        return -1


    logger.info("Searching for Jep JAR file")
    jep_java_lib_paths = find_package_files(JEP_PY_PACKAGE_NAME, "*.jar", fallback_dir)
    if not jep_java_lib_paths:
        logger.error("Could not find Jep JAR file")
        return -1
    # copy the Jep JAR file to the appropriate extension folder
    copyfile(jep_java_lib_paths[0], ghidra_lib_path)


    logger.info("Searching for Jep native library")
    jep_os_lib_name = "%s.%s" % (jep_os_lib_prefix, jep_os_lib_ext)
    jep_os_lib_paths = find_package_files(JEP_PY_PACKAGE_NAME, jep_os_lib_name, fallback_dir)
    if not jep_os_lib_paths and sys.implementation.cache_tag:
        jep_os_lib_impl_name = "%s%s.%s" % (
            jep_os_lib_prefix,
            '.%s-*' % sys.implementation.cache_tag,
            jep_os_lib_ext
        )
        jep_os_lib_paths = find_package_files(JEP_PY_PACKAGE_NAME, jep_os_lib_impl_name, fallback_dir)
    if not jep_os_lib_paths:
        logger.error("Could not find Jep native library")
        return -1
    # copy the Jep OS-dependent file to the appopriate extension folder
    copyfile(jep_os_lib_paths[0], ghidra_os_lib_path / jep_os_lib_name)


    logger.info("Done")
    return 0


if __name__ == "__main__":
    """ """
    import argparse
    parser = argparse.ArgumentParser(
        description="Locate Jep module directory and copy necessary files to Ghidrathon extension directories."
    )

    parser.add_argument("-p", "--path", type=str, help="Fallback path to Jep Python module directory")
    parser.add_argument("-d", "--debug", action="store_true", help="Show debug messages")

    sys.exit(main(parser.parse_args()))
