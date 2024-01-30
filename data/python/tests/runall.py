# Run Ghidrathon unit tests.
# @author Mike Hunhoff (mehunhoff@google.com)
# @category Python 3
# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Light harness used to run Python tests

Note: you must run this harness from the Ghidra script manager or headless mode
"""

import unittest
import pathlib
import sys


def main():
    loader = unittest.TestLoader()

    directory = str(pathlib.Path(__file__).resolve().parent)

    suite = loader.discover(directory, pattern="test_*.py")
    return 0 if unittest.TextTestRunner(verbosity=2, failfast=True).run(suite).wasSuccessful() else -1


if __name__ == "__main__":
    sys.exit(main())
