# Run Ghidrathon unit tests.
# @author Mike Hunhoff (michael.hunhoff@mandiant.com)
# @category Python 3
# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
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


def main():
    loader = unittest.TestLoader()
    result = unittest.TestResult()

    directory = str(pathlib.Path(__file__).resolve().parent)

    suite = loader.discover(directory, pattern="test_*.py")
    _ = unittest.TextTestRunner(verbosity=2, failfast=True).run(suite)


if __name__ == "__main__":
    main()

    print(currentProgram)
