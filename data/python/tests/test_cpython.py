# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Unit tests to verify CPython modules

Note: you must run these tests from the Ghidra script manager or headless mode
"""

import unittest
import warnings


class TestCPython(unittest.TestCase):
    def test_numpy(self):
        try:
            import numpy

            a = numpy.array(["cat", "dog"])
        except ImportError:
            warnings.warn("numpy module is not installed - ignoring test")
            pass
