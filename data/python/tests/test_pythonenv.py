# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Unit tests to verify Python environment

Note: you must run these tests from the Ghidra script manager or headless mode
"""

import unittest


class TestPythonEnv(unittest.TestCase):
    def test_packaging_tags(self):
        # https://github.com/mandiant/Ghidrathon/issues/62
        from packaging.tags import platform_tags

        self.assertIsInstance(tuple(platform_tags()), tuple)
