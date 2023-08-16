# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Unit tests to verify Ghidra Jep bridge

Note: you must run these tests from the Ghidra script manager or headless mode
"""

import unittest


class TestJepBridge(unittest.TestCase):
    def assertIsJavaObject(self, o):
        from java.lang import Object

        if not (o is None or isinstance(o, Object)):
            raise AssertionError("Object %s is not valid" % str(o))

    def assertIsNotJavaObject(self, o):
        from java.lang import Object

        if isinstance(o, Object):
            raise AssertionError("Object %s is not valid" % str(o))

    def test_type_instance(self):
        # see Jep: https://github.com/ninia/jep/blob/15e36a7ba54eb7d8f7ffd85f16675fa4fd54eb1d/src/test/python/test_import.py#L54-L65
        from java.lang import Object
        from java.io import Serializable
        from java.util import Date
        from ghidra.program.database import ProgramDB

        self.assertIsInstance(Date(), Object.__pytype__)
        self.assertIsInstance(Date(), Serializable.__pytype__)
        self.assertTrue(issubclass(Date.__pytype__, Object.__pytype__))
        self.assertTrue(issubclass(Date.__pytype__, Serializable.__pytype__))
        self.assertIsInstance(Date(), Object)
        self.assertIsInstance(Date(), Serializable)
        self.assertTrue(issubclass(Date, Object))
        self.assertTrue(issubclass(Date, Serializable))
        self.assertIsInstance(currentProgram(), ProgramDB)

    def test_ghidra_script_variables(self):
        self.assertIsJavaObject(monitor())
        self.assertIsJavaObject(currentAddress())
        self.assertIsJavaObject(currentProgram())
        self.assertIsJavaObject(currentLocation())
        self.assertIsJavaObject(currentHighlight())
        self.assertIsJavaObject(currentSelection())

    def test_ghidra_script_methods(self):
        self.assertIsInstance(getGhidraVersion(), str)

    def test_java_excluded_packages(self):
        import pdb

        self.assertIsNotJavaObject(pdb)
