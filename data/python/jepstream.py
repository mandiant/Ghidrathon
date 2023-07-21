# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Redirect sys.stdout and sys.stderr to Ghidra console window

Python stdout and stderr print to Python; we want to see this output print to the Ghidra console window. To do this
we must override sys.stdout and sys.stderr with Java PrintWriters that are connected to the Ghidra console window.
"""
import sys
import io


def get_fake_io_wrapper():
    """build a TextIOWrapper referencing an empty byte array

    we set the encoding to the system default in hopes this doesn't cause issues when sending text from Python to Java
    """
    return io.TextIOWrapper(io.BytesIO(b""), encoding=sys.getdefaultencoding())


# sys.stdout and sys.stderr may be None (see https://docs.python.org/3/library/sys.html#sys.__stdout__); therefore
# we must set these to an object that has enough functionality to emulate basic write functionality. we create a
# TextIOWrapper referencing an empty byte array and override the write method with the write method of our Java
# PrintWriters connected to the Ghidra console window. hopefully this is good enough but we may run into issues in the
# future if Python code tries to reference unexpected methods/members e.g. "encoding"


if not sys.stdout:
    sys.stdout = get_fake_io_wrapper()

if not sys.stderr:
    sys.stderr = get_fake_io_wrapper()


# assumes GhidraPluginToolConsoleOut/ErrWriter are passed from Java to Python before execution


sys.stdout.write = GhidraPluginToolConsoleOutWriter.write
sys.stderr.write = GhidraPluginToolConsoleErrWriter.write
