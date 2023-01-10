# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Execute a Python script passed from Java

We use a function defined in Python versus Jep.runScript in Java because it gives
us better control over handling exceptions.
"""


def jep_runscript(path):
    """attempt to compiled and exec Python script file

    Args:
        path (str): full path to Python script file
    """
    with open(path, "rb") as f_in:
        # attempt to read Python script
        source = f_in.read()

    # set __file__ so child script can locate itself
    # TODO: do we need to set others?
    additional_globals = {"__file__": path}

    try:
        exec(compile(source, path, "exec"), {**globals(), **additional_globals})
    except SystemExit as err:
        print(f"Script {path} called exit with code {err.code}")
    except Exception as err:
        # Python exceptions are printed in Python instead of Java to give us better error
        # messages in the Ghidra console window
        import traceback

        traceback.print_exc()
