# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Inject GhidraScript methods into Python

This lets us provide Python with GhidraScript helper methods e.g. getBytes. We store these in __buitlins__ to provide access
across Python imports similar to how this works in Jython.

assumes __ghidra_script__ is passed from Java to Python prior to execution
"""

for attr in dir(__ghidra_script__):
    if attr.startswith("__"):
        # ignore private
        continue
    if attr.startswith("print"):
        # ignore helper functions for print e.g. print, println
        continue
    if attr == "java_name":
        # ignore java_name added by Jep
        continue

    o = getattr(__ghidra_script__, attr)
    if callable(o) and attr not in __builtins__:
        __builtins__[attr] = o
