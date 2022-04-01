# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Print a welcome message to the console window

We use a small Python script to print a welcome message to the Ghidra console window. This
should only be called after the Jep subinterpreter has been configured.
"""

import sys


message = """
   _____ _     _     _           _   _                 
  / ____| |   (_)   | |         | | | |                
 | |  __| |__  _  __| |_ __ __ _| |_| |__   ___  _ __  
 | | |_ | '_ \| |/ _` | '__/ _` | __| '_ \ / _ \| '_ \ 
 | |__| | | | | | (_| | | | (_| | |_| | | | (_) | | | |
  \_____|_| |_|_|\__,_|_|  \__,_|\__|_| |_|\___/|_| |_|
                                                       
Python %s Interpreter for Ghidra. Developed by FLARE.
"""


def format_version():
    """ """
    return "%d.%d.%d" % sys.version_info[:3]


print(message % format_version())
