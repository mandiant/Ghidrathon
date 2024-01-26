# Run Ghidrathon unit tests.
# @author Mike Hunhoff (michael.hunhoff@mandiant.com)
# @category Python 3
# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

import pathlib
import jep

path = pathlib.Path("hello.txt")
path.write_text(f"Hello from Jep {jep.__version__}", encoding="utf-8")
