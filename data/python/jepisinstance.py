# Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Proxy Python isinstance and issubclass calls

See Jep: https://github.com/ninia/jep/issues/438
Note: we should remove this code when Jep https://github.com/ninia/jep/pull/440 is merged and released
"""

import builtins

_saved_isinstance = builtins.isinstance
_saved_issubclass = builtins.issubclass


def _proxy_isinstance(obj, classinfo):
    if "jep.PyJClass" in str(type(classinfo)):
        classinfo = classinfo.__pytype__
    return _saved_isinstance(obj, classinfo)


def _proxy_issubclass(obj, classinfo):
    if "jep.PyJClass" in str(type(obj)):
        obj = obj.__pytype__
    if "jep.PyJClass" in str(type(classinfo)):
        classinfo = classinfo.__pytype__
    return _saved_issubclass(obj, classinfo)


builtins.isinstance = _proxy_isinstance
builtins.issubclass = _proxy_issubclass
