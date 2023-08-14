# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

__cache_key__ = "__ghidrathon_cached_state__"
__ghidrathon_flatapi_wrapper_stub_template__ = """@__ghidrathon_flatapi_wrapper__\ndef %s(*args, **kwargs): ..."""


class __GhidrathonCachedState__(object):
    def __init__(self, script, stdout, stderr):
        self.script = script
        self.stdout = stdout
        self.stderr = stderr


def __get_java_thread__():
    from java.lang import Thread

    return Thread.currentThread().getId()


def __get_cache__():
    cache = __builtins__.get(__cache_key__, None)
    if cache is None:
        raise RuntimeError("__builtins__ key %s does not exist!" % __cache_key__)

    return cache


def __get_cached_state__():
    cache = __get_cache__()

    state = cache.get(__get_java_thread__(), None)
    if state is None:
        raise RuntimeError("__builtins__[%s] key %s does not exist!" % (__cache_key__, __get_java_thread__()))

    return state


def __get_cached_state_script__():
    script = __get_cached_state__()
    if script is None:
        raise RuntimeError("GhidraScript is None!")
    return script.script


def __get_cached_state_script_state__():
    state = __get_cached_state_script__().getState()
    if state is None:
        raise RuntimeError("GhidraState is None!")

    return state


def __set_state__(script, stdout, stderr):
    """set the GhidraScript object for the current Java thread"""
    __builtins__[__cache_key__][__get_java_thread__()] = __GhidrathonCachedState__(script, stdout, stderr)


def __unset_state__():
    """unset the GhidraScript object for the current Java thread"""
    cache = __get_cache__()
    del cache[__get_java_thread__()]


def __ghidrathon_flatapi_wrapper__(func):
    def wrapped(*args, **kwargs):
        return getattr(__get_cached_state_script__(), func.__name__)(*args, **kwargs)

    return wrapped


def __ghidrathon_monitor_wrapper__():
    return __get_cached_state_script__().getMonitor()


def __ghidrathon_currentProgram_wrapper__():
    return __get_cached_state_script_state__().getCurrentProgram()


def __ghidrathon_currentAddress_wrapper__():
    return __get_cached_state_script_state__().getCurrentAddress()


def __ghidrathon_currentLocation_wrapper__():
    return __get_cached_state_script_state__().getCurrentLocation()


def __ghidrathon_currentSelection_wrapper__():
    return __get_cached_state_script_state__().getCurrentSelection()


def __ghidrathon_currentHighlight_wrapper__():
    return __get_cached_state_script_state__().getCurrentHighlight()


def __ghidrathon_stdout_writer_wrapper__(*args, **kwargs):
    state = __get_cached_state__()
    if state.stdout is None:
        raise RuntimeError("GhidraScript stdout is None!")

    return state.stdout.write(*args, **kwargs)


def __ghidrathon_stderr_writer_wrapper__(*args, **kwargs):
    state = __get_cached_state__()
    if state.stderr is None:
        raise RuntimeError("GhidraScript stderr is None!")

    return state.stderr.write(*args, **kwargs)


def __set_io_writer_wrappers__():
    import sys

    def get_fake_io_wrapper():
        """build a TextIOWrapper referencing an empty byte array

        we set the encoding to the system default in hopes this doesn't cause issues when sending text from Python to Java
        """
        import io

        return io.TextIOWrapper(io.BytesIO(b""), encoding=sys.getdefaultencoding())

    # sys.stdout and sys.stderr may be None (see https://docs.python.org/3/library/sys.html#sys.__stdout__); therefore
    # we must set these to an object that has enough functionality to emulate basic write functionality. we create a
    # TextIOWrapper referencing an empty byte array and override the write method with the write method of our Java
    # PrintWriters connected to the Ghidra console window. hopefully this is good enough but we may run into issues in the
    # future if Python code tries to reference unexpected methods/members e.g. "encoding"
    if sys.stdout is None:
        sys.stdout = get_fake_io_wrapper()

    if sys.stderr is None:
        sys.stderr = get_fake_io_wrapper()

    # set sys.stdout.write and sys.stderr.write wrappers
    sys.stdout.write = __ghidrathon_stdout_writer_wrapper__
    sys.stderr.write = __ghidrathon_stderr_writer_wrapper__


__set_io_writer_wrappers__()


def __set_flatapi_wrappers__():
    import ghidra.app.script

    for attr in dir(ghidra.app.script.GhidraScript):
        if attr.startswith("__"):
            continue

        if attr in __builtins__:
            continue

        if attr.startswith("print"):
            continue

        attr_o = getattr(ghidra.app.script.GhidraScript, attr)
        if not callable(attr_o):
            continue

        # dynamically generate wrapper stub using attribute name
        exec(__ghidrathon_flatapi_wrapper_stub_template__ % attr, globals())

        # add dynamically generated wrapper stub to __builtins__
        __builtins__[attr] = globals()[attr]


__set_flatapi_wrappers__()


def __set_state_wrappers__():
    __builtins__["monitor"] = __ghidrathon_monitor_wrapper__
    __builtins__["currentProgram"] = __ghidrathon_currentProgram_wrapper__
    __builtins__["currentAddress"] = __ghidrathon_currentAddress_wrapper__
    __builtins__["currentLocation"] = __ghidrathon_currentLocation_wrapper__
    __builtins__["currentSelection"] = __ghidrathon_currentSelection_wrapper__
    __builtins__["currentHighlight"] = __ghidrathon_currentHighlight_wrapper__


__set_state_wrappers__()


def __set_builtins_cache__():
    if __cache_key__ not in __builtins__:
        __builtins__[__cache_key__] = {}


__set_builtins_cache__()
