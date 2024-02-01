# Copyright (C) 2023 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.
import io
import os
import abc
import sys

import java.lang

cache_key = "ghidrathon_cache"
flatprogramapi_wrapper_stub = """@flatprogramapi_wrapper\ndef %s(*args, **kwargs): ..."""


class GhidrathonCachedStream:
    def __init__(self, stream, closed=False):
        self.stream = stream
        self.closed = closed


class GhidrathonCachedGhidraState:
    def __init__(self):
        self.script = None
        self.stdout = None
        self.stderr = None


def get_java_thread_id():
    return java.lang.Thread.currentThread().getId()


def get_cache():
    cache = __builtins__.get(cache_key, None)
    if cache is None:
        raise RuntimeError("__builtins__ key %s does not exist" % cache_key)

    return cache


def get_state():
    state = get_cache().get(get_java_thread_id(), None)
    if state is None:
        raise RuntimeError("__builtins__[%s] key %s does not exist" % (cache_key, get_java_thread_id()))

    return state


def get_script():
    script = get_state().script
    if script is None:
        raise RuntimeError("GhidraScript not set")

    return script


def get_script_state():
    state = get_script().getState()
    if state is None:
        raise RuntimeError("GhidraState not set")

    return state


def get_stdout():
    stdout = get_state().stdout
    if stdout is None:
        raise RuntimeError("stdout not set")

    return stdout


def get_stderr():
    stderr = get_state().stderr
    if stderr is None:
        raise RuntimeError("stderr not set")

    return stderr


def init_state():
    __builtins__[cache_key][get_java_thread_id()] = GhidrathonCachedGhidraState()


def set_script(script):
    get_state().script = script


def set_streams(stdout, stderr):
    get_state().stdout = GhidrathonCachedStream(stdout)
    get_state().stderr = GhidrathonCachedStream(stderr)


def remove_state():
    del get_cache()[get_java_thread_id()]


def flatprogramapi_wrapper(api):
    def wrapped(*args, **kwargs):
        return getattr(get_script(), api.__name__)(*args, **kwargs)

    return wrapped


class GhidrathonTextIOWrapperBase(abc.ABC):
    @abc.abstractproperty
    def __stream__(self):
        ...

    @abc.abstractproperty
    def name(self):
        ...

    @abc.abstractproperty
    def closed(self):
        ...

    @abc.abstractmethod
    def fileno(self):
        ...

    @property
    def line_buffering(self):
        """If line_buffering is True, flush() is implied when a call to write contains a newline character or a carriage return."""
        return True

    @property
    def write_through(self):
        """If write_through is True, calls to write() are guaranteed not to be buffered: any data written on the TextIOWrapper object is immediately handled to its underlying binary buffer."""
        return False

    @property
    def encoding(self):
        return sys.getdefaultencoding()

    @property
    def errors(self):
        """Pass 'strict' to raise a ValueError exception if there is an encoding error (the default of None has the same effect)"""
        return "strict"

    @property
    def mode(self):
        return "w"

    @property
    def newlines(self):
        raise io.UnsupportedOperation

    @property
    def buffer(self):
        raise io.UnsupportedOperation

    def isatty(self):
        return False

    def writable(self):
        return True

    def writelines(self, lines):
        if self.closed:
            raise ValueError("stream closed")

        for line in lines:
            self.write(line)

    def write(self, text):
        if self.closed:
            raise ValueError("stream closed")

        num_chars = self.__stream__.write(text)

        if self.line_buffering:
            if "\r" in text or "\n" in text:
                self.flush()

        return num_chars

    def flush(self):
        if self.closed:
            raise ValueError("stream closed")

        self.__stream__.flush()

    def close(self):
        if self.closed:
            return

        self.flush()
        self.closed = True

    def seekable(self):
        """Return True if the stream supports random access. If False, seek(), tell() and truncate() will raise OSError."""
        return False

    def seek(*args, **kwargs):
        raise OSError("operation not supported")

    def tell(*args, **kwargs):
        raise OSError("operation not supported")

    def truncate(*args, **kwargs):
        raise OSError("operation not supported")

    def readable(self):
        """Return True if the stream can be read from. If False, read() will raise OSError."""
        return False

    def read(*args, **kwargs):
        raise OSError("operation not supported")

    def readline(*args, **kwargs):
        raise OSError("operation not supported")

    def readlines(*args, **kwwargs):
        raise OSError("operation not supported")

    def reconfigure(*args, **kwargs):
        raise io.UnsupportedOperation

    def detach(*args, **kwargs):
        raise io.UnsupportedOperation


class GhidrathonStdoutWrapper(GhidrathonTextIOWrapperBase):
    @property
    def name(self):
        return "<stdout>"

    @property
    def __stream__(self):
        stream = get_stdout().stream
        if stream is None:
            raise RuntimeError("%s not set" % self.name)
        return stream

    @property
    def closed(self):
        return get_stdout().closed

    @closed.setter
    def closed(self, v):
        get_stdout().closed = v

    def fileno(self):
        return 1


class GhidrathonStderrWrapper(GhidrathonTextIOWrapperBase):
    @property
    def name(self):
        return "<stderr>"

    @property
    def __stream__(self):
        stream = get_stderr().stream
        if stream is None:
            raise RuntimeError("%s not set" % self.name)
        return stream

    @property
    def closed(self):
        return get_stderr().closed

    @closed.setter
    def closed(self, v):
        get_stderr().closed = v

    def fileno(self):
        return 2


sys.stdout = GhidrathonStdoutWrapper()
sys.stderr = GhidrathonStderrWrapper()


def wrap_flatprogramapi_functions():
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
        exec(flatprogramapi_wrapper_stub % attr, globals())

        # add dynamically generated wrapper stub to __builtins__
        __builtins__[attr] = globals()[attr]


wrap_flatprogramapi_functions()


def wrapped_monitor():
    return get_script().getMonitor()


def wrapped_state():
    return get_script_state()


def wrapped_script():
    return get_script()


def wrapped_currentProgram():
    return get_script_state().getCurrentProgram()


def wrapped_currentAddress():
    return get_script_state().getCurrentAddress()


def wrapped_currentLocation():
    return get_script_state().getCurrentLocation()


def wrapped_currentSelection():
    return get_script_state().getCurrentSelection()


def wrapped_currentHighlight():
    return get_script_state().getCurrentHighlight()


__builtins__["monitor"] = wrapped_monitor
__builtins__["state"] = wrapped_state
__builtins__["script"] = wrapped_script
__builtins__["currentProgram"] = wrapped_currentProgram
__builtins__["currentAddress"] = wrapped_currentAddress
__builtins__["currentLocation"] = wrapped_currentLocation
__builtins__["currentSelection"] = wrapped_currentSelection
__builtins__["currentHighlight"] = wrapped_currentHighlight

if cache_key not in __builtins__:
    __builtins__[cache_key] = {}
