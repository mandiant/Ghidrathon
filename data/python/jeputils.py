import sys
import platform

import jep
import ghidrathon
from java.lang import System

ALLOWED_EXCEPTIONS = (RuntimeError, OSError)


def log_env_details(exc):
    exc_type = type(exc)
    if issubclass(exc_type, ALLOWED_EXCEPTIONS):
        print(
            f"Python={platform.python_version()}, "
            f"Arch={System.getProperty('os.arch')}, "
            f"OS={System.getProperty('os.name')}, "
            f"Ghidra={getGhidraVersion()}, "
            f"Java={System.getProperty('java.version')}, "
            f"Ghidrathon={ghidrathon.GhidrathonPlugin.getVersion()}, "
            f"Jep={jep.__version__}",
            file=sys.stderr,
        )
