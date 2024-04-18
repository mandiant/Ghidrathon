import sys
import platform

import jep
import ghidrathon
from java.lang import System

ALLOWED_EXCEPTIONS = [RuntimeError, OSError]


def log_env_details(exc_type):
    if any(issubclass(exc_type, exc_class) for exc_class in ALLOWED_EXCEPTIONS):
        print(
            "Python={python_version}, Arch={arch}, OS={os}, Ghidra={ghidra_version}, Java={java_version}, Ghidrathon={ghidrathon_version}, Jep={jep_version}".format(
                python_version=platform.python_version(),
                arch=System.getProperty("os.arch"),
                os=System.getProperty("os.name"),
                ghidra_version=getGhidraVersion(),
                java_version=System.getProperty("java.version"),
                ghidrathon_version="4.0.0",
                jep_version=jep.__version__,
            ),
            file=sys.stderr,
        )
