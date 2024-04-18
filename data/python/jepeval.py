# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

"""Used to eval Python statements passed from Java

We use a function defined in Python versus Jep.eval in Java because it
gives us better control over handling multi-line statements
"""

jepeval_lines = []


def jepeval(line):
    """attempt to compile and eval a given Python statement

    Args:
        line (str): Python statement to compile/eval

    Returns:
        bool: True if more input needed, otherwise False
    """

    def _jepeval(line):
        """attempt to compile and eval a given Python statement

        Args:
            line (str): Python statement to compile/eval

        Returns:
            bool: True if more input needed, otherwise False
        """
        global jepeval_lines

        if not line:
            # statement may be empty e.g. user hit "enter" in console
            if jepeval_lines:
                # we have cached statements, combine and attempt to compile/eval
                source = "\n".join(jepeval_lines)
                jepeval_lines = None
                exec(compile(source, "<string>", "single"), globals(), globals())
        elif not jepeval_lines:
            # we don't have any cached statements, attempt to compile/eval single statement
            try:
                exec(compile(line, "<string>", "single"), globals(), globals())
            except (IndentationError, TabError) as err:
                # assume IndetationError/TabError indicate user's attempt to define multi-line block
                # e.g. for loop; cache statement to combine and compile/eval later
                jepeval_lines = [line]
                return True
            except SyntaxError as err:
                if err.msg == "unexpected EOF while parsing":
                    # python3.8 does not raise IndentationError, TabError so we must check for a SyntaxError
                    # with a hard-coded message
                    jepeval_lines = [line]
                    return True
                else:
                    raise err
        else:
            # we have cached statements, user must be defining a multi-line block e.g. for loop; cache
            # statement to combine and compile/eval later
            jepeval_lines.append(line)
            return True

        return False

    more_input_needed = False

    try:
        more_input_needed = _jepeval(line)
    except SystemExit as err:
        more_input_needed = False
    except Exception as err:
        # Python exceptions are printed in Python instead of Java to improve error messaging
        # in the Ghidra console window
        import traceback

        import utils

        traceback.print_exc()
        utils.log_env_details(type(err))

    return more_input_needed
