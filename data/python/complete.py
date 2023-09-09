import ast
import inspect
import types

import java

from ghidrathon import PythonCodeCompletionFactory


def isJavaModule(module):
    modules = ['ghidra.', 'java.']
    return any(module.startswith(name) for name in modules)


def isJavaMethod(obj):
    "Returns whether the given object is a bound method implemented in Java"
    return (isinstance(obj, types.MethodType) and hasattr(obj, '__self__') and hasattr(obj.__self__, '__module__') and isJavaModule(obj.__self__.__module__)) or obj.__class__.__name__ == "PythonCodeCompletionFactory$InspectableJavaMethod"


class CompletionObject:
    "Object returned by getObject. See the documentation of getObject"
    def __init__(self, o):
        self.obj = o

    def getmembers(self):
        "Returns the properties of the encapsulated object as a (name, value) tuple"
        if self.obj.__class__.__name__ == "PythonCodeCompletionFactory$InspectableJavaObject":
            return self.obj.getProperties()
        return inspect.getmembers(self.obj)


def getObject(value, locals):
    """
    Attempts to resolve the object that would be generated when evaluating
    the AST `value` within the local variables `locals`.
    This method does not run any python code and thus does not produce
    side effects.
    This also means we may not have enough information to determine which
    object would be produced by this expression.

    This function returns a CompletionObject if the object produced by this
    expression could be found. If not, this function returns None.

    Note: In case a method call on a Java object is processed, we return
    a `PythonCodeCompletionFactory$InspectableJavaObject` that fakes the
    properties and methods of the Java Object that would be returned if
    called. This is necessary, as calling the function could produce side
    effects.

    On a similar note, for python functions we also cannot return the actual
    object that would be returned. In this case we return the returntype of
    the function signature (if available). This should mostly work but may
    be missing properties that are dynamically assigned on such an object
    during creation. But this is currently the best we can do for python.
    """
    match value:
        case ast.Constant(literal):
            return CompletionObject(literal)
        case ast.Name(id, ctx):
            try:
                # Get object
                obj = eval(id, locals)
                return CompletionObject(obj)
            except NameError:
                return None
        case ast.Call(func, _, _):
            prop = getObject(func, locals)
            retval = None

            # Hack to introspect java methods
            if prop and isJavaMethod(prop.obj):
                retval = PythonCodeCompletionFactory.getReturnType(prop.obj.__self__, prop.obj.__name__)
                if retval and retval.getSrcClass() == java.lang.String:
                    # jep autoconverts between basic types
                    # There are more of these edge cases but this one happens the most
                    retval = ''
            # If it ain't java, we may have a python signature
            # if not, then we are lost
            elif prop and inspect.signature(prop.obj).return_annotation:
                retval = inspect.signature(prop.obj).return_annotation
            if retval:
                return CompletionObject(retval)
            return None
        case ast.Attribute(value, attr, _):
            prop = getObject(value, locals)
            props = [y for (x, y) in prop.getmembers() if x == attr]
            if props:
                # There may be multiple functions with different signatures
                # This only happens when those members are reported through
                # PythonCodeCompletionFactory$InspectableJavaObject.getProperties()
                # and not when inspected via python
                # This is bad for our cause, but we just have to live with that
                # Just pick one, we don't check the signature anyways
                # And luckily they all have the same return type
                return CompletionObject(props[0])
            return None
        case ast.Subscript | ast.ListComp | ast.SetComp | ast.GeneratorExp | ast.DictComp:
            # TODO, can we handle this?
            return None
        case default:
            raise ValueError(f"I don't know how to handle '{ast.dump(default)}' (getObject)")


def getProperties(value, locals):
    """
    Returns a list of properties of the AST given by `value` when evaluated
    within the local variables `locals`
    Each entry of the returned list is of the form (name, prop).
    `name` is a string and `prop` is the value of that property.
    Because we do not actually run this code, we may not have enough
    information to offer introspection for this value. In this case
    the resulting list is empty
    """
    prop = getObject(value, locals)
    if prop:
        return prop.getmembers()
    return []


def getVariables(locals):
    """
    Returns all variables in the local scope and the builtins.
    That is because most of the jepwrappers are bound to the builtins...
    And thus don't show up in the local scope
    """
    return [(x, locals[x]) for x in locals if locals[x] != locals] + \
        [(x, __builtins__[x]) for x in __builtins__]


def makeCompletions(values, prefix=''):
    """
    Returns a list of CodeCompletion objects for all properties in the list
    that start with the given prefix.
    """
    return [PythonCodeCompletionFactory.newCodeCompletion(name, name[len(prefix):], value)
            for name, value in values if name.startswith(prefix)]


def completeAST(parsed, locals, needs_property):
    """
    Tries to provide autocompletion suggestions for the AST given by `parsed`
    with the variables in scope given by locals.
    Due to the way we have to handle property access, we need
    a special case when the original input ended with a trailing point.
    Therefore if `needs_property` is True, we return the properties of
    the object returned if the given AST were to be evaluated.
    If `needs_property` is False instead, we treat the last property access
    in the AST as unfinished and report all properties that start with the last
    property name as a prefix.
    See the complete function for more information
    """
    match parsed:
        case ast.Constant(literal):
            if needs_property:
                return makeCompletions(getProperties(parsed, locals))
            return []
        case ast.Expr(value):
            return completeAST(value, locals, needs_property)
        case ast.UnaryOp(_, operand):
            return completeAST(operand, locals, needs_property)
        case ast.BinOp(_, _, right):
            return completeAST(right, locals, needs_property)
        case ast.BoolOp(_, values):
            return completeAST(values[-1], locals, needs_property)
        case ast.Compare(_, _, comparators):
            return completeAST(comparators, locals, needs_property)
        case ast.Name(id, _):
            if needs_property:
                return makeCompletions(getProperties(parsed, locals))
            return makeCompletions(getVariables(locals), id)
        case ast.Call(func, _, _):
            if needs_property:
                return makeCompletions(getProperties(parsed, locals))
            # This is a valid function call and not an unfinished fragment
            # There is nothing to complete
            return []
        case ast.IfExp(_, _, orelse):
            return completeAST(orelse, locals, needs_property)
        case ast.Attribute(value, attr, _):
            if needs_property:
                # We need to complete a full property at the end
                return makeCompletions(getProperties(parsed, locals), '')
            # We already typed part of the property, let's see what we could complete
            return makeCompletions(getProperties(value, locals), attr)
        case ast.NamedExpr():
            # Of the form (x := 4). If this is parsed, then it is already complete
            # Therefore there's nothing to complete here
            return []
        case ast.Subscript() | ast.ListComp() | ast.SetComp() | ast.GeneratorExp() | ast.DictComp():
            if needs_property:
                # Just pass introspection to getProperties
                return makeCompletions(getProperties(parsed, locals), '')
            # This is a valid expression and not an unfinished fragment
            # There is nothing to complete
            return []
        case ast.Starred(value, _):
            return completeAST(value, locals, needs_property)
        case ast.Assign(_, value, _):
            return completeAST(value, locals, needs_property)
        case ast.AnnAssign(_, _, value, _):
            return completeAST(value, locals, needs_property)
        case ast.AugAssign(_, _, value):
            return completeAST(value, locals, needs_property)
        case ast.Raise(exc, cause):
            if cause:
                return completeAST(cause, locals, needs_property)
            return completeAST(exc, locals, needs_property)
        case ast.Assert(test, msg):
            if msg:
                return completeAST(msg, locals, needs_property)
            return completeAST(test, locals, needs_property)
        case ast.Delete(targets):
            return completeAST(targets[-1], locals, needs_property)
        case ast.Pass | ast.Break | ast.Continue:
            return []
        case ast.Return(value):
            if value:
                return completeAST(value, locals, needs_property)
            return []
        case ast.Lambda(_, body):
            return completeAST(body, locals, needs_property)
        case ast.Yield(value) | ast.YieldFrom(value):
            return completeAST(body, locals, needs_property)
        case ast.Import() | ast.ImportFrom():
            # TODO, import autocompletion?
            return []
        case ast.Global() | ast.Nonlocal():
            # TODO, autocomplete variable names?
            return []
        # All other cases should be multi-line expressions, which our
        # interpreter console does not support
        case default:
            raise ValueError(f"I don't know how to handle '{ast.dump(default)}' (completeAST)")


def complete(cmd, locals):
    """
    Tries to provide autocompletion suggestions for the input string `cmd`
    with the variables in scope given by locals.
    """
    # Python with a trailing point will never compile
    # We have to handle this special case seperately
    needs_property = cmd.endswith('.')
    # Special case: floating point literals, e.g.
    # 0. is parsed as a float in python ;)
    if len(cmd) > 2 and cmd[-2] in '0123456789':
        needs_property = False
    if needs_property:
        cmd = cmd[:-1]

    # CMD may not be valid python, therefore we
    # get the longest suffix that is syntactically correct
    # This should work most of the time
    parsed = None
    while True:
        # Uh oh, there is no valid expression
        if not cmd:
            # Just return a list of the locals
            return makeCompletions(getVariables(locals))

        try:
            parsed = ast.parse(cmd, mode='single')
            break
        except SyntaxError:
            cmd = cmd[1:].lstrip()
    # Parsed will always be of type ast.Interactive
    # We only have to complete the last expression
    return completeAST(parsed.body[-1], locals, needs_property)
