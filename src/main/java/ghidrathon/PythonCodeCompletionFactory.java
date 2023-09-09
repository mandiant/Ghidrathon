/* ###
 * IP: GHIDRATHON
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 *      http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
// Taken from https://github.com/NationalSecurityAgency/ghidra/blob/d7d6b44e296ac4a215766916d5c24e8b53b2909a/Ghidra/Features/Python/src/main/java/ghidra/python/PythonCodeCompletionFactory.java
package ghidrathon;

import java.awt.Color;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.util.*;

import javax.swing.JComponent;

import jep.python.PyObject;
import jep.JepException;

import docking.widgets.label.GDLabel;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.framework.options.Options;
import ghidra.util.Msg;

/**
 * Generates CodeCompletions from Python objects.
 * 
 * 
 *
 */
public class PythonCodeCompletionFactory {
  private static class InspectableJavaObject<T> {
    private Class<T> srcClass;

    public InspectableJavaObject(Class<T> c) {
      srcClass = c;
    }

    public Class<T> getSrcClass() {
      return srcClass;
    }

    /**
     * Returns the Java methods declared for a given object
     * @param obj a Java Object
     * @return the Java method names and a proxy that can be inspected as well
     */
    public List<Object[]> getProperties() {
      List<Object[]> properties = new ArrayList<>();
      Method[] declaredMethods = srcClass.getMethods();
      Field[] declaredFields = srcClass.getFields();
      
      for (Method declaredMethod : declaredMethods) {
        properties.add(new Object [] {
          declaredMethod.getName(),
          new InspectableJavaMethod(this, declaredMethod)
        });
      }

      for (Field declaredField : declaredFields) {
        properties.add(new Object [] {
          declaredField.getName(),
          new InspectableJavaObject(declaredField.getType())
        });
      }

      return properties;
    }
  }

  private static class InspectableJavaMethod {
    private Method method;
    public String __name__;
    public Object __self__;

    public InspectableJavaMethod(Object o, Method m) {
      method = m;
      __name__ = m.getName();
      __self__ = o;
    }

    public Method getMethod() {
      return method;
    }
  }

  
  private static Map<String, Color> typeToColorMap = new HashMap<>();
  public static final String COMPLETION_LABEL = "Code Completion Colors";

  /* package-level accessibility so that PythonPlugin can tell this is
   * our option
   */
  final static String INCLUDE_TYPES_LABEL = "Include type names in code completion popup?";
  private final static String INCLUDE_TYPES_DESCRIPTION =
    "Whether or not to include the type names (classes) of the possible " +
    "completions in the code completion window.  The class name will be " +
    "parenthesized after the completion.";
  private final static boolean INCLUDE_TYPES_DEFAULT = true;
  private static boolean includeTypes = INCLUDE_TYPES_DEFAULT;

  public static final Color NULL_COLOR = new Color(255, 0, 0);
  public static final Color FUNCTION_COLOR = new Color(0, 128, 0);
  public static final Color PACKAGE_COLOR = new Color(128, 0, 0);
  public static final Color CLASS_COLOR = new Color(0, 0, 255);
  public static final Color METHOD_COLOR = new Color(0, 128, 128);
  /* anonymous code chunks */
  public static final Color CODE_COLOR = new Color(0, 64, 0);
  public static final Color INSTANCE_COLOR = new Color(128, 0, 128);
  public static final Color SEQUENCE_COLOR = new Color(128, 96, 64);
  public static final Color MAP_COLOR = new Color(64, 96, 128);
  public static final Color NUMBER_COLOR = new Color(64, 64, 64);

  static {
    setupClass("NoneType", NULL_COLOR);

    setupClass("builtin_function_or_method", FUNCTION_COLOR);
    setupClass("function", FUNCTION_COLOR);

    setupClass("module", PACKAGE_COLOR);

    setupClass("str", SEQUENCE_COLOR);
    setupClass("bytes", SEQUENCE_COLOR);
    setupClass("list", SEQUENCE_COLOR);
    setupClass("tuple", SEQUENCE_COLOR);
    setupClass("dict", MAP_COLOR);

    setupClass("int", NUMBER_COLOR);
    setupClass("float", NUMBER_COLOR);
    setupClass("complex", NUMBER_COLOR);
  }

  /**
   * Returns the type name for a Python Object.
   * 
   * @param pyObj Object to determine to type name
   * @return The type name.
   */
  private static String getTypeName(PyObject pyObj) {
    return pyObj.getAttr("__class__", PyObject.class).getAttr("__name__", String.class);
  }

  /**
   * Sets up a Type mapping.
   * 
   * @param typeName Type name
   * @param defaultColor default Color for this type
   * @param description description of the type
   */
  private static void setupClass(String typeName, Color defaultColor) {
    typeToColorMap.put(typeName, defaultColor);
  }

  /**
   * Creates a new CodeCompletion from the given Python objects.
   * 
   * @param description description of the new CodeCompletion
   * @param insertion what will be inserted to make the code complete
   * @param pyObj a Python Object
   * @return A new CodeCompletion from the given Python objects.
   */
  public static CodeCompletion newCodeCompletion(String description, String insertion,
                                                 Object obj) {
    JComponent comp = null;

    if (obj != null) {
      String type;
      Color color;
      if ((obj instanceof PyObject)) {
        type = getTypeName((PyObject) obj);
        color = typeToColorMap.get(type);
      } else {
        type = obj.getClass().getSimpleName();
        color = CLASS_COLOR;
      }
      if (includeTypes) {
        description = description + " (" + type + ")";
      }

      comp = new GDLabel(description);
      if (color != null) {
        comp.setForeground(color);
      }
    }
    return new CodeCompletion(description, insertion, comp);
  }

  /**
   * Returns the Java methods declared for a given object
   * @param obj a Java Object
   * @return the Java method names and a proxy that can be inspected as well
   */
  public static Object getReturnType(Object obj, String name) {
    Class<?> c;
    if (obj instanceof InspectableJavaObject) {
      c = ((InspectableJavaObject) obj).getSrcClass();
    } else {
      c = obj.getClass();
    }

    return new InspectableJavaObject(getReturnTypeForClass(c, name));
  }

  /**
   * Returns the Java methods declared for a given java class
   * @param obj a Java Object
   * @return the Java method names and a proxy that can be inspected as well
   */
  public static Class getReturnTypeForClass(Class c, String name) {
    Method[] declaredMethods = c.getMethods();

    for (Method declaredMethod : declaredMethods) {
      if (declaredMethod.getName().equals(name)) {
        return declaredMethod.getReturnType();
      }
    }

    return null;
  }

  /**
   * Sets up Python code completion Options.
   * @param plugin python plugin as options owner
   * @param options an Options handle
   */
  public static void setupOptions(GhidrathonPlugin plugin, Options options) {
    includeTypes = options.getBoolean(INCLUDE_TYPES_LABEL, INCLUDE_TYPES_DEFAULT);
    options.registerOption(INCLUDE_TYPES_LABEL, INCLUDE_TYPES_DEFAULT, null,
                           INCLUDE_TYPES_DESCRIPTION);

    Iterator<?> iter = typeToColorMap.keySet().iterator();
    while (iter.hasNext()) {
      String currentType = (String) iter.next();
      options.registerOption(
        COMPLETION_LABEL + Options.DELIMITER + currentType,
        typeToColorMap.get(currentType), null,
        "Color to use for '" + currentType + "'.");
      typeToColorMap.put(currentType,
                         options.getColor(COMPLETION_LABEL + Options.DELIMITER + currentType,
                                          typeToColorMap.get(currentType)));
    }
  }

  /**
   * Handle an Option change.
   * 
   * This is named slightly differently because it is a static method, not
   * an instance method.
   * 
   * By the time we get here, we assume that the Option changed is indeed
   * ours. 
   * 
   * @param options the Options handle
   * @param name name of the Option changed
   * @param oldValue the old value
   * @param newValue the new value
   */
  public static void changeOptions(Options options, String name, Object oldValue,
                                   Object newValue) {
    String typeName = name.substring((COMPLETION_LABEL + Options.DELIMITER).length());

    if (typeToColorMap.containsKey(typeName)) {
      typeToColorMap.put(typeName, (Color) newValue);
    }
    else if (name.equals(INCLUDE_TYPES_LABEL)) {
      includeTypes = ((Boolean) newValue).booleanValue();
    }
    else {
      Msg.error(PythonCodeCompletionFactory.class, "unknown option '" + name + "'");
    }
  }
}
