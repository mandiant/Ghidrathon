// Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
// You may obtain a copy of the License at: [package root]/LICENSE.txt
// Unless required by applicable law or agreed to in writing, software distributed under the License
//  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied.
// See the License for the specific language governing permissions and limitations under the
// License.

package ghidrathon.interpreter;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.framework.Application;
import ghidrathon.GhidrathonClassEnquirer;
import ghidrathon.GhidrathonConfig;
import ghidrathon.GhidrathonScript;
import ghidrathon.GhidrathonUtils;
import java.io.File;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.PrintWriter;
import java.lang.reflect.*;
import java.util.concurrent.atomic.AtomicBoolean;
import jep.Jep;
import jep.JepConfig;
import jep.JepException;
import jep.MainInterpreter;

/** Utility class used to configure a Jep instance to access Ghidra */
public class GhidrathonInterpreter {

  private Jep jep_ = null;
  private PrintWriter out = null;
  private PrintWriter err = null;
  private GhidrathonConfig config = null;

  // these variables set across GhidrathonInterpreter instances
  private static final JepConfig jepConfig = new JepConfig();
  private static final GhidrathonClassEnquirer ghidrathonClassEnquirer =
      new GhidrathonClassEnquirer();
  private static final AtomicBoolean jepConfigInitialized = new AtomicBoolean(false);
  private static final AtomicBoolean ghidraScriptMethodsInitialized = new AtomicBoolean(false);
  private static final AtomicBoolean jepNativeBinaryInitialized = new AtomicBoolean(false);

  /**
   * Create and configure a new GhidrathonInterpreter instance.
   *
   * @throws JepException
   * @throws IOException
   */
  private GhidrathonInterpreter(GhidrathonConfig config) throws JepException, IOException {

    this.out = config.getStdOut();
    this.err = config.getStdErr();
    this.config = config;

    // we must set the native Jep library once before creating a Jep instance
    if (jepNativeBinaryInitialized.get() == false) {
      setJepNativeBinaryPath();
      jepNativeBinaryInitialized.set(true);
    }

    // we must set JepConfig once before creating the first SharedInterpreter
    if (jepConfigInitialized.get() == false) {
      setJepConfig();
      jepConfigInitialized.set(true);
    }

    // create new Jep SharedInterpreter instance
    jep_ = new jep.SharedInterpreter();

    // now that everything is configured, we should be able to run some utility scripts
    // to help us further configure the Python environment
    setJepEval();
    setJepRunScript();
  }

  /** Configure JepConfig for ALL Jep SharedInterpreters */
  private void setJepConfig() {
    // configure the Python includes path with the user's Ghidra script directory
    String paths = "";

    // add data/python/ to Python includes directory
    try {
      paths +=
          Application.getModuleDataSubDirectory(GhidrathonUtils.THIS_EXTENSION_NAME, "python")
              + File.pathSeparator;
    } catch (IOException e) {
      e.printStackTrace(this.err);
      throw new RuntimeException(e);
    }

    // add paths specified in Ghidrathon config
    for (String path : this.config.getPythonIncludePaths()) {

      paths += path + File.pathSeparator;
    }

    // configure Java names that will be ignored when importing from Python
    for (String name : this.config.getJavaExcludeLibs()) {

      ghidrathonClassEnquirer.addJavaExcludeLib(name);
    }

    // set the class loader with access to Ghidra scripting API
    jepConfig.setClassLoader(ClassLoader.getSystemClassLoader());

    // set class enquirer used to handle Java imports from Python
    jepConfig.setClassEnquirer(ghidrathonClassEnquirer);

    // configure Python includes Path
    jepConfig.addIncludePaths(paths);

    // sets JepConfig for ALL SharedInterpreters created moving forward
    jep.SharedInterpreter.setConfig(jepConfig);
  }

  /** Extends Python sys.path to include Ghidra script source directories */
  private void setPySys() {
    String paths = "";

    for (ResourceFile resourceFile : GhidraScriptUtil.getScriptSourceDirectories()) {
      paths += resourceFile.getFile(false).getAbsolutePath() + File.pathSeparator;
    }

    jep_.eval("import sys");
    jep_.eval(
        "sys.path.extend([path for path in '"
            + paths
            + "'.split('"
            + File.pathSeparator
            + "') if path not in sys.path])");

    String executable = config.getPyExecutable();
    if (!executable.isEmpty()) {
      jep_.eval("sys.executable='" + executable + "'");
    }
  }

  /**
   * Configure native Jep library.
   *
   * <p>User must build and include native Jep library in the appropriate OS folder prior to
   * building this extension. Requires os/win64/libjep.dll for Windows Requires os/linux64/libjep.so
   * for Linux
   *
   * @throws JepException
   * @throws FileNotFoundException
   */
  private void setJepNativeBinaryPath() throws JepException, FileNotFoundException {

    File nativeJep;

    try {

      nativeJep = Application.getOSFile(GhidrathonUtils.THIS_EXTENSION_NAME, "libjep.so");

    } catch (FileNotFoundException e) {

      // whoops try Windows
      nativeJep = Application.getOSFile(GhidrathonUtils.THIS_EXTENSION_NAME, "jep.dll");
    }

    try {

      MainInterpreter.setJepLibraryPath(nativeJep.getAbsolutePath());

    } catch (IllegalStateException e) {
      // library path has already been set elsewhere, we expect this to happen as Jep
      // Maininterpreter
      // thread exists forever once it's created
    }
  }

  /**
   * Configure "jepeval" function in Python land.
   *
   * <p>We use Python to evaluate Python statements because as of Jep 4.0 interactive mode is no
   * longer supported. As a side effect we also get better tracebacks. Requires
   * data/python/jepeval.py.
   *
   * @throws JepException
   * @throws FileNotFoundException
   */
  private void setJepEval() throws JepException, FileNotFoundException {

    ResourceFile file =
        Application.getModuleDataFile(GhidrathonUtils.THIS_EXTENSION_NAME, "python/jepeval.py");

    jep_.runScript(file.getAbsolutePath());
  }

  /**
   * Configure "jep_runscript" function in Python land.
   *
   * <p>We use Python to run Python scripts because it gives us better access to tracebacks.
   * Requires data/python/jeprunscript.py.
   *
   * @throws JepException
   * @throws FileNotFoundException
   */
  private void setJepRunScript() throws JepException, FileNotFoundException {

    ResourceFile file =
        Application.getModuleDataFile(
            GhidrathonUtils.THIS_EXTENSION_NAME, "python/jeprunscript.py");

    jep_.runScript(file.getAbsolutePath());
  }

  /**
   * Configure GhidraState.
   *
   * <p>This exposes things like currentProgram, currentAddress, etc. similar to Jython. We need to
   * repeat this prior to executing new Python code in order to provide the latest state e.g. that
   * current currentAddress. Requires data/python/jepinject.py.
   *
   * @param script GhidrathonScript instance
   * @throws JepException
   * @throws FileNotFoundException
   */
  private void injectScriptHierarchy(GhidraScript script)
      throws JepException, FileNotFoundException {
    if (script == null) {
      return;
    }

    ResourceFile file =
        Application.getModuleDataFile(GhidrathonUtils.THIS_EXTENSION_NAME, "python/jepbuiltins.py");
    jep_.runScript(file.getAbsolutePath());

    // inject GhidraScript public/private fields e.g. currentAddress into Python
    // see
    // https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Python/src/main/java/ghidra/python/GhidraPythonInterpreter.java#L341-L377
    for (Class<?> scriptClass = script.getClass();
        scriptClass != Object.class;
        scriptClass = scriptClass.getSuperclass()) {
      for (Field field : scriptClass.getDeclaredFields()) {
        if (Modifier.isPublic(field.getModifiers()) || Modifier.isProtected(field.getModifiers())) {
          try {
            field.setAccessible(true);
            jep_.invoke("jep_set_builtin", field.getName(), field.get(script));
          } catch (IllegalAccessException iae) {
            throw new JepException("Unexpected security manager being used!");
          }
        }
      }
    }

    // inject GhidraScript methods once into Python; we ASSUME all SharedInterpreters can share the same methods
    if (ghidraScriptMethodsInitialized.get() == false) {
      file =
          Application.getModuleDataFile(GhidrathonUtils.THIS_EXTENSION_NAME, "python/jepinject.py");
      jep_.set("__ghidra_script__", script);
      jep_.runScript(file.getAbsolutePath());

      ghidraScriptMethodsInitialized.set(true);
    }
  }

  /**
   * Create a new GhidrathonInterpreter instance.
   *
   * @return GhidrathonInterpreter
   * @throws RuntimeException
   */
  public static GhidrathonInterpreter get(GhidrathonConfig config) throws RuntimeException {

    try {

      return new GhidrathonInterpreter(config);

    } catch (Exception e) {

      e.printStackTrace(config.getStdErr());
      throw new RuntimeException(e);
    }
  }

  /**
   * Close Jep instance.
   *
   * <p>We must call this function when finished with a Jep instance, otherwise, issues arise if we
   * try to create a new Jep instance on the same thread. This function must be called from the same
   * thread that created the Jep instance.
   */
  public void close() {

    try {

      if (jep_ != null) {
        jep_.close();
        jep_ = null;
      }

    } catch (JepException e) {

      e.printStackTrace(this.err);
      throw new RuntimeException(e);
    }
  }

  /**
   * Pass value from Java to Python
   *
   * @param value name as seen in Python
   * @param o Java object to be passed to Python
   * @return
   */
  public void set(String name, Object o) {

    try {

      jep_.set(name, o);

    } catch (JepException e) {

      e.printStackTrace(this.err);
      throw new RuntimeException(e);
    }
  }

  /**
   * Evaluate Python statement.
   *
   * <p>This function must be called from the same thread that instantiated the Jep instance.
   *
   * @param line Python statement
   * @return True (need more input), False (no more input needed)
   */
  public boolean eval(String line) {

    try {

      setPySys();
      setStreams();

      return (boolean) jep_.invoke("jepeval", line);

    } catch (JepException e) {

      // Python exceptions should be handled in Python land; something bad must have happened
      e.printStackTrace(this.err);
      throw new RuntimeException(e);
    }
  }

  /**
   * Evaluate Python statement.
   *
   * <p>This function must be called from the same thread that instantiated the Jep instance.
   *
   * @param line Python statement
   * @param script GhidrathonScript with desired state.
   * @return True (need more input), False (no more input needed)
   * @throws FileNotFoundException
   */
  public boolean eval(String line, GhidrathonScript script) {

    try {

      injectScriptHierarchy(script);

    } catch (JepException | FileNotFoundException e) {

      // we made it here; something bad went wrong, raise to caller
      e.printStackTrace(this.err);
      throw new RuntimeException(e);
    }

    try {

      setPySys();
      setStreams();

      return (boolean) jep_.invoke("jepeval", line);

    } catch (JepException e) {

      // Python exceptions should be handled in Python land; something bad must have happened
      e.printStackTrace(this.err);
      throw new RuntimeException(e);
    }
  }

  /**
   * Run Python script.
   *
   * <p>This function must be called from the same thread that instantiated the Jep instance.
   *
   * @param file Python script to execute
   */
  public void runScript(ResourceFile file) {

    try {

      setPySys();
      setStreams();

      jep_.invoke("jep_runscript", file.getAbsolutePath());

    } catch (JepException e) {

      // Python exceptions should be handled in Python land; something bad must have happened
      e.printStackTrace(this.err);
      throw new RuntimeException(e);
    }
  }

  /**
   * Run Python script.
   *
   * <p>This function must be called from the same thread that instantiated the Jep instance.
   *
   * @param file Python script to execute
   * @param script GhidrathonScript with desired state.
   * @throws FileNotFoundException
   */
  public void runScript(ResourceFile file, GhidraScript script) {

    try {

      injectScriptHierarchy(script);

      setPySys();
      setStreams();

      jep_.invoke("jep_runscript", file.getAbsolutePath());

    } catch (JepException | FileNotFoundException e) {

      // Python exceptions should be handled in Python land; something bad must have happened
      e.printStackTrace(this.err);
      throw new RuntimeException(e);
    }
  }

  /**
   * Set output and error streams for Jep instance.
   *
   * <p>Output and error streams from Python interpreter are redirected to the specified streams. If
   * these are not set, this data is lost.
   *
   * @param out output stream
   * @param err error stream
   */
  public void setStreams() {

    try {

      ResourceFile file =
          Application.getModuleDataFile(GhidrathonUtils.THIS_EXTENSION_NAME, "python/jepstream.py");

      jep_.set("GhidraPluginToolConsoleOutWriter", this.out);
      jep_.set("GhidraPluginToolConsoleErrWriter", this.err);

      jep_.runScript(file.getAbsolutePath());

    } catch (JepException | FileNotFoundException e) {

      // ensure stack trace prints to err stream for user
      e.printStackTrace(this.err);
      throw new RuntimeException(e);
    }
  }

  public void printWelcome() {

    try {

      ResourceFile file =
          Application.getModuleDataFile(
              GhidrathonUtils.THIS_EXTENSION_NAME, "python/jepwelcome.py");

      jep_.set("GhidraVersion", Application.getApplicationVersion());

      runScript(file);

    } catch (JepException | FileNotFoundException e) {

      e.printStackTrace(this.err);
      throw new RuntimeException(e);
    }
  }

  public String getPrimaryPrompt() {

    return ">>> ";
  }

  public String getSecondaryPrompt() {

    return "... ";
  }
}
