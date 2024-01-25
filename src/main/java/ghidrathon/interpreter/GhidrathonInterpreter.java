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
import ghidra.util.Msg;
import ghidrathon.GhidrathonClassEnquirer;
import ghidrathon.GhidrathonConfig;
import ghidrathon.GhidrathonScript;
import ghidrathon.GhidrathonUtils;
import java.io.*;
import java.lang.reflect.*;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.stream.Collectors;
import jep.Jep;
import jep.JepConfig;
import jep.JepException;
import jep.MainInterpreter;
import jep.PyConfig;

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
  private static final AtomicBoolean jepMainInterpreterInitialized = new AtomicBoolean(false);
  private static final AtomicBoolean jepPythonSysModuleInitialized = new AtomicBoolean(false);

  private static File jepPythonPackageDir = null;
  private static File jepNativeFile = null;
  private static File pythonFile = null;

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

    // we must configure jep.MainInterpreter once before creating our first jep.SharedInterpreter
    if (jepMainInterpreterInitialized.get() == false) {
      configureJepMainInterpreter();
      jepMainInterpreterInitialized.set(true);
    }

    // we must set JepConfig once before creating the first jep.SharedInterpreter
    if (jepConfigInitialized.get() == false) {
      setJepConfig();
      jepConfigInitialized.set(true);
    }

    // create new Jep SharedInterpreter instance
    jep_ = new jep.SharedInterpreter();

    // we must configure Python sys module AFTER the first jep.SharedInterpreter is created
    if (jepPythonSysModuleInitialized.get() == false) {
      jep_.eval(
          String.format("import sys;sys.executable=sys._base_executable=r\"%s\"", this.pythonFile));
      // site module configures other necessary sys vars, e.g. sys.prefix, using sys.executable
      jep_.eval("import site;site.main()");
      jep_.eval(
          String.format(
              "sys.path.extend([r\"%s\"])",
              Application.getModuleDataSubDirectory(GhidrathonUtils.THIS_EXTENSION_NAME, "python")
                  .getAbsolutePath()));
      jepPythonSysModuleInitialized.set(true);
    }

    // now that everything is configured, we should be able to run some utility scripts
    // to help us further configure the Python environment
    setJepWrappers();

    jep_.invoke("jepwrappers.init_state");
    jep_.invoke("jepwrappers.set_streams", this.out, this.err);

    setJepEval();
    setJepRunScript();
  }

  /** Configure jep.JepConfig for ALL Jep SharedInterpreters */
  private void setJepConfig() {
    // configure the Python includes path with the user's Ghidra script directory
    String paths = "";

    // add Jep parent directory
    paths += this.jepPythonPackageDir.getParentFile().getAbsolutePath() + File.pathSeparator;

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
  private void extendPythonSysPath() {
    String paths = "";

    for (ResourceFile resourceFile : GhidraScriptUtil.getScriptSourceDirectories()) {
      paths += resourceFile.getFile(false).getAbsolutePath() + File.pathSeparator;
    }

    jep_.eval("import sys");
    jep_.eval(
        "sys.path.extend([path for path in r'"
            + paths
            + "'.split('"
            + File.pathSeparator
            + "') if path not in sys.path])");
  }

  /**
   * Configure jep.MainInterpreter
   *
   * @throws JepException
   * @throws FileNotFoundException
   */
  private void configureJepMainInterpreter() throws JepException, FileNotFoundException {

    File ghidrathonSaveFile =
        new File(
            Application.getApplicationRootDirectory().getParentFile().getFile(false),
            "ghidrathon.save");
    if (!(ghidrathonSaveFile.exists() && ghidrathonSaveFile.isFile())) {
      throw new JepException(
          String.format(
              "Failed to find %s. Please configure Ghidrathon before running it.",
              ghidrathonSaveFile.getAbsolutePath()));
    }

    Msg.info(
        GhidrathonInterpreter.class,
        String.format("Using save file at %s.", ghidrathonSaveFile.getAbsolutePath()));

    // read absolute path of Python interpreter from save file
    try (BufferedReader reader = new BufferedReader(new FileReader(ghidrathonSaveFile))) {
      String pythonFilePath = reader.readLine().trim();
      if (pythonFilePath != null && !pythonFilePath.isEmpty()) {
        this.pythonFile = new File(pythonFilePath);
      }
    } catch (IOException e) {
      throw new JepException(
          String.format("Failed to read %s (%s)", ghidrathonSaveFile.getAbsolutePath(), e));
    }

    // validate Python file path exists and is a file
    if (this.pythonFile == null || !(this.pythonFile.exists() && this.pythonFile.isFile())) {
      throw new JepException(
          String.format(
              "Python path %s is not valid. Please configure Ghidrathon before running it.",
              this.pythonFile.getAbsolutePath()));
    }

    Msg.info(
        GhidrathonInterpreter.class,
        String.format("Using Python interpreter at %s.", this.pythonFile.getAbsolutePath()));

    String jepPythonPackagePath = findJepPackageDir();
    if (jepPythonPackagePath.isEmpty()) {
      throw new JepException(
          "Could not find Jep Python package. Please install Jep before running Ghidrathon.");
    }
    this.jepPythonPackageDir = new File(jepPythonPackagePath);

    // validate Jep Python package directory is valid and exists
    if (!(this.jepPythonPackageDir.exists() && this.jepPythonPackageDir.isDirectory())) {
      throw new JepException(
          String.format(
              "Jep Python package path %s is not valid. Please verify your Jep installation works"
                  + " before running Ghidrathon.",
              this.jepPythonPackageDir.getAbsolutePath()));
    }

    Msg.info(
        GhidrathonInterpreter.class,
        String.format(
            "Using Jep Python package at %s.", this.jepPythonPackageDir.getAbsolutePath()));

    // find our native Jep file
    // https://github.com/ninia/jep/blob/dd2bf345392b1b66fd6c9aeb12c234a557690ba1/src/main/java/jep/LibraryLocator.java#L86C1-L93C10
    String libraryName = System.mapLibraryName("jep");
    if (libraryName.endsWith(".dylib")) {
      /*
       * OS X uses a different extension for System.loadLibrary and
       * System.mapLibraryName
       */
      libraryName = libraryName.replace(".dylib", ".jnilib");
    }
    this.jepNativeFile = new File(this.jepPythonPackageDir, libraryName);

    // validate our native Jep file exists and is a file
    if (!(this.jepNativeFile.exists() && this.jepNativeFile.isFile())) {
      throw new JepException(
          String.format(
              "Jep native file path %s is not valid. Please verify your Jep installation works"
                  + " before running Ghidrathon.",
              this.jepNativeFile.getAbsolutePath()));
    }

    Msg.info(
        GhidrathonInterpreter.class,
        String.format("Using Jep native file at %s.", this.jepNativeFile.getAbsolutePath()));

    try {
      MainInterpreter.setJepLibraryPath(this.jepNativeFile.getAbsolutePath());

      PyConfig config = new PyConfig();

      // we can't auto import the site module becuase we are running an embedded Python interpreter
      config.setNoSiteFlag(1);
      config.setIgnoreEnvironmentFlag(1);

      MainInterpreter.setInitParams(config);
    } catch (IllegalStateException e) {
      e.printStackTrace(this.err);
      throw new RuntimeException(e);
    }
  }

  private String findJepPackageDir() {
    String output =
        execCmd(
            this.pythonFile.getAbsolutePath(),
            "-c",
            "import importlib.util;import"
                + " pathlib;print(pathlib.Path(importlib.util.find_spec('jep').origin).parent)");
    return output.trim();
  }

  // DANGER: DO NOT PASS DYNAMIC COMMANDS HERE!
  private String execCmd(String... commands) {
    Runtime runtime = Runtime.getRuntime();
    Process process = null;
    try {
      process = runtime.exec(commands);
    } catch (IOException e) {
      Msg.error(GhidrathonInterpreter.class, "error: " + e.toString());
      return "";
    }

    BufferedReader lineReader =
        new BufferedReader(new java.io.InputStreamReader(process.getInputStream()));
    String output = String.join("\n", lineReader.lines().collect(Collectors.toList()));

    BufferedReader errorReader =
        new BufferedReader(new java.io.InputStreamReader(process.getErrorStream()));
    String error = String.join("\n", errorReader.lines().collect(Collectors.toList()));

    if (error.length() > 0) {
      Msg.error(GhidrathonInterpreter.class, error);
    }

    return output;
  }

  /**
   * Configure wrapper functions in Python land.
   *
   * @throws JepException
   */
  private void setJepWrappers() throws JepException {

    jep_.eval("import jepwrappers");
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
        jep_.invoke("jepwrappers.remove_state");
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

      extendPythonSysPath();

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
   */
  public boolean eval(String line, GhidrathonScript script) {

    try {

      jep_.invoke("jepwrappers.set_script", script);
      extendPythonSysPath();

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

      extendPythonSysPath();

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
   */
  public void runScript(ResourceFile file, GhidraScript script) {

    try {

      jep_.invoke("jepwrappers.set_script", script);
      extendPythonSysPath();

      jep_.invoke("jep_runscript", file.getAbsolutePath());

    } catch (JepException e) {

      // Python exceptions should be handled in Python land; something bad must have happened
      e.printStackTrace(this.err);
      throw new RuntimeException(e);
    }
  }

  public void printWelcome() {

    try {

      ResourceFile file =
          Application.getModuleDataFile(
              GhidrathonUtils.THIS_EXTENSION_NAME, "python/jepwelcome.py");

      jep_.set("ghidra_version", Application.getApplicationVersion());

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
