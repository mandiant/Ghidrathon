// Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
// You may obtain a copy of the License at: [package root]/LICENSE.txt
// Unless required by applicable law or agreed to in writing, software distributed under the License
//  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied.
// See the License for the specific language governing permissions and limitations under the
// License.

package ghidrathon.interpreter;

import com.google.gson.*;
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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import java.util.stream.Collectors;
import jep.Jep;
import jep.JepConfig;
import jep.JepException;
import jep.MainInterpreter;
import jep.PyConfig;

/** Utility class used to configure a Jep instance to access Ghidra */
public class GhidrathonInterpreter {

  private class GhidrathonSave {
    String executable;
    String home;
  }

  private static final String GHIDRATHON_SAVE_FILENAME = "ghidrathon.save";
  private static final String GHIDRATHON_SAVE_PATH = "GHIDRATHON_SAVE_PATH";
  private static final String SUPPORTED_JEP_VERSION = "4.2.0";

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
  private static File pythonExecutableFile = null;
  private static File pythonHomeDir = null;

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
      Msg.info(GhidrathonInterpreter.class, "Configuring jep.MainInterpreter.");

      configureJepMainInterpreter();
      jepMainInterpreterInitialized.set(true);
    }

    // we must set JepConfig once before creating the first jep.SharedInterpreter
    if (jepConfigInitialized.get() == false) {
      Msg.info(GhidrathonInterpreter.class, "Configuring jep.JepConfig.");
      setJepConfig();
      jepConfigInitialized.set(true);
    }

    Msg.info(GhidrathonInterpreter.class, "Creating new jep.SharedInterpreter.");

    // create new Jep SharedInterpreter instance
    jep_ = new jep.SharedInterpreter();

    // we must configure Python sys module AFTER the first jep.SharedInterpreter is created
    if (jepPythonSysModuleInitialized.get() == false) {
      Msg.info(GhidrathonInterpreter.class, "Configuring Python sys module.");

      jep_.eval(
          String.format(
              "import sys;sys.executable=sys._base_executable=r\"%s\"", this.pythonExecutableFile));
      // site module configures other necessary sys vars, e.g. sys.prefix, using sys.executable
      jep_.eval("import site;site.main()");
      jep_.eval(
          String.format(
              "sys.path.extend([r\"%s\"])",
              Application.getModuleDataSubDirectory(GhidrathonUtils.THIS_EXTENSION_NAME, "python")
                  .getAbsolutePath()));

      // print embedded interpreter configuration to application.log
      Msg.info(GhidrathonInterpreter.class, "Embedded Python configuration:");
      Msg.info(
          GhidrathonInterpreter.class, String.format("Python %s", jep_.getValue("sys.version")));

      String[] sysVars = {
        "sys.executable",
        "sys._base_executable",
        "sys.prefix",
        "sys.base_prefix",
        "sys.exec_prefix",
        "sys.base_exec_prefix"
      };

      for (String sysVar : sysVars) {
        Msg.info(
            GhidrathonInterpreter.class,
            String.format("%s = \"%s\"", sysVar, jep_.getValue(sysVar)));
      }

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

    // get the ghidrathon.save path from the environment variable or use the default path
    String ghidrathonSavePath = System.getenv(GHIDRATHON_SAVE_PATH);
    File ghidrathonSaveFile;

    if (ghidrathonSavePath != null && !ghidrathonSavePath.isEmpty()) {
      ghidrathonSaveFile = new File(ghidrathonSavePath, GHIDRATHON_SAVE_FILENAME);
      Msg.info(
          GhidrathonInterpreter.class,
          String.format("Using save file from environment variable %s.", GHIDRATHON_SAVE_PATH));
    } else {
      ghidrathonSaveFile =
          new File(
              Application.getApplicationRootDirectory().getParentFile().getFile(false),
              GHIDRATHON_SAVE_FILENAME);
      Msg.info(GhidrathonInterpreter.class, String.format("Using default save file path."));
    }

    if (!(ghidrathonSaveFile.exists() && ghidrathonSaveFile.isFile())) {
      throw new JepException(
          String.format(
              "Failed to find %s. Please configure Ghidrathon before running it.",
              ghidrathonSaveFile.getAbsolutePath()));
    }

    Msg.info(
        GhidrathonInterpreter.class,
        String.format("Using save file found at %s.", ghidrathonSaveFile.getAbsolutePath()));

    GhidrathonSave ghidrathonSave = null;
    try (BufferedReader reader = new BufferedReader(new FileReader(ghidrathonSaveFile))) {
      String json = reader.readLine().trim();
      if (json != null && !json.isEmpty()) {
        try {
          ghidrathonSave = new Gson().fromJson(json, GhidrathonSave.class);
        } catch (JsonSyntaxException e) {
          throw new JepException(
              String.format(
                  "Failed to parse JSON from %s (%s). Please configure Ghidrathon before running"
                      + " it.",
                  ghidrathonSaveFile.getAbsolutePath(), e));
        }
      }
    } catch (IOException e) {
      throw new JepException(
          String.format("Failed to read %s (%s)", ghidrathonSaveFile.getAbsolutePath(), e));
    }

    if (ghidrathonSave.home == null || ghidrathonSave.executable == null) {
      throw new JepException(
          String.format(
              "%s JSON is not valid. Please configure Ghidrathon before running it.",
              ghidrathonSaveFile.getAbsolutePath()));
    }

    Msg.info(
        GhidrathonInterpreter.class,
        String.format(
            "ghidrathonSave.home = \"%s\", ghidrathonSave.executable = \"%s\"",
            ghidrathonSave.home, ghidrathonSave.executable));

    // validate Python home directory exists and is a directory
    this.pythonHomeDir = new File(ghidrathonSave.home);
    if (!(this.pythonHomeDir.exists() && this.pythonHomeDir.isDirectory())) {
      throw new JepException(
          String.format(
              "Python home path %s is not valid. Please configure Ghidrathon before running it.",
              this.pythonHomeDir.getAbsolutePath()));
    }

    // validate Python executable path exists and is a file
    this.pythonExecutableFile = new File(ghidrathonSave.executable);
    if (!(this.pythonExecutableFile.exists() && this.pythonExecutableFile.isFile())) {
      throw new JepException(
          String.format(
              "Python executable path %s is not valid. Please configure Ghidrathon before running"
                  + " it.",
              this.pythonExecutableFile.getAbsolutePath()));
    }

    Msg.info(
        GhidrathonInterpreter.class,
        String.format(
            "Using Python interpreter at %s.", this.pythonExecutableFile.getAbsolutePath()));

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

    File jepVersionFile = new File(this.jepPythonPackageDir, "version.py");

    if (!(jepVersionFile.exists() && jepVersionFile.isFile())) {
      throw new JepException(
          String.format(
              "%s is not valid - could not check Jep version. Please verify your jep installation"
                  + " works before running Ghidrathon.",
              jepVersionFile.getAbsolutePath()));
    }

    boolean isCorrectJepVersion = false;
    try (BufferedReader br = new BufferedReader(new FileReader(jepVersionFile))) {
      for (String line; (line = br.readLine()) != null; ) {
        if (line.contains(GhidrathonInterpreter.SUPPORTED_JEP_VERSION)) {
          isCorrectJepVersion = true;
          break;
        }
      }
    } catch (IOException e) {
      throw new JepException(
          String.format("Failed to read %s (%s).", jepVersionFile.getAbsolutePath(), e));
    }

    if (!isCorrectJepVersion) {
      throw new JepException(
          String.format(
              "Please install Jep version %s before running Ghidrathon.",
              GhidrathonInterpreter.SUPPORTED_JEP_VERSION));
    }

    Msg.info(
        GhidrathonInterpreter.class,
        String.format("Using Jep version %s.", GhidrathonInterpreter.SUPPORTED_JEP_VERSION));

    /*
     * We need to ensure Jep nativate can link its dependencies, namely
     * Python. This must be done before jep.MainInterpreter is initialized so we attempt
     * to load Jep native here and resolve any linking issues. Linking issues are most common
     * when a non-standard Python install is used.
     */
    try {
      System.load(this.jepNativeFile.getAbsolutePath());
    } catch (UnsatisfiedLinkError e) {
      Msg.info(
          GhidrathonInterpreter.class,
          String.format("Link error encountered when loading Jep native (%s)", e));

      // https://github.com/ninia/jep/blob/dd2bf345392b1b66fd6c9aeb12c234a557690ba1/src/main/java/jep/LibraryLocator.java#L244
      Matcher m = Pattern.compile("libpython[\\w\\.]*").matcher(e.getMessage());
      if (!(m.find() && findPythonLibrary(m.group(0)))) {
        if (!findPythonLibraryWindows()) {
          // failed to resolve link error
          throw new JepException(String.format("Failed to load native Jep (%s).", e));
        }
      }
    }

    /*
     * This is hacky but we do not have a way to force Jep to use the Jep native
     * that we have resolved without calling jep.MainInterpreter.setJepLibraryPath.
     * This results in System.load(<jep_native>) twice which, according to the Java
     * documentation is ok as the second load attempt is ignored.
     */
    MainInterpreter.setJepLibraryPath(this.jepNativeFile.getAbsolutePath());

    // delay site module import
    PyConfig config = new PyConfig();
    config.setNoSiteFlag(1);

    MainInterpreter.setInitParams(config);
  }

  private String findJepPackageDir() {
    String output =
        execCmd(
            this.pythonExecutableFile.getAbsolutePath(),
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
   * Attempt to load libpython from within PYTHONHOME
   *
   * @param libraryName the full file name of libpython
   * @return true if libpython was found and loaded.
   */
  private boolean findPythonLibrary(String libraryName) {
    // https://github.com/ninia/jep/blob/dd2bf345392b1b66fd6c9aeb12c234a557690ba1/src/main/java/jep/LibraryLocator.java#L275
    if (this.pythonHomeDir != null) {
      for (String libDirName : new String[] {"lib", "lib64", "Lib"}) {
        File libDir = new File(this.pythonHomeDir, libDirName);
        if (!libDir.isDirectory()) {
          continue;
        }
        File libraryFile = new File(libDir, libraryName);
        if (libraryFile.exists()) {
          System.load(libraryFile.getAbsolutePath());
          return true;
        }
      }
    }
    return false;
  }

  /**
   * Attempt to load pythonXX.dll from within PYTHONHOME
   *
   * @return true if pythonXX.dll was found and loaded.
   */
  private boolean findPythonLibraryWindows() {
    // https://github.com/ninia/jep/blob/dd2bf345392b1b66fd6c9aeb12c234a557690ba1/src/main/java/jep/LibraryLocator.java#L297
    if (this.pythonHomeDir != null) {
      Pattern re = Pattern.compile("^python\\d\\d+\\.dll$");
      for (File file : this.pythonHomeDir.listFiles()) {
        if (!file.isFile()) {
          continue;
        }
        if (re.matcher(file.getName()).matches() && file.exists()) {
          System.load(file.getAbsolutePath());
          return true;
        }
      }
    }
    return false;
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
