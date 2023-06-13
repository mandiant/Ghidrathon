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

import java.io.BufferedReader;
import java.io.IOException;
import java.nio.charset.Charset;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.PathMatcher;
import java.util.List;
import java.util.Locale;
import java.util.stream.Collectors;
import java.util.stream.Stream;


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
import java.lang.reflect.*;
import jep.Jep;
import jep.JepConfig;
import jep.JepException;
import jep.MainInterpreter;
import jep.PyConfig;
import org.apache.commons.io.output.WriterOutputStream;

import org.apache.logging.log4j.Logger;
import org.apache.logging.log4j.LogManager;


/** Utility class used to configure a Jep instance to access Ghidra */
public class GhidrathonInterpreter {
  static final Logger log = LogManager.getLogger(GhidrathonInterpreter.class);

  private Jep jep = null;
  private GhidrathonConfig ghidrathonConfig = null;

  private final JepConfig jepConfig = new JepConfig();
  private final GhidrathonClassEnquirer ghidrathonClassEnquirer = new GhidrathonClassEnquirer();

  private boolean scriptMethodsInjected = false;

  /**
   * Create and configure a new GhidrathonInterpreter instance.
   *
   * @throws JepException
   * @throws IOException
   */
  private GhidrathonInterpreter(GhidrathonConfig config) throws JepException, IOException {

    ghidrathonConfig = config;

    // configure the Python includes path with the user's Ghdira script directory
    String paths = "";
    for (ResourceFile resourceFile : GhidraScriptUtil.getScriptSourceDirectories()) {

      paths += resourceFile.getFile(false).getAbsolutePath() + File.pathSeparator;
    }

    // add data/python/ to Python includes directory
    paths +=
        Application.getModuleDataSubDirectory(GhidrathonUtils.THIS_EXTENSION_NAME, "python")
            + File.pathSeparator;

    // add paths specified in Ghidrathon config
    for (String path : ghidrathonConfig.getPythonIncludePaths()) {

      paths += path + File.pathSeparator;
    }

    // configure Java names that will be ignored when importing from Python
    for (String name : ghidrathonConfig.getJavaExcludeLibs()) {

      ghidrathonClassEnquirer.addJavaExcludeLib(name);
    }

    // set the class loader with access to Ghidra scripting API
    jepConfig.setClassLoader(ClassLoader.getSystemClassLoader());

    // set class enquirer used to handle Java imports from Python
    jepConfig.setClassEnquirer(ghidrathonClassEnquirer);

    // configure Python includes Path
    jepConfig.addIncludePaths(paths);

    // add Python shared modules - these should be CPython modules for Jep to handle specially
    for (String name : ghidrathonConfig.getPythonSharedModules()) {

      jepConfig.addSharedModules(name);
    }

    // configure Jep stdout
    if (ghidrathonConfig.getStdOut() != null) {

      jepConfig.redirectStdout(
          new WriterOutputStream(
              ghidrathonConfig.getStdOut(), System.getProperty("file.encoding")) {

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
              super.write(b, off, len);
              flush(); // flush the output to ensure it is displayed in real-time
            }
          });
    }

    // configure Jep stderr
    if (ghidrathonConfig.getStdErr() != null) {
      jepConfig.redirectStdErr(
          new WriterOutputStream(
              ghidrathonConfig.getStdErr(), System.getProperty("file.encoding")) {

            @Override
            public void write(byte[] b, int off, int len) throws IOException {
              super.write(b, off, len);
              flush(); // flush the error to ensure it is displayed in real-time
            }
          });
    }

    // we must set the native Jep library before creating a Jep instance
    setJepPaths();

    // create a new Jep interpreter instance
    jep = new jep.SubInterpreter(jepConfig);

    // now that everything is configured, we should be able to run some utility scripts
    // to help us further configure the Python environment
    setJepEval();
    setJepRunScript();
  }

  private PathMatcher getJepDllPathMatcher() throws Exception {
    String os = System.getProperty("os.name", "generic").toLowerCase(Locale.ENGLISH);
    if ((os.indexOf("mac") >= 0) || (os.indexOf("darwin") >= 0)) {
      String arch = System.getProperty("os.arch");
      if (arch == "amd64") {
        // x86
        return FileSystems.getDefault().getPathMatcher("glob:**libjep.so");
      } else if (arch == "arm64") {
        // arm m1
        // TODO: just guessing this arch name arm64
        return FileSystems.getDefault().getPathMatcher("glob:**libjep.jnilib");
      }
    } else if (os.indexOf("win") >= 0) {
        return FileSystems.getDefault().getPathMatcher("glob:**jep.dll");
    } else if (os.indexOf("nux") >= 0) {
        return FileSystems.getDefault().getPathMatcher("glob:**libjep.so");
    } else {
        throw new Exception("OS not implemented: " + os);
    }

    throw new Exception("OS not implemented: " + os);
  }

  private Path searchJepDll(Path path) {
    PathMatcher matcher;
    try {
      matcher = getJepDllPathMatcher();
    } catch (Exception e) {
      return null;
    }

    List<Path> dllPaths;
    try (Stream<Path> walk = Files.walk(path)) {
      dllPaths = walk
              .filter(Files::isRegularFile)
              .filter(x -> matcher.matches(x))
              .collect(Collectors.toList());

    } catch (IOException e) {
      return null;
    }

    if (dllPaths.isEmpty()) {
      return null;
    }

    if (dllPaths.size() > 1) {
      // not sure which to pick
      log.error("too many results in directory: " + path.toString());
      return null;
    }

    return dllPaths.stream().findFirst().get();
  }

  // DANGER: DO NOT PASS DYNAMIC COMMANDS HERE!
  private String execCmd(String ... commands) {
    Runtime runtime = Runtime.getRuntime();
    Process process = null;
    try {
      process = runtime.exec(commands);
    } catch (IOException e) {
      log.error("error: " + e.toString());
      return "";
    }

    BufferedReader lineReader = new BufferedReader(new java.io.InputStreamReader(process.getInputStream()));
    String output = String.join("\n", lineReader.lines().collect(Collectors.toList()));

    BufferedReader errorReader = new BufferedReader(new java.io.InputStreamReader(process.getErrorStream()));
    String error = String.join("\n", errorReader.lines().collect(Collectors.toList()));

    if (error.length() > 0) {
      log.error(error);
    }

    return output;
  }

  private Path findPythonPathJep() {
    String var = "PYTHONPATH";
    String env = System.getenv(var);
    if (env != null) {
      for (String envv : env.split(";")) {
        Path path = java.nio.file.FileSystems.getDefault().getPath(envv);
        Path location = searchJepDll(path);
        if (location != null) {
          // return first matching DLL
          return location;
        }
      }
    }
    return null;
  }

  private Path findVirtualEnvJep() {
    String var = "VIRTUAL_ENV";
    String env = System.getenv(var);
    if (env != null) {
      Path path = java.nio.file.FileSystems.getDefault().getPath(env);
      Path location = searchJepDll(path);
      if (location != null) {
        // return only matching DLL
        return location;
      }
    }
    return null;
  }

  private Path findSystemJep() {
    String output = execCmd("python3", "-c", "import sys; import base64; print((b' '.join(map(lambda s: base64.b64encode(s.encode('utf-8')), sys.path))).decode('ascii'))");

    Charset UTF8_CHARSET = Charset.forName("UTF-8");

    for (String base64 : output.split(" ")) {
      byte[] bytes = java.util.Base64.getDecoder().decode(base64);
      String s = new String(bytes, UTF8_CHARSET);

      Path path1 = java.nio.file.FileSystems.getDefault().getPath(s);
      Path location = searchJepDll(path1);

      if (location != null) {
        return location;
      }
    }

    return null;
  }

  private void setJepDll(Path path) {
    log.info("set JEP DLL: " + path.toString());
    try {
      MainInterpreter.setJepLibraryPath(path.toAbsolutePath().toString());
    } catch (IllegalStateException e) {
      // library path has already been set elsewhere, 
      // we expect this to happen as Jep Maininterpreter
      // thread exists forever once it's created
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
  private void setJepPaths() throws JepException, FileNotFoundException {
    // if this is set, it take precedence over VIRTUAL_ENV.
    Path pythonPathJep = findPythonPathJep();
    if (pythonPathJep != null) {
      log.info("found JEP dll via PYTHONPATH: " + pythonPathJep);
    }

    // if this is set, it takes precedence over system python
    Path virtualenvJep = findVirtualEnvJep();
    if (virtualenvJep != null) {
      log.info("found JEP dll via VIRTUAL_ENV: " + virtualenvJep);
    }

    // fall back to whatever python3 references
    Path systemJep = findSystemJep();
    if (systemJep != null) {
        log.info("found JEP dll via python3: " + systemJep);
    }

    if (pythonPathJep != null) {
      setJepDll(pythonPathJep);
    } else if (virtualenvJep != null) {
      setJepDll(virtualenvJep);
    } else if (systemJep != null) {
      setJepDll(systemJep);
    } else {
      log.error("unable to find jep");
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

    jep.runScript(file.getAbsolutePath());
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

    jep.runScript(file.getAbsolutePath());
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
    jep.runScript(file.getAbsolutePath());

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
            jep.invoke("jep_set_builtin", field.getName(), field.get(script));
          } catch (IllegalAccessException iae) {
            throw new JepException("Unexpected security manager being used!");
          }
        }
      }
    }

    if (!scriptMethodsInjected) {
      // inject GhidraScript methods into Python
      file =
          Application.getModuleDataFile(GhidrathonUtils.THIS_EXTENSION_NAME, "python/jepinject.py");
      jep.set("__ghidra_script__", script);
      jep.runScript(file.getAbsolutePath());
    }

    scriptMethodsInjected = true;
  }

  /**
   * Create a new GhidrathonInterpreter instance.
   *
   * @return GhidrathonInterpreter
   * @throws RuntimeException
   */
  public static GhidrathonInterpreter get(GhidrathonConfig ghidrathonConfig)
      throws RuntimeException {

    try {

      return new GhidrathonInterpreter(ghidrathonConfig);

    } catch (Exception e) {

      e.printStackTrace();
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

      if (jep != null) {
        jep.close();
        jep = null;
      }

    } catch (JepException e) {

      e.printStackTrace();
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

      jep.set(name, o);

    } catch (JepException e) {

      e.printStackTrace();
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

      return (boolean) jep.invoke("jepeval", line);

    } catch (JepException e) {

      // Python exceptions should be handled in Python land; something bad must have happened
      e.printStackTrace();
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
      e.printStackTrace();
      throw new RuntimeException(e);
    }

    try {

      return (boolean) jep.invoke("jepeval", line);

    } catch (JepException e) {

      // Python exceptions should be handled in Python land; something bad must have happened
      e.printStackTrace();
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

      jep.invoke("jep_runscript", file.getAbsolutePath());

    } catch (JepException e) {

      // Python exceptions should be handled in Python land; something bad must have happened
      e.printStackTrace();
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
      jep.invoke("jep_runscript", file.getAbsolutePath());

    } catch (JepException | FileNotFoundException e) {

      // Python exceptions should be handled in Python land; something bad must have happened
      e.printStackTrace();
      throw new RuntimeException(e);
    }
  }

  public void printWelcome() {

    try {

      ResourceFile file =
          Application.getModuleDataFile(
              GhidrathonUtils.THIS_EXTENSION_NAME, "python/jepwelcome.py");

      jep.set("GhidraVersion", Application.getApplicationVersion());

      jep.runScript(file.getAbsolutePath());

    } catch (JepException | FileNotFoundException e) {

      e.printStackTrace();
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
