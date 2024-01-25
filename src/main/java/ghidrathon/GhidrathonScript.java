// Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
// You may obtain a copy of the License at: [package root]/LICENSE.txt
// Unless required by applicable law or agreed to in writing, software distributed under the License
//  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied.
// See the License for the specific language governing permissions and limitations under the
// License.

package ghidrathon;

import generic.jar.ResourceFile;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptProvider;
import ghidra.app.script.GhidraScriptUtil;
import ghidra.app.script.GhidraState;
import ghidra.app.services.ConsoleService;
import ghidra.framework.plugintool.PluginTool;
import ghidrathon.interpreter.GhidrathonInterpreter;
import java.io.FileNotFoundException;
import java.io.PrintWriter;

public class GhidrathonScript extends GhidraScript {

  @Override
  protected void run() {

    GhidrathonInterpreter python = null;
    GhidrathonConfig config = GhidrathonUtils.getDefaultGhidrathonConfig();

    // init Ghidrathon configuration
    config.addStdOut(getStdOut());
    config.addStdErr(getStdErr());

    try {

      python = GhidrathonInterpreter.get(config);

      // run Python script from Python interpreter
      python.runScript(getSourceFile(), this);

      // flush stdout and stderr to ensure all is printed to console window
      config.getStdErr().flush();
      config.getStdOut().flush();

    } catch (RuntimeException e) {

      e.printStackTrace(config.getStdErr());

    } finally {

      if (python != null) {
        python.close();
      }
    }
  }

  /**
   * Execute Python script using given script state See
   * https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Python/src/main/java/ghidra/python/PythonScript.java#L53
   *
   * @param name Script name to execute
   * @param scriptState Ghidra script state
   */
  @Override
  public void runScript(String name, GhidraState scriptState) {

    GhidrathonInterpreter python = null;
    GhidrathonConfig config = GhidrathonUtils.getDefaultGhidrathonConfig();

    config.addStdOut(getStdOut());
    config.addStdErr(getStdErr());

    try {

      python = GhidrathonInterpreter.get(config);

      ResourceFile source = GhidraScriptUtil.findScriptByName(name);
      if (source == null) {
        throw new FileNotFoundException("could not find file " + name);
      }

      GhidraScriptProvider provider = GhidraScriptUtil.getProvider(source);
      GhidraScript script = provider.getScriptInstance(source, writer);

      if (script == null) {
        throw new RuntimeException("could not init ghidra script instance");
      }

      if (scriptState == state) {
        updateStateFromVariables();
      }

      if (script instanceof GhidrathonScript) {
        script.set(scriptState, monitor, writer);

        GhidrathonScript ghidrathonScript = (GhidrathonScript) script;

        // run Python script using interpreter
        python.runScript(ghidrathonScript.getSourceFile(), ghidrathonScript);
      } else {
        script.execute(scriptState, monitor, writer);
      }

      if (scriptState == state) {
        loadVariablesFromState();
      }

    } catch (Exception e) {

      e.printStackTrace(config.getStdErr());

    } finally {

      if (python != null) {
        python.close();
      }
    }
  }

  private PrintWriter getStdOut() {

    PluginTool tool = state.getTool();

    if (tool != null) {
      ConsoleService console = tool.getService(ConsoleService.class);

      if (console != null) {
        return console.getStdOut();
      }
    }

    return new PrintWriter(System.out, true);
  }

  private PrintWriter getStdErr() {

    PluginTool tool = state.getTool();

    if (tool != null) {
      ConsoleService console = tool.getService(ConsoleService.class);

      if (console != null) {
        return console.getStdErr();
      }
    }

    return new PrintWriter(System.err, true);
  }

  @Override
  public String getCategory() {

    return "Ghidrathon";
  }
}
