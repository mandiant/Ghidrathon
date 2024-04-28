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

import ghidra.app.CorePluginPackage;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.plugin.ProgramPlugin;
import ghidra.app.plugin.core.console.CodeCompletion;
import ghidra.app.plugin.core.interpreter.InterpreterConnection;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.plugin.core.interpreter.InterpreterPanelService;
import ghidra.framework.options.OptionsChangeListener;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.util.task.TaskLauncher;
import ghidra.util.task.TaskMonitor;
import ghidra.util.task.TaskMonitorAdapter;
import java.io.OutputStream;
import java.io.PrintWriter;
import java.util.Collections;
import java.util.List;
import javax.swing.*;

// @formatter:off
@PluginInfo(
    status = PluginStatus.STABLE,
    packageName = CorePluginPackage.NAME,
    category = PluginCategoryNames.COMMON,
    shortDescription = "Python 3 Interpreter",
    description =
        "The FLARE team's open-source Python 3 interpreter console that is tightly integrated with"
            + " a loaded Ghidra program.",
    servicesRequired = {InterpreterPanelService.class},
    isSlowInstallation = true)
// @formatter:on

public class GhidrathonPlugin extends ProgramPlugin
    implements InterpreterConnection, OptionsChangeListener {

  private static final String VERSION = "4.0.0";

  private InterpreterConsole console;
  private GhidrathonConsoleInputThread inputThread;
  private TaskMonitor interactiveTaskMonitor;
  private GhidrathonScript interactiveScript;

  public GhidrathonPlugin(PluginTool tool) {

    super(tool);
  }

  InterpreterConsole getConsole() {

    return console;
  }

  public TaskMonitor getInteractiveTaskMonitor() {

    return interactiveTaskMonitor;
  }

  GhidrathonScript getInteractiveScript() {

    return interactiveScript;
  }

  public static String getVersion() {
    return VERSION;
  }

  @Override
  protected void init() {

    super.init();

    console =
        getTool().getService(InterpreterPanelService.class).createInterpreterPanel(this, false);
    console.addFirstActivationCallback(() -> resetInterpreter());
  }

  @Override
  public void optionsChanged(
      ToolOptions options, String optionName, Object oldValue, Object newValue) {
    // TODO Auto-generated method stub
  }

  @Override
  public String getTitle() {

    return "Ghidrathon";
  }

  @Override
  public ImageIcon getIcon() {
    // TODO Auto-generated method stub
    return null;
  }

  @Override
  public String toString() {

    return getPluginDescription().getName();
  }

  public void flushConsole() {

    this.getConsole().getOutWriter().flush();
    this.getConsole().getErrWriter().flush();
  }

  @Override
  public List<CodeCompletion> getCompletions(String cmd) {
    // TODO Auto-generated method stub
    return Collections.<CodeCompletion>emptyList();
  }

  private void resetInterpreter() {

    TaskLauncher.launchModal(
        "Resetting Ghidrathon...",
        () -> {
          resetInterpreterInBackground();
        });
  }

  @Override
  protected void dispose() {

    // Terminate the input thread
    if (inputThread != null) {
      inputThread.dispose();
      inputThread = null;
    }

    // Dispose of the console
    if (console != null) {
      console.dispose();
      console = null;
    }

    super.dispose();
  }

  private void resetInterpreterInBackground() {

    interactiveScript = new GhidrathonScript();
    interactiveTaskMonitor = new PythonInteractiveTaskMonitor(console.getStdOut());

    inputThread = new GhidrathonConsoleInputThread(this);
    inputThread.start();
  }

  class PythonInteractiveTaskMonitor extends TaskMonitorAdapter {

    private PrintWriter output = null;

    public PythonInteractiveTaskMonitor(PrintWriter stdOut) {
      output = stdOut;
    }

    public PythonInteractiveTaskMonitor(OutputStream stdout) {
      this(new PrintWriter(stdout));
    }

    @Override
    public void setMessage(String message) {
      output.println("<python-interactive>: " + message);
    }
  }
}
