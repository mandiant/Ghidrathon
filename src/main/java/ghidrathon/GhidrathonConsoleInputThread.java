// Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
// You may obtain a copy of the License at: [package root]/LICENSE.txt
// Unless required by applicable law or agreed to in writing, software distributed under the License
//  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express
// or implied.
// See the License for the specific language governing permissions and limitations under the
// License.

package ghidrathon;

import db.Transaction;
import generic.jar.ResourceFile;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;
import ghidra.app.script.GhidraState;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;
import ghidra.util.task.TaskMonitor;
import ghidrathon.interpreter.GhidrathonInterpreter;
import java.io.BufferedReader;
import java.io.File;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.util.concurrent.atomic.AtomicBoolean;

import java.util.concurrent.*;

public class GhidrathonConsoleInputThread extends Thread {
  public static interface GhidrathonREPLCallable<T> {
    public abstract T call(GhidrathonInterpreter python);
  }
  
  public static class GhidrathonREPLThread extends Thread {
    private static int generationCount = 0;

    private GhidrathonConfig config;
    GhidrathonInterpreter python = null;

    private AtomicBoolean shouldContinue = new AtomicBoolean(true);
    private LinkedBlockingQueue<RunnableFuture<?>> tasks = new LinkedBlockingQueue<>();

    public GhidrathonREPLThread(GhidrathonConfig config) {
      super("Ghidrathon console repl thread (generation " + ++generationCount + ")");
      this.config = config;
    }

    private void abort() {
      shouldContinue.set(false);

      while (!tasks.isEmpty()) {
        try {
          tasks.take().cancel(true);
        } catch (InterruptedException e) {}
      }
    }

    @Override
    public void run() {
      try {
        python = GhidrathonInterpreter.get(config);
      } catch (RuntimeException e) {
        if (python != null) {
          python.close();
        }

        abort();
        e.printStackTrace(config.getStdErr());
        return;
      }

      while (shouldContinue.get() || !tasks.isEmpty()) {
        try {
          tasks.take().run();
        } catch (InterruptedException e) {
          e.printStackTrace(config.getStdErr());
        }
      }
      python.close();
    }

    public <T> Future<T> submitTask(final GhidrathonREPLCallable<T> f) throws InterruptedException {
      if (!shouldContinue.get()) {
        throw new IllegalStateException("Cannot submit task. REPL thread was already disposed");
      }

      final GhidrathonREPLThread self = this;

      RunnableFuture<T> result = new FutureTask<T>(() -> f.call(self.python));
      tasks.put(result);

      return result;
    }

    public void dispose() {
      // This order prevents race conditions
      // We set shouldContinue to false first and then wake up the thread
      // This ensures that when the thread processes
      shouldContinue.set(false);
      
      // no-op future to wake up the thread
      try {
        tasks.put(new FutureTask<Object>(() -> null));
      } catch (InterruptedException e) {
        // This shouldn't happen, but there is nothing we can do except log the error
        e.printStackTrace(config.getStdErr());
      }
    }
  }

  private static int generationCount = 0;

  private GhidrathonPlugin plugin = null;
  private InterpreterConsole console = null;
  private GhidrathonREPLThread repl = null;

  private AtomicBoolean shouldContinue = new AtomicBoolean(true);
  private GhidrathonConfig config = GhidrathonUtils.getDefaultGhidrathonConfig();

  GhidrathonConsoleInputThread(GhidrathonPlugin plugin) {

    super("Ghidrathon console input thread (generation " + ++generationCount + ")");

    this.plugin = plugin;
    this.console = plugin.getConsole();

    // init Ghidrathon configuration
    config.addStdErr(console.getErrWriter());
    config.addStdOut(console.getOutWriter());
  }

  public GhidrathonREPLThread getREPL() {
    return repl;
  }

  /**
   * Console input thread.
   *
   * <p>This thread passes Python statements from Java to Python to be evaluated. The interpreter is
   * is configured to print stdout and stderr to the console Window. Multi-line Python blocks are
   * supported but this is mostly handled in by the interpreter.
   */
  @Override
  public void run() {

    console.clear();

    repl = new GhidrathonREPLThread(config);
    repl.start();

    try {

      repl.submitTask((python) -> {
          python.printWelcome();
          return null;
        }).get();

    } catch (InterruptedException | ExecutionException e) {
      e.printStackTrace(config.getStdErr());
      Msg.error(GhidrathonConsoleInputThread.class, "Failed to start ghidrathon console.", e);

      repl.dispose();
      return;
    }

    try (BufferedReader reader = new BufferedReader(new InputStreamReader(console.getStdin()))) {

      plugin.flushConsole();
      console.setPrompt(repl.python.getPrimaryPrompt());

      // begin reading and passing input from console stdin to Python to be evaluated
      while (shouldContinue.get()) {

        String line;

        if (console.getStdin().available() > 0) {
          line = reader.readLine();
        } else {
          try {

            Thread.sleep(50);

          } catch (InterruptedException e) {

          }

          continue;
        }

        boolean moreInputWanted = evalPython(line);

        this.plugin.flushConsole();
        this.console.setPrompt(
            moreInputWanted ? repl.python.getSecondaryPrompt() : repl.python.getPrimaryPrompt());
      }

    } catch (InterruptedException | ExecutionException e) {
      e.printStackTrace(config.getStdErr());

      Msg.error(GhidrathonConsoleInputThread.class, "Failed to evaluate python. Please reset", e);
    } catch (IOException e) {

      e.printStackTrace();
      Msg.error(
          GhidrathonConsoleInputThread.class,
          "Internal error reading commands from python console. Please reset.",
          e);

    } finally {

      repl.dispose();
    }
  }

  /**
   * Configures Ghidra state and passes Python statement to Python.
   *
   * <p>This function must be called by the same thread that created the Jep instance. See
   * https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Python/src/main/java/ghidra/python/PythonPluginExecutionThread.java#L55
   *
   * @param line Python to evaluate
   * @return True if more input needed, otherwise False
   * @throws RuntimeException
   */
  private boolean evalPython(String line) throws InterruptedException, ExecutionException {

    boolean status;

    TaskMonitor interactiveTaskMonitor = plugin.getInteractiveTaskMonitor();
    GhidrathonScript interactiveScript = plugin.getInteractiveScript();
    Program program = plugin.getCurrentProgram();

    try (Transaction tx = program != null ? program.openTransaction("Ghidrathon console command") : null) {

      interactiveTaskMonitor.clearCanceled();
      interactiveScript.setSourceFile(new ResourceFile(new File("Ghidrathon")));
      PluginTool tool = plugin.getTool();

      interactiveScript.set(
          new GhidraState(
              tool,
              tool.getProject(),
              program,
              plugin.getProgramLocation(),
              plugin.getProgramSelection(),
              plugin.getProgramHighlight()),
          interactiveTaskMonitor,
          new PrintWriter(console.getStdOut()));

      status = repl.submitTask((python) -> python.eval(line, interactiveScript)).get();
      
    } finally {
      interactiveScript.end(false);
    }

    return status;
  }

  void dispose() {

    shouldContinue.set(false);
  }
}
