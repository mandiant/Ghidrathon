// Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
// You may obtain a copy of the License at: [package root]/LICENSE.txt
// Unless required by applicable law or agreed to in writing, software distributed under the License
//  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package ghidrathon;

import java.io.File;
import java.io.PrintWriter;
import java.io.IOException;
import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.util.concurrent.atomic.AtomicBoolean;

import generic.jar.ResourceFile;

import ghidra.util.Msg;
import ghidra.app.script.GhidraState;
import ghidra.app.plugin.core.interpreter.InterpreterConsole;

import ghidrathon.GhidrathonUtils;
import ghidrathon.GhidrathonConfig;
import ghidrathon.interpreter.GhidrathonInterpreter;

public class GhidrathonConsoleInputThread extends Thread {

	private static int generationCount = 0;
	
	private GhidrathonPlugin plugin = null;
	private InterpreterConsole console = null;
	private GhidrathonInterpreter python = null;

	private AtomicBoolean shouldContinue = new AtomicBoolean(true);

	private final GhidrathonConfig config = GhidrathonUtils.getDefaultGhidrathonConfig();

	GhidrathonConsoleInputThread(GhidrathonPlugin plugin) {

		super("Ghidrathon console input thread (generation " + ++generationCount + ")");

		this.plugin = plugin;
		this.console = plugin.getConsole();

		// init Ghidrathon configuration
		config.addStdErr(console.getErrWriter());
		config.addStdOut(console.getOutWriter());

	}

	/**
	 * Console input thread.
	 * 
	 * This thread passes Python statements from Java to Python to be evaluated. The interpreter is
	 * is configured to print stdout and stderr to the console Window. Multi-line Python blocks are
	 * supported but this is mostly handled in by the interpreter.
	 */
	@Override
	public void run() {

		console.clear();

		try {

			python = GhidrathonInterpreter.get(config);
			
			python.printWelcome();

		} catch (RuntimeException e) {

			if (python != null) {
				python.close();
			}
			
			e.printStackTrace(config.getStdErr());
			return;

		}

		try (BufferedReader reader = new BufferedReader(new InputStreamReader(console.getStdin()))) {

			plugin.flushConsole();
			console.setPrompt(python.getPrimaryPrompt());
			
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
				this.console.setPrompt(moreInputWanted ? python.getSecondaryPrompt() : python.getPrimaryPrompt());
			}
			
		} catch (RuntimeException | IOException e) {

			e.printStackTrace();
			Msg.error(GhidrathonConsoleInputThread.class,
					"Internal error reading commands from python console. Please reset.", e);

		} finally {

			python.close();

		}
	}

	/**
	 * Configures Ghidra state and passes Python statement to Python.
	 * 
	 * This function must be called by the same thread that created the Jep instance.
	 * See https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Python/src/main/java/ghidra/python/PythonPluginExecutionThread.java#L55
	 * 
	 * @param line Python to evaluate
	 * @return True if more input needed, otherwise False
	 * @throws RuntimeException
	 */
	private boolean evalPython(String line) throws RuntimeException {

		boolean status;
		
		// set transaction for the execution
		int transactionNumber = -1;
		if (plugin.getCurrentProgram() != null) {
			transactionNumber = plugin.getCurrentProgram().startTransaction("Ghidrathon command");
		}

		// setup Ghidra state to be passed into interpreter
		plugin.getInteractiveTaskMonitor().clearCanceled();
		plugin.getInteractiveScript().setSourceFile(new ResourceFile(new File("Ghidrathon")));
		plugin.getInteractiveScript()
				.set(new GhidraState(plugin.getTool(), plugin.getTool().getProject(), plugin.getCurrentProgram(),
						plugin.getProgramLocation(), plugin.getProgramSelection(), plugin.getProgramHighlight()),
						plugin.getInteractiveTaskMonitor(), new PrintWriter(console.getStdOut()));

		try {
			
			status = python.eval(line, plugin.getInteractiveScript());
		
		} finally {
			
			if (plugin.getCurrentProgram() != null) {
				plugin.getCurrentProgram().endTransaction(transactionNumber, true);
			}
			
		}

		return status;

	}

	void dispose() {

		shouldContinue.set(false);

	}
}
