// Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
// You may obtain a copy of the License at: [package root]/LICENSE.txt
// Unless required by applicable law or agreed to in writing, software distributed under the License
//  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package ghidrathon.interpreter;

import java.io.File;
import java.lang.reflect.*;
import java.io.PrintWriter;
import java.io.IOException;
import java.io.FileNotFoundException;

import generic.jar.ResourceFile;

import ghidra.framework.Application;
import ghidra.app.script.GhidraScript;
import ghidra.app.script.GhidraScriptUtil;

import jep.Jep;
import jep.JepConfig;
import jep.JepException;
import jep.MainInterpreter;

import ghidrathon.GhidrathonScript;

/**
 * Utility class used to configure a Jep instance to access Ghidra
 */
public class GhidrathonInterpreter {

	private Jep jep;
	private JepConfig config;

	private boolean scriptMethodsInjected = false;

	private PrintWriter err = null;
	private PrintWriter out = null;
	
	private static String extname = Application.getMyModuleRootDirectory().getName();
	
	/**
	 * Create and configure a new GhidrathonInterpreter instance.
	 * 
	 * @throws JepException
	 * @throws IOException 
	 */
	private GhidrathonInterpreter() throws JepException, IOException{
		
		// configure the Python includes path with the user's Ghdira script directory
		String paths = "";
		for (ResourceFile resourceFile : GhidraScriptUtil.getScriptSourceDirectories()) {
			paths += resourceFile.getFile(false).getAbsolutePath() + File.pathSeparator;
		}
		
		// add data/python/ to Python includes directory
		paths += Application.getModuleDataSubDirectory(extname, "python") + File.pathSeparator;
		
		config = new JepConfig();
		
		// set the class loader with access to Ghidra scripting API
		config.setClassLoader(ClassLoader.getSystemClassLoader());
		
		// configure Python includes Path
		config.addIncludePaths(paths);
		
		// we must set the native Jep library before creating a Jep instance
		setJepNativeBinaryPath();
		
		// create a new Jep interpreter instance
		jep = new jep.SubInterpreter(config);
		
		// now that everything is configured, we should be able to run some utility scripts
		// to help us further configure the Python environment
		setJepEval();
		setJepRunScript();

	}
	
	/**
	 * Configure native Jep library.
	 * 
	 * User must build and include native Jep library in the appropriate OS folder prior to
	 * building this extension.
	 * Requires os/win64/libjep.dll for Windows
	 * Requires os/linux64/libjep.so for Linux
	 * 
	 * @throws JepException
	 * @throws FileNotFoundException
	 */
	private void setJepNativeBinaryPath() throws JepException, FileNotFoundException {
		
		File nativeJep;
		
		try {
			
			nativeJep = Application.getOSFile(extname, "libjep.so");
			
		} catch (FileNotFoundException e) {
			
			// whoops try Windows
			nativeJep = Application.getOSFile(extname, "jep.dll");

		}
		
		try {
			
			MainInterpreter.setJepLibraryPath(nativeJep.getAbsolutePath());
			
		} catch (IllegalStateException e) {
			// library path has already been set elsewhere, we expect this to happen as Jep Maininterpreter
			// thread exists forever once it's created
		}
		
	}

	
	/**
	 * Configure "jepeval" function in Python land.
	 * 
	 * We use Python to evaluate Python statements because as of Jep 4.0 interactive mode
	 * is no longer supported. As a side effect we also get better tracebacks.
	 * Requires data/python/jepeval.py.
	 * 
	 * @throws JepException
	 * @throws FileNotFoundException
	 */
	private void setJepEval() throws JepException, FileNotFoundException {
		
		ResourceFile file = Application.getModuleDataFile(extname, "python/jepeval.py");
		
		jep.runScript(file.getAbsolutePath());
		
	}

	/**
	 * Configure "jep_runscript" function in Python land.
	 * 
	 * We use Python to run Python scripts because it gives us better access to tracebacks.
	 * Requires data/python/jeprunscript.py.
	 * 
	 * @throws JepException
	 * @throws FileNotFoundException
	 */
	private void setJepRunScript() throws JepException, FileNotFoundException {
		
		ResourceFile file = Application.getModuleDataFile(extname, "python/jeprunscript.py");
		
		jep.runScript(file.getAbsolutePath());
		
	}
		
	/**
	 * Configure GhidraState.
	 * 
	 * This exposes things like currentProgram, currentAddress, etc. similar to Jython. We need to repeat this
	 * prior to executing new Python code in order to provide the latest state e.g. that current currentAddress.
	 * Requires data/python/jepinject.py.
	 * 
	 * @param script GhidrathonScript instance
	 * @throws JepException
	 * @throws FileNotFoundException
	 */
	private void injectScriptHierarchy(GhidraScript script) throws JepException, FileNotFoundException {
		if (script == null) {
			return;
		}

		// inject GhidraScript public/private fields e.g. currentAddress into Python
		// see https://github.com/NationalSecurityAgency/ghidra/blob/master/Ghidra/Features/Python/src/main/java/ghidra/python/GhidraPythonInterpreter.java#L341-L377
		for (Class<?> scriptClass = script.getClass(); scriptClass != Object.class; scriptClass =
			scriptClass.getSuperclass()) {
			for (Field field : scriptClass.getDeclaredFields()) {
				if (Modifier.isPublic(field.getModifiers()) ||
					Modifier.isProtected(field.getModifiers())) {
					try {
						field.setAccessible(true);
						jep.set(field.getName(), field.get(script));
					}
					catch (IllegalAccessException iae) {
						throw new JepException("Unexpected security manager being used!");
					}
				}
			}
		}

		if (!scriptMethodsInjected) {
			// inject GhidraScript methods into Python
			ResourceFile file = Application.getModuleDataFile(extname, "python/jepinject.py");
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
	public static GhidrathonInterpreter get() throws RuntimeException {
		
		try {
			
			return new GhidrathonInterpreter();
			
		} catch (Exception e) {
			
			e.printStackTrace();
			throw new RuntimeException(e);
			
		}
		
	}
	
	/**
	 * Close Jep instance.
	 * 
	 * We must call this function when finished with a Jep instance, otherwise, issues arise if we try to create a 
	 * new Jep instance on the same thread. This function must be called from the same thread that created the Jep instance.
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
	 * This function must be called from the same thread that instantiated the Jep instance.
	 * 
	 * @param line Python statement
	 * 
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
	 * This function must be called from the same thread that instantiated the Jep instance.
	 * 
	 * @param line Python statement
	 * @param script GhidrathonScript with desired state.
	 * 
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
	 * This function must be called from the same thread that instantiated the Jep instance.
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
	 * This function must be called from the same thread that instantiated the Jep instance.
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
	
	/**
	 * Set output and error streams for Jep instance.
	 * 
	 * Output and error streams from Python interpreter are redirected to the specified streams. If these are not set, this data is lost.
	 * 
	 * @param out output stream
	 * @param err error stream
	 */
	public void setStreams(PrintWriter out, PrintWriter err) {
		
		try {
			
			ResourceFile file = Application.getModuleDataFile(extname, "python/jepstream.py");
			
			jep.set("GhidraPluginToolConsoleOutWriter", out);
			jep.set("GhidraPluginToolConsoleErrWriter", err);
			
			jep.runScript(file.getAbsolutePath());
			
			this.out = out;
			this.err = err;
			
		} catch (JepException | FileNotFoundException e) {
			
			// ensure stack trace prints to err stream for user
			e.printStackTrace();
			throw new RuntimeException(e);
			
		}
		
	}
	
	public void printWelcome() {
		
		try {
			
			ResourceFile file = Application.getModuleDataFile(extname, "python/jepwelcome.py");

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