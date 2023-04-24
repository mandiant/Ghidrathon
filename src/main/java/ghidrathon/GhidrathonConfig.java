// Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
// You may obtain a copy of the License at: [package root]/LICENSE.txt
// Unless required by applicable law or agreed to in writing, software distributed under the License
//  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package ghidrathon;

import java.util.List;
import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;

public class GhidrathonConfig {

	private final List<String> javaExcludeLibs = new ArrayList<String>();
	private final List<String> pythonIncludePaths = new ArrayList<String>();
	private final List<String> pythonSharedModules = new ArrayList<String>();

	private PrintWriter out = null;
	private PrintWriter err = null;

	public void addStdOut(PrintWriter out) {
		this.out = out;
	}

	public void addStdErr(PrintWriter err) {
		this.err = err;
	}

	public PrintWriter getStdOut() {
		return out;
	}

	public PrintWriter getStdErr() {
		return err;
	}

	public void addPythonSharedModule(String name) {
		pythonSharedModules.add(name);
	}

	public void addPythonSharedModules(List<String> names) {
		pythonSharedModules.addAll(names);
	}

	public Iterable<String> getPythonSharedModules() {
		return Collections.unmodifiableList(pythonSharedModules);
	}

	public void addJavaExcludeLib(String name) {
		javaExcludeLibs.add(name);
	}

	public void addJavaExcludeLibs(List<String> names) {
		javaExcludeLibs.addAll(names);
	}

	public Iterable<String> getJavaExcludeLibs() {
		return Collections.unmodifiableList(javaExcludeLibs);
	}

	public void addPythonIncludePath(String path) {
		pythonIncludePaths.add(path);
	}

	public void addPythonIncludePaths(List<String> paths) {
		pythonIncludePaths.addAll(paths);
	}

	public Iterable<String> getPythonIncludePaths() {
		return Collections.unmodifiableList(pythonIncludePaths);
	}
}