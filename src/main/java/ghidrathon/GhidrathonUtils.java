// Copyright (C) 2022 Mandiant, Inc. All Rights Reserved.
// Licensed under the Apache License, Version 2.0 (the "License");
//  you may not use this file except in compliance with the License.
// You may obtain a copy of the License at: [package root]/LICENSE.txt
// Unless required by applicable law or agreed to in writing, software distributed under the License
//  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and limitations under the License.

package ghidrathon;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

import ghidra.util.Msg;
import ghidra.framework.Application;
import ghidra.framework.options.SaveState;

import ghidrathon.GhidrathonConfig;

public class GhidrathonUtils {

	private static String defaultConfigFilename = "GhidrathonConfig.xml";
	private static String javaExcludeLibsKey = "JAVA_EXCLUDE_LIBS";
	private static String pythonSharedModulesKey = "PYTHON_SHARED_MODULES";
	private static String pythonIncludePathsKey = "PYTHON_INCLUDE_PATHS";
	
	// extension name e.g. "Ghidrathon"	
	private static String extname = Application.getMyModuleRootDirectory().getName();

	public static GhidrathonConfig getDefaultGhidrathonConfig() {

		GhidrathonConfig config = new GhidrathonConfig();

		File userConfigPath = new File(Application.getUserSettingsDirectory(), defaultConfigFilename);

		if (!userConfigPath.isFile()) {
			Msg.info(GhidrathonUtils.class, "adding configuration to user settings at " + userConfigPath);

			// user configuration does not exist, copy default to user settings directory
			try {

				File defaultConfigPath = Application.getModuleDataFile(extname, defaultConfigFilename).getFile(false);
				Files.copy(defaultConfigPath.toPath(), userConfigPath.toPath(), StandardCopyOption.REPLACE_EXISTING);

			} catch (IOException e) {
 
				Msg.error(GhidrathonUtils.class, "failed to write user configuration [" + e + "]");
				return config;

			}
		}

		SaveState state = null;
		try {
			state = new SaveState(userConfigPath);
		} catch (IOException e) {
			Msg.error(GhidrathonUtils.class, "failed to read configuration state [" + e + "]");
			return config;
		}

		for (String name: state.getStrings(javaExcludeLibsKey, new String[0])) {
			config.addJavaExcludeLib(name);
		}

		for (String name: state.getStrings(pythonIncludePathsKey, new String[0])) {
			config.addPythonIncludePath(name);
		}

		for (String name: state.getStrings(pythonSharedModulesKey, new String[0])) {
			config.addPythonSharedModule(name);
		}

		return config;
	}

}
