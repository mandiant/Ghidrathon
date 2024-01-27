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

import ghidra.framework.Application;
import ghidra.framework.options.SaveState;
import ghidra.util.Msg;
import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;

/** Utility functions */
public class GhidrathonUtils {

  // name of this extension e.g. "Ghidrathon"
  public static final String THIS_EXTENSION_NAME = Application.getMyModuleRootDirectory().getName();

  private static final String DEFAULT_CONFIG_FILENAME = "GhidrathonConfig.xml";
  private static final String JAVA_EXCLUDE_LIBS_KEY = "JAVA_EXCLUDE_LIBS";
  private static final String PY_SHARED_MODULES_KEY = "PYTHON_SHARED_MODULES";
  private static final String PY_INCLUDE_PATHS_KEY = "PYTHON_INCLUDE_PATHS";

  /**
   * Get Ghidrathon's default configuration - default configuration is stored in data/ and copied to
   * Ghidra user settings directory when first accessed
   */
  public static GhidrathonConfig getDefaultGhidrathonConfig() {

    GhidrathonConfig config = new GhidrathonConfig();
    File userSettingsPath =
        new File(Application.getUserSettingsDirectory(), DEFAULT_CONFIG_FILENAME);

    // copy configuration from /data to Ghidra user settings if file does not already exist
    if (!userSettingsPath.isFile()) {

      Msg.info(
          GhidrathonUtils.class, "Addings configuration to user settings at " + userSettingsPath);

      try {

        File dataPath =
            Application.getModuleDataFile(THIS_EXTENSION_NAME, DEFAULT_CONFIG_FILENAME)
                .getFile(false);
        Files.copy(
            dataPath.toPath(), userSettingsPath.toPath(), StandardCopyOption.REPLACE_EXISTING);

      } catch (IOException e) {

        Msg.error(GhidrathonUtils.class, "Failed to write user configuration [" + e + "]");
        return config;
      }
    }

    SaveState state = null;

    // attempt to read configuration from Ghidra user settings
    try {

      state = new SaveState(userSettingsPath);

    } catch (IOException e) {

      Msg.error(GhidrathonUtils.class, "Failed to read configuration state [" + e + "]");
      return config;
    }

    // add Java exclude libs that will be ignored when importing from Python - this is used to avoid
    // naming conflicts, e.g. "pdb"
    for (String name : state.getStrings(JAVA_EXCLUDE_LIBS_KEY, new String[0])) {

      config.addJavaExcludeLib(name);
    }

    // add Python include paths
    for (String name : state.getStrings(PY_INCLUDE_PATHS_KEY, new String[0])) {

      config.addPythonIncludePath(name);
    }

    // add Python shared modules - these modules are handled specially by Jep to avoid crashes
    // caused
    // by CPython extensions, e.g. numpy
    for (String name : state.getStrings(PY_SHARED_MODULES_KEY, new String[0])) {

      config.addPythonSharedModule(name);
    }

    return config;
  }
}
