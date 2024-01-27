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
import ghidra.app.script.GhidraScriptLoadException;
import ghidra.app.script.GhidraScriptProvider;
import java.io.FileWriter;
import java.io.IOException;
import java.io.PrintWriter;

public class GhidrathonScriptProvider extends GhidraScriptProvider {

  @Override
  public String getDescription() {

    return "Python 3";
  }

  @Override
  public String getExtension() {

    return ".py";
  }

  @Override
  public GhidraScript getScriptInstance(ResourceFile sourceFile, PrintWriter writer)
      throws GhidraScriptLoadException {
    try {
      GhidraScript script;
      script = GhidrathonScript.class.getDeclaredConstructor().newInstance();
      script.setSourceFile(sourceFile);

      return script;
    } catch (ReflectiveOperationException e) {
      throw new GhidraScriptLoadException("Unable to instantiate: " + e.getMessage(), e);
    }
  }

  @Override
  public void createNewScript(ResourceFile newScript, String category) throws IOException {

    PrintWriter writer = new PrintWriter(new FileWriter(newScript.getFile(false)));

    writeHeader(writer, category);
    writer.println("");
    writeBody(writer);
    writer.println("");
    writer.close();
  }

  @Override
  public String getCommentCharacter() {

    return "#";
  }

  /**
   * Commandeer the .py script extension
   *
   * <p>Ghidra loads script providers in order determined by Collections.sort; Ghidra then selects
   * the first script provider that accepts the file extension of the script to be executed see
   * https://github.com/NationalSecurityAgency/ghidra/blob/8b2ea61e27c07c48dc21eff9095905f739208703/Ghidra/Features/Base/src/main/java/ghidra/app/script/GhidraScriptUtil.java#L274-L281
   *
   * <p>Collections.sort invokes GhidraScriptProvider.compareTo so we can override compareTo and
   * check if the script provider we are being compared to uses the .py extension; if true, we
   * simply return -1 to be ordered higher in the list of script providers used by Ghidra
   */
  @Override
  public int compareTo(GhidraScriptProvider that) {

    if (that.getExtension().equals(".py")) {
      // return -1 so our script provider is preferred
      return -1;
    }

    return super.compareTo(that);
  }
}
