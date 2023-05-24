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

    return ".py3";
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
}
