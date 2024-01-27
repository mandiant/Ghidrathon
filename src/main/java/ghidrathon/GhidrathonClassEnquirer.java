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

import java.util.ArrayList;
import java.util.List;
import jep.ClassEnquirer;
import jep.ClassList;

/**
 * Implements Jep ClassEnquirer used to handle Java imports from Python - specifically we use this
 * class to handle naming conflicts, e.g. pdb
 */
public class GhidrathonClassEnquirer implements ClassEnquirer {

  private final List<String> javaExcludeLibs = new ArrayList<String>();
  private final ClassEnquirer classList = ClassList.getInstance();

  public void addJavaExcludeLib(String name) {
    javaExcludeLibs.add(name);
  }

  public void addJavaExcludeLibs(List<String> names) {
    javaExcludeLibs.addAll(names);
  }

  public boolean isJavaPackage(String name) {
    if (javaExcludeLibs.contains(name)) {
      return false;
    }

    return classList.isJavaPackage(name);
  }

  public String[] getClassNames(String name) {
    return classList.getClassNames(name);
  }

  public String[] getSubPackages(String name) {
    return classList.getSubPackages(name);
  }
}
