# Print function basic block and instruction counts.
# @author Mike Hunhoff (mehunhoff@google.com)
# @category Python 3

# Copyright (C) 2024 Mandiant, Inc. All Rights Reserved.
# Licensed under the Apache License, Version 2.0 (the "License");
#  you may not use this file except in compliance with the License.
# You may obtain a copy of the License at: [package root]/LICENSE.txt
# Unless required by applicable law or agreed to in writing, software distributed under the License
#  is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and limitations under the License.

from ghidra.program.model.block import BasicBlockModel, SimpleBlockIterator

for func in currentProgram().getListing().getFunctions(True):
    block_count = 0

    # find basic block count for the current function
    block_itr = SimpleBlockIterator(BasicBlockModel(currentProgram()), func.getBody(), monitor())
    while block_itr.hasNext():
        block_count += 1
        block_itr.next()

    # find instruction count for the current function
    insn_count = len(tuple(currentProgram().getListing().getInstructions(func.getBody(), True)))

    # print counts to user
    print(
        f"Function {func.getName()} @ {hex(func.getEntryPoint().getOffset())}: {block_count} blocks, {insn_count} instructions"
    )
