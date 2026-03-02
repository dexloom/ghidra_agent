/* ###
 * IP: GHIDRA
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package ghidra.agent.tools;

import com.google.gson.*;

import ghidra.app.plugin.assembler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;

/**
 * Assembles and patches one or more instructions at a given address.
 * Uses Ghidra's built-in multi-architecture assembler — no external tools needed.
 * All writes are transaction-wrapped for undo support.
 */
public class AssemblePatch implements AgentTool {

	@Override
	public String getName() {
		return "assemble_patch";
	}

	@Override
	public String getDescription() {
		return "Assemble assembly instructions and write them to a specific address in the binary. " +
			"Uses the program's native instruction set (x86, ARM, MIPS, etc.) automatically. " +
			"Provide one or more instructions as strings. Examples: 'NOP', 'MOV EAX, 0', " +
			"'JMP 0x401234', 'RET'. All changes are undoable via Ctrl+Z.";
	}

	@Override
	public String getParameterSchema() {
		return """
				{
				  "type": "object",
				  "properties": {
				    "address": {
				      "type": "string",
				      "description": "Hex address where patching begins, e.g. \\"0x401000\\"."
				    },
				    "instructions": {
				      "type": "array",
				      "items": { "type": "string" },
				      "description": "Ordered list of assembly instructions to write, e.g. [\\"NOP\\", \\"NOP\\", \\"RET\\"]."
				    }
				  },
				  "required": ["address", "instructions"]
				}
				""";
	}

	@Override
	public String execute(AgentContext ctx, String argsJson) throws Exception {
		JsonObject args = JsonParser.parseString(argsJson).getAsJsonObject();
		if (!args.has("address") || !args.has("instructions")) {
			return "ERROR: 'address' and 'instructions' are required.";
		}

		Program program = ctx.getProgram();
		Address addr = program.getAddressFactory().getAddress(args.get("address").getAsString());
		if (addr == null) {
			return "ERROR: Invalid address.";
		}

		String[] instructions = new String[args.getAsJsonArray("instructions").size()];
		int i = 0;
		for (JsonElement elem : args.getAsJsonArray("instructions")) {
			instructions[i++] = elem.getAsString();
		}

		Assembler asm = Assemblers.getAssembler(program);

		int tx = program.startTransaction("AI Agent: assemble patch");
		try {
			InstructionIterator patched = asm.assemble(addr, instructions);

			JsonArray assembled = new JsonArray();
			Address current = addr;
			while (patched.hasNext()) {
				Instruction instr = patched.next();
				JsonObject entry = new JsonObject();
				entry.addProperty("address", instr.getAddress().toString());
				entry.addProperty("mnemonic", instr.getMnemonicString());
				StringBuilder bytes = new StringBuilder();
				for (byte b : instr.getBytes()) {
					bytes.append(String.format("%02x ", b));
				}
				entry.addProperty("bytes", bytes.toString().trim());
				assembled.add(entry);
				current = instr.getAddress();
			}

			program.endTransaction(tx, true);

			JsonObject response = new JsonObject();
			response.addProperty("success", true);
			response.addProperty("start_address", addr.toString());
			response.addProperty("instructions_patched", assembled.size());
			response.add("patched", assembled);
			return new Gson().toJson(response);
		}
		catch (AssemblySyntaxException e) {
			program.endTransaction(tx, false);
			return "ERROR: Assembly syntax error: " + e.getMessage();
		}
		catch (AssemblySemanticException e) {
			program.endTransaction(tx, false);
			return "ERROR: Assembly semantic error (instruction may be invalid for this architecture): " +
				e.getMessage();
		}
		catch (Exception e) {
			program.endTransaction(tx, false);
			return "ERROR: Patch failed: " + e.getMessage();
		}
	}
}
