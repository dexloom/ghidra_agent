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

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;

/**
 * Renames a function and optionally sets a comment describing its purpose.
 * All mutations are wrapped in a named transaction for undo support.
 */
public class RenameFunction implements AgentTool {

	@Override
	public String getName() {
		return "rename_function";
	}

	@Override
	public String getDescription() {
		return "Rename a function and optionally add a plate comment describing what it does. " +
			"Always call get_decompiled_code first to understand the function before renaming. " +
			"All changes are undoable via Ctrl+Z.";
	}

	@Override
	public String getParameterSchema() {
		return """
				{
				  "type": "object",
				  "properties": {
				    "address": {
				      "type": "string",
				      "description": "Hex address of the function, e.g. \\"0x401000\\"."
				    },
				    "current_name": {
				      "type": "string",
				      "description": "Current function name (used to look up the function if address not provided)."
				    },
				    "new_name": {
				      "type": "string",
				      "description": "The new name to assign to the function."
				    },
				    "comment": {
				      "type": "string",
				      "description": "Optional plate comment to set on the function (describe what it does)."
				    }
				  },
				  "required": ["new_name"]
				}
				""";
	}

	@Override
	public String execute(AgentContext ctx, String argsJson) throws Exception {
		Program program = ctx.getProgram();
		JsonObject args = JsonParser.parseString(argsJson).getAsJsonObject();

		if (!args.has("new_name")) {
			return "ERROR: 'new_name' is required.";
		}
		String newName = args.get("new_name").getAsString();

		Function fn = resolveFunction(program, args);
		if (fn == null) {
			return "ERROR: Function not found. Provide a valid 'address' or 'current_name'.";
		}

		String oldName = fn.getName();
		int tx = program.startTransaction("AI Agent: rename function");
		try {
			fn.setName(newName, SourceType.USER_DEFINED);

			if (args.has("comment")) {
				String comment = args.get("comment").getAsString();
				program.getListing().setComment(fn.getEntryPoint(),
					CodeUnit.PLATE_COMMENT, comment);
			}

			program.endTransaction(tx, true);

			JsonObject response = new JsonObject();
			response.addProperty("success", true);
			response.addProperty("old_name", oldName);
			response.addProperty("new_name", fn.getName());
			response.addProperty("address", fn.getEntryPoint().toString());
			return new Gson().toJson(response);
		}
		catch (Exception e) {
			program.endTransaction(tx, false);
			return "ERROR: Failed to rename function: " + e.getMessage();
		}
	}

	private Function resolveFunction(Program program, JsonObject args) {
		FunctionManager fm = program.getFunctionManager();

		if (args.has("address")) {
			try {
				Address addr = program.getAddressFactory()
						.getAddress(args.get("address").getAsString());
				if (addr != null) {
					Function fn = fm.getFunctionAt(addr);
					if (fn == null) {
						fn = fm.getFunctionContaining(addr);
					}
					return fn;
				}
			}
			catch (Exception e) {
				// fall through
			}
		}

		if (args.has("current_name")) {
			String name = args.get("current_name").getAsString();
			for (Function fn : fm.getFunctions(true)) {
				if (fn.getName().equals(name)) {
					return fn;
				}
			}
		}

		return null;
	}
}
