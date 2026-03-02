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

import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

/**
 * Decompiles a function and returns the C pseudo-code.
 */
public class GetDecompiledCode implements AgentTool {

	@Override
	public String getName() {
		return "get_decompiled_code";
	}

	@Override
	public String getDescription() {
		return "Decompile a function at a given address and return the C pseudo-code. " +
			"Use this before renaming or analyzing a function to understand what it does.";
	}

	@Override
	public String getParameterSchema() {
		return """
				{
				  "type": "object",
				  "properties": {
				    "address": {
				      "type": "string",
				      "description": "Hex address of the function entry point, e.g. \\"0x401000\\"."
				    },
				    "name": {
				      "type": "string",
				      "description": "Alternatively, the exact function name to look up."
				    }
				  },
				  "required": []
				}
				""";
	}

	@Override
	public String execute(AgentContext ctx, String argsJson) throws Exception {
		Program program = ctx.getProgram();
		JsonObject args =
			argsJson != null ? JsonParser.parseString(argsJson).getAsJsonObject() : new JsonObject();

		Function fn = resolveFunction(program, args);
		if (fn == null) {
			return "ERROR: Function not found. Provide a valid 'address' or 'name'.";
		}

		DecompInterface decompiler = new DecompInterface();
		try {
			decompiler.openProgram(program);
			DecompileResults result =
				decompiler.decompileFunction(fn, 60, TaskMonitor.DUMMY);

			if (!result.decompileCompleted()) {
				return "ERROR: Decompilation failed: " + result.getErrorMessage();
			}

			DecompiledFunction decompiledFn = result.getDecompiledFunction();
			String code = decompiledFn != null ? decompiledFn.getC() : "(no C code produced)";

			JsonObject response = new JsonObject();
			response.addProperty("function_name", fn.getName());
			response.addProperty("address", fn.getEntryPoint().toString());
			response.addProperty("signature", fn.getSignature().getPrototypeString());
			response.addProperty("decompiled_code", code);
			return new Gson().toJson(response);
		}
		finally {
			decompiler.dispose();
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
				// fall through to name lookup
			}
		}

		if (args.has("name")) {
			String name = args.get("name").getAsString();
			for (Function fn : fm.getFunctions(true)) {
				if (fn.getName().equals(name)) {
					return fn;
				}
			}
		}

		return null;
	}
}
