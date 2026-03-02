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

import java.util.Set;

import com.google.gson.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

/**
 * Returns the callers and callees of a function — its immediate call-graph neighbours.
 */
public class GetCallersCallees implements AgentTool {

	@Override
	public String getName() {
		return "get_callers_callees";
	}

	@Override
	public String getDescription() {
		return "Get the callers (functions that call this function) and callees (functions called " +
			"by this function) for a given function. Essential for understanding call graph " +
			"relationships, finding attack surfaces, and tracing data flow.";
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
				      "description": "Function name (used if address not provided)."
				    },
				    "direction": {
				      "type": "string",
				      "enum": ["both", "callers", "callees"],
				      "description": "Which direction to query. Default: \\"both\\"."
				    }
				  },
				  "required": []
				}
				""";
	}

	@Override
	public String execute(AgentContext ctx, String argsJson) throws Exception {
		JsonObject args =
			argsJson != null ? JsonParser.parseString(argsJson).getAsJsonObject() : new JsonObject();

		Function fn = resolveFunction(ctx.getProgram(), args);
		if (fn == null) {
			return "ERROR: Function not found. Provide a valid 'address' or 'name'.";
		}

		String direction = args.has("direction") ? args.get("direction").getAsString() : "both";

		JsonObject response = new JsonObject();
		response.addProperty("function", fn.getName());
		response.addProperty("address", fn.getEntryPoint().toString());

		if (!direction.equals("callees")) {
			Set<Function> callers = fn.getCallingFunctions(TaskMonitor.DUMMY);
			JsonArray callersArr = new JsonArray();
			for (Function caller : callers) {
				JsonObject entry = new JsonObject();
				entry.addProperty("name", caller.getName());
				entry.addProperty("address", caller.getEntryPoint().toString());
				callersArr.add(entry);
			}
			response.add("callers", callersArr);
			response.addProperty("caller_count", callers.size());
		}

		if (!direction.equals("callers")) {
			Set<Function> callees = fn.getCalledFunctions(TaskMonitor.DUMMY);
			JsonArray calleesArr = new JsonArray();
			for (Function callee : callees) {
				JsonObject entry = new JsonObject();
				entry.addProperty("name", callee.getName());
				entry.addProperty("address", callee.getEntryPoint().toString());
				entry.addProperty("isExternal", callee.isExternal());
				calleesArr.add(entry);
			}
			response.add("callees", calleesArr);
			response.addProperty("callee_count", callees.size());
		}

		return new Gson().toJson(response);
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
