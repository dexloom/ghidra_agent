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

import java.util.ArrayList;
import java.util.List;

import com.google.gson.*;

import ghidra.program.model.listing.*;

/**
 * Lists all functions defined in the current program, with their addresses and names.
 */
public class ListFunctions implements AgentTool {


	private static final int MAX_FUNCTIONS = 500;

	@Override
	public String getName() {
		return "list_functions";
	}

	@Override
	public String getDescription() {
		return "List all functions in the currently open binary. Returns function names, " +
			"entry point addresses, and sizes. Results are capped at " + MAX_FUNCTIONS +
			" functions; use the 'offset' parameter to paginate.";
	}

	@Override
	public String getParameterSchema() {
		return """
				{
				  "type": "object",
				  "properties": {
				    "offset": {
				      "type": "integer",
				      "description": "Number of functions to skip (for pagination). Default: 0."
				    },
				    "filter": {
				      "type": "string",
				      "description": "Optional substring to filter function names (case-insensitive)."
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

		int offset = args.has("offset") ? args.get("offset").getAsInt() : 0;
		String filter =
			args.has("filter") ? args.get("filter").getAsString().toLowerCase() : null;

		FunctionManager fm = program.getFunctionManager();
		List<JsonObject> results = new ArrayList<>();
		int skipped = 0;

		for (Function fn : fm.getFunctions(true)) {
			String name = fn.getName();
			if (filter != null && !name.toLowerCase().contains(filter)) {
				continue;
			}
			if (skipped < offset) {
				skipped++;
				continue;
			}
			if (results.size() >= MAX_FUNCTIONS) {
				break;
			}
			JsonObject entry = new JsonObject();
			entry.addProperty("name", name);
			entry.addProperty("address", fn.getEntryPoint().toString());
			entry.addProperty("size", fn.getBody().getNumAddresses());
			entry.addProperty("isExternal", fn.isExternal());
			results.add(entry);
		}

		JsonObject response = new JsonObject();
		response.addProperty("total_returned", results.size());
		response.addProperty("offset", offset);
		JsonArray arr = new JsonArray();
		results.forEach(arr::add);
		response.add("functions", arr);
		return new Gson().toJson(response);
	}
}
