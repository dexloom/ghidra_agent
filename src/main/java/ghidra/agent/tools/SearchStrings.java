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
import ghidra.program.model.symbol.*;
import ghidra.program.util.string.*;
import ghidra.util.task.TaskMonitor;

/**
 * Finds string constants in the binary using Ghidra's StringSearcher.
 * Supports ASCII and Unicode, minimum length filtering, and substring filtering.
 */
public class SearchStrings implements AgentTool {

	private static final int MAX_RESULTS = 500;

	@Override
	public String getName() {
		return "search_strings";
	}

	@Override
	public String getDescription() {
		return "Find string constants in the binary (ASCII, UTF-16). Optionally filter by a " +
			"substring (case-insensitive). Returns the string value, address, and any " +
			"cross-references to it. Useful for finding error messages, URLs, commands, " +
			"registry keys, and other interesting literals.";
	}

	@Override
	public String getParameterSchema() {
		return """
				{
				  "type": "object",
				  "properties": {
				    "filter": {
				      "type": "string",
				      "description": "Optional substring to filter strings (case-insensitive)."
				    },
				    "min_length": {
				      "type": "integer",
				      "description": "Minimum string length in characters. Default: 4."
				    },
				    "max_results": {
				      "type": "integer",
				      "description": "Maximum number of results. Default: 100."
				    },
				    "include_xrefs": {
				      "type": "boolean",
				      "description": "Include cross-references (callers) for each string. Default: false."
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

		String filter = args.has("filter") ? args.get("filter").getAsString().toLowerCase() : null;
		int minLength = args.has("min_length") ? args.get("min_length").getAsInt() : 4;
		int maxResults = args.has("max_results") ? args.get("max_results").getAsInt() : 100;
		boolean includeXrefs = args.has("include_xrefs") && args.get("include_xrefs").getAsBoolean();
		final int limit = Math.min(maxResults, MAX_RESULTS);

		Program program = ctx.getProgram();
		ReferenceManager refMgr = program.getReferenceManager();
		FunctionManager fm = program.getFunctionManager();

		List<JsonObject> results = new ArrayList<>();

		StringSearcher searcher = new StringSearcher(program, minLength, 1, true, true);
		searcher.search(program.getMemory().getLoadedAndInitializedAddressSet(),
			foundString -> {
				if (results.size() >= limit) {
					return; // already have enough
				}
				String value = foundString.getString(program.getMemory());
				if (value == null || value.isBlank()) {
					return;
				}
				if (filter != null && !value.toLowerCase().contains(filter)) {
					return;
				}

				JsonObject entry = new JsonObject();
				entry.addProperty("address", foundString.getAddress().toString());
				entry.addProperty("value", value);
				entry.addProperty("length", value.length());
				entry.addProperty("type", foundString.getDataType().getName());

				if (includeXrefs) {
					JsonArray xrefs = new JsonArray();
					for (Reference ref : refMgr.getReferencesTo(foundString.getAddress())) {
						JsonObject xref = new JsonObject();
						xref.addProperty("from", ref.getFromAddress().toString());
						Function fn = fm.getFunctionContaining(ref.getFromAddress());
						xref.addProperty("function", fn != null ? fn.getName() : "<unknown>");
						xrefs.add(xref);
					}
					entry.add("xrefs", xrefs);
				}

				results.add(entry);
			}, true, TaskMonitor.DUMMY);

		JsonArray arr = new JsonArray();
		results.forEach(arr::add);

		JsonObject response = new JsonObject();
		response.addProperty("total_found", results.size());
		response.addProperty("min_length", minLength);
		if (filter != null) {
			response.addProperty("filter", filter);
		}
		response.add("strings", arr);
		if (results.size() >= limit) {
			response.addProperty("note",
				"Results capped at " + limit + ". Increase max_results for more.");
		}
		return new Gson().toJson(response);
	}
}
