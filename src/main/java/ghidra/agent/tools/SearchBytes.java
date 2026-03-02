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

import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.mem.Memory;

/**
 * Scans program memory for a byte pattern (hex string with optional wildcards).
 * Pattern format: space-separated hex bytes, use "??" for wildcard bytes.
 * Example: "55 8b ec ?? ?? ff 15"
 */
public class SearchBytes implements AgentTool {

	private static final int MAX_RESULTS = 200;

	@Override
	public String getName() {
		return "search_bytes";
	}

	@Override
	public String getDescription() {
		return "Search program memory for a byte pattern. Use hex bytes separated by spaces. " +
			"Use '??' as a wildcard for any byte. Example: '55 8b ec ?? ?? 6a 00'. " +
			"Returns matching addresses and the containing function name. " +
			"Ideal for finding malware signatures, function prologues, or specific opcodes.";
	}

	@Override
	public String getParameterSchema() {
		return """
				{
				  "type": "object",
				  "properties": {
				    "pattern": {
				      "type": "string",
				      "description": "Hex byte pattern with optional '??' wildcards. E.g. '55 8b ec ?? ?? ff 15'."
				    },
				    "max_results": {
				      "type": "integer",
				      "description": "Maximum number of matches to return. Default: 50."
				    }
				  },
				  "required": ["pattern"]
				}
				""";
	}

	@Override
	public String execute(AgentContext ctx, String argsJson) throws Exception {
		JsonObject args = JsonParser.parseString(argsJson).getAsJsonObject();
		if (!args.has("pattern")) {
			return "ERROR: 'pattern' is required.";
		}

		String pattern = args.get("pattern").getAsString().trim();
		int maxResults = args.has("max_results") ? args.get("max_results").getAsInt() : 50;
		maxResults = Math.min(maxResults, MAX_RESULTS);

		Program program = ctx.getProgram();
		Memory memory = program.getMemory();
		FunctionManager fm = program.getFunctionManager();

		// Parse the pattern into bytes and mask arrays
		String[] parts = pattern.split("\\s+");
		byte[] bytes = new byte[parts.length];
		byte[] mask = new byte[parts.length];

		for (int i = 0; i < parts.length; i++) {
			if (parts[i].equals("??") || parts[i].equals("?")) {
				bytes[i] = 0;
				mask[i] = 0;
			}
			else {
				bytes[i] = (byte) Integer.parseInt(parts[i], 16);
				mask[i] = (byte) 0xFF;
			}
		}

		JsonArray matches = new JsonArray();
		Address searchFrom = program.getMinAddress();

		while (matches.size() < maxResults && searchFrom != null) {
			Address found = memory.findBytes(searchFrom, bytes, mask, true, null);
			if (found == null) {
				break;
			}

			JsonObject match = new JsonObject();
			match.addProperty("address", found.toString());

			Function fn = fm.getFunctionContaining(found);
			match.addProperty("function", fn != null ? fn.getName() : "<no function>");
			match.addProperty("function_address",
				fn != null ? fn.getEntryPoint().toString() : "");

			// Read the actual bytes at this location for context
			byte[] actual = new byte[Math.min(parts.length, 16)];
			memory.getBytes(found, actual);
			StringBuilder hex = new StringBuilder();
			for (byte b : actual) {
				hex.append(String.format("%02x ", b));
			}
			match.addProperty("bytes", hex.toString().trim());
			matches.add(match);

			// Advance past this match
			searchFrom = found.add(1);
			if (searchFrom == null || searchFrom.compareTo(found) <= 0) {
				break; // overflow
			}
		}

		JsonObject response = new JsonObject();
		response.addProperty("pattern", pattern);
		response.addProperty("match_count", matches.size());
		response.add("matches", matches);
		if (matches.size() >= maxResults) {
			response.addProperty("note",
				"Results capped at " + maxResults + ". Increase max_results for more.");
		}
		return new Gson().toJson(response);
	}
}
