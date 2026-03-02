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

/**
 * Places a Ghidra bookmark at an address so analysis results are visible
 * in the Bookmarks panel and persist in the project database.
 */
public class SetBookmark implements AgentTool {

	@Override
	public String getName() {
		return "set_bookmark";
	}

	@Override
	public String getDescription() {
		return "Place a bookmark at an address to annotate analysis findings. Bookmarks are " +
			"visible in the Ghidra Bookmarks panel (Window > Bookmarks) and persist in the " +
			"project. Use this to mark vulnerabilities, interesting functions, or anything " +
			"the analyst should review. Type should be one of: 'Analysis', 'Warning', 'Error', 'Note'.";
	}

	@Override
	public String getParameterSchema() {
		return """
				{
				  "type": "object",
				  "properties": {
				    "address": {
				      "type": "string",
				      "description": "Hex address to bookmark, e.g. \\"0x401234\\"."
				    },
				    "type": {
				      "type": "string",
				      "enum": ["Analysis", "Warning", "Error", "Note"],
				      "description": "Bookmark type. Default: \\"Note\\"."
				    },
				    "category": {
				      "type": "string",
				      "description": "Category label, e.g. \\"Vulnerability\\", \\"Crypto\\", \\"C2\\"."
				    },
				    "comment": {
				      "type": "string",
				      "description": "Description of why this address is interesting."
				    }
				  },
				  "required": ["address", "comment"]
				}
				""";
	}

	@Override
	public String execute(AgentContext ctx, String argsJson) throws Exception {
		JsonObject args = JsonParser.parseString(argsJson).getAsJsonObject();
		if (!args.has("address") || !args.has("comment")) {
			return "ERROR: 'address' and 'comment' are required.";
		}

		Program program = ctx.getProgram();
		Address addr = program.getAddressFactory().getAddress(args.get("address").getAsString());
		if (addr == null) {
			return "ERROR: Invalid address.";
		}

		String type = args.has("type") ? args.get("type").getAsString() : "Note";
		String category = args.has("category") ? args.get("category").getAsString() : "AI Agent";
		String comment = args.get("comment").getAsString();

		int tx = program.startTransaction("AI Agent: set bookmark");
		try {
			BookmarkManager bm = program.getBookmarkManager();
			bm.setBookmark(addr, type, category, comment);
			program.endTransaction(tx, true);

			JsonObject response = new JsonObject();
			response.addProperty("success", true);
			response.addProperty("address", addr.toString());
			response.addProperty("type", type);
			response.addProperty("category", category);
			response.addProperty("comment", comment);
			return new Gson().toJson(response);
		}
		catch (Exception e) {
			program.endTransaction(tx, false);
			return "ERROR: Failed to set bookmark: " + e.getMessage();
		}
	}
}
