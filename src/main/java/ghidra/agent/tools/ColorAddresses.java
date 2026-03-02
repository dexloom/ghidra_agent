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

import java.awt.Color;
import java.util.*;

import com.google.gson.*;

import ghidra.app.plugin.core.colorizer.ColorizingService;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.address.*;
import ghidra.program.model.listing.*;

/**
 * Highlights addresses in the Ghidra listing using the ColorizingService.
 * Makes analysis results immediately visible in the code browser.
 */
public class ColorAddresses implements AgentTool {

	private static final Map<String, Color> NAMED_COLORS;
	static {
		NAMED_COLORS = new HashMap<>();
		NAMED_COLORS.put("red", new Color(0xFF6B6B));
		NAMED_COLORS.put("orange", new Color(0xFFAA44));
		NAMED_COLORS.put("yellow", new Color(0xFFEE55));
		NAMED_COLORS.put("green", new Color(0x88DD66));
		NAMED_COLORS.put("blue", new Color(0x66AAFF));
		NAMED_COLORS.put("purple", new Color(0xCC88FF));
		NAMED_COLORS.put("pink", new Color(0xFF99CC));
		NAMED_COLORS.put("cyan", new Color(0x66DDEE));
		NAMED_COLORS.put("white", Color.WHITE);
		NAMED_COLORS.put("clear", null);
	}

	@Override
	public String getName() {
		return "color_addresses";
	}

	@Override
	public String getDescription() {
		return "Highlight addresses in the Ghidra listing with a background color. " +
			"Use this to visually annotate findings: color vulnerabilities red, " +
			"crypto functions purple, string references yellow, etc. " +
			"Colors are named: red, orange, yellow, green, blue, purple, pink, cyan, white, clear (removes color). " +
			"Accepts a list of hex addresses or a function name to color the entire function body.";
	}

	@Override
	public String getParameterSchema() {
		return """
				{
				  "type": "object",
				  "properties": {
				    "addresses": {
				      "type": "array",
				      "items": { "type": "string" },
				      "description": "List of hex addresses to color."
				    },
				    "function_name": {
				      "type": "string",
				      "description": "Color the entire body of this function."
				    },
				    "function_address": {
				      "type": "string",
				      "description": "Color the entire body of the function at this address."
				    },
				    "color": {
				      "type": "string",
				      "description": "Color name: red, orange, yellow, green, blue, purple, pink, cyan, white, clear."
				    }
				  },
				  "required": ["color"]
				}
				""";
	}

	@Override
	public String execute(AgentContext ctx, String argsJson) throws Exception {
		JsonObject args = JsonParser.parseString(argsJson).getAsJsonObject();
		if (!args.has("color")) {
			return "ERROR: 'color' is required.";
		}

		String colorName = args.get("color").getAsString().toLowerCase();
		if (!NAMED_COLORS.containsKey(colorName)) {
			return "ERROR: Unknown color '" + colorName + "'. Use: " +
				String.join(", ", NAMED_COLORS.keySet());
		}
		Color color = NAMED_COLORS.get(colorName);

		PluginTool tool = ctx.getTool();
		ColorizingService service = tool.getService(ColorizingService.class);
		if (service == null) {
			return "ERROR: ColorizingService not available. Ensure the Colorizer plugin is loaded.";
		}

		Program program = ctx.getProgram();
		AddressSet addrSet = new AddressSet();

		// Add explicitly listed addresses
		if (args.has("addresses")) {
			for (JsonElement elem : args.getAsJsonArray("addresses")) {
				try {
					Address addr =
						program.getAddressFactory().getAddress(elem.getAsString());
					if (addr != null) {
						addrSet.add(addr);
					}
				}
				catch (Exception e) {
					// skip bad addresses
				}
			}
		}

		// Add function body by name or address
		Function fn = null;
		FunctionManager fm = program.getFunctionManager();
		if (args.has("function_address")) {
			Address addr = program.getAddressFactory()
					.getAddress(args.get("function_address").getAsString());
			if (addr != null) {
				fn = fm.getFunctionAt(addr);
				if (fn == null) {
					fn = fm.getFunctionContaining(addr);
				}
			}
		}
		if (fn == null && args.has("function_name")) {
			String name = args.get("function_name").getAsString();
			for (Function f : fm.getFunctions(true)) {
				if (f.getName().equals(name)) {
					fn = f;
					break;
				}
			}
		}
		if (fn != null) {
			addrSet.add(fn.getBody());
		}

		if (addrSet.isEmpty()) {
			return "ERROR: No valid addresses or functions specified.";
		}

		if (color == null) {
			// "clear" removes coloring
			service.clearBackgroundColor(addrSet.getMinAddress(), addrSet.getMaxAddress());
		}
		else {
			service.setBackgroundColor(addrSet, color);
		}

		JsonObject response = new JsonObject();
		response.addProperty("success", true);
		response.addProperty("color", colorName);
		response.addProperty("address_count", addrSet.getNumAddressRanges());
		if (fn != null) {
			response.addProperty("function", fn.getName());
		}
		return new Gson().toJson(response);
	}
}
