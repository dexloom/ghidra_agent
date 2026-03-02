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

import java.util.List;

import com.google.gson.*;

import ghidra.app.util.demangler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

/**
 * Demangles C++/Rust/Swift mangled symbol names, and optionally auto-demangles
 * all functions in the program that have mangled names.
 */
public class DemangleSymbol implements AgentTool {

	@Override
	public String getName() {
		return "demangle_symbol";
	}

	@Override
	public String getDescription() {
		return "Demangle a C++, Rust, or Swift mangled symbol name (e.g. '_ZN7MyClass7doThingEic') " +
			"to a human-readable form. Can also scan and demangle all unresolved mangled symbols " +
			"in the program. Supports GCC/Clang (itanium ABI), MSVC, Rust, and Swift.";
	}

	@Override
	public String getParameterSchema() {
		return """
				{
				  "type": "object",
				  "properties": {
				    "symbol": {
				      "type": "string",
				      "description": "A single mangled symbol to demangle, e.g. '_ZN7MyClass7doThingEic'."
				    },
				    "scan_all": {
				      "type": "boolean",
				      "description": "Scan all functions and demangle any that appear to be mangled. Default: false."
				    },
				    "max_scan": {
				      "type": "integer",
				      "description": "Max functions to scan when scan_all is true. Default: 200."
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

		Program program = ctx.getProgram();

		if (args.has("symbol")) {
			return demangleSingle(program, args.get("symbol").getAsString());
		}

		if (args.has("scan_all") && args.get("scan_all").getAsBoolean()) {
			return scanAll(program, args.has("max_scan") ? args.get("max_scan").getAsInt() : 200);
		}

		return "ERROR: Provide 'symbol' for a single demangle, or set 'scan_all': true to scan all functions.";
	}

	private String demangleSingle(Program program, String mangled) {
		List<DemangledObject> results = DemanglerUtil.demangle(program, mangled, null);
		if (results == null || results.isEmpty()) {
			JsonObject r = new JsonObject();
			r.addProperty("mangled", mangled);
			r.add("demangled", JsonNull.INSTANCE);
			r.addProperty("success", false);
			r.addProperty("note", "Could not demangle — may not be a mangled symbol.");
			return new Gson().toJson(r);
		}

		JsonArray arr = new JsonArray();
		for (DemangledObject obj : results) {
			JsonObject entry = new JsonObject();
			entry.addProperty("demangled", obj.getSignature(false));
			entry.addProperty("name", obj.getName());
			entry.addProperty("namespace",
				obj.getNamespace() != null ? obj.getNamespace().getNamespaceName() : "");
			arr.add(entry);
		}

		JsonObject r = new JsonObject();
		r.addProperty("mangled", mangled);
		r.addProperty("success", true);
		r.add("results", arr);
		return new Gson().toJson(r);
	}

	private String scanAll(Program program, int maxScan) {
		FunctionManager fm = program.getFunctionManager();
		JsonArray demangled = new JsonArray();
		int scanned = 0;

		for (Function fn : fm.getFunctions(true)) {
			if (scanned++ >= maxScan) {
				break;
			}
			String name = fn.getName();
			// Heuristic: mangled symbols start with _Z (GCC/Clang), _R (Rust), ?$ (MSVC)
			if (!looksMangled(name)) {
				continue;
			}

			List<DemangledObject> results =
				DemanglerUtil.demangle(program, name, fn.getEntryPoint());
			if (results == null || results.isEmpty()) {
				continue;
			}

			DemangledObject best = results.get(0);
			JsonObject entry = new JsonObject();
			entry.addProperty("address", fn.getEntryPoint().toString());
			entry.addProperty("mangled", name);
			entry.addProperty("demangled", best.getSignature(false));
			demangled.add(entry);
		}

		JsonObject response = new JsonObject();
		response.addProperty("total_demangled", demangled.size());
		response.addProperty("scanned", scanned);
		response.add("symbols", demangled);
		return new Gson().toJson(response);
	}

	private boolean looksMangled(String name) {
		return name.startsWith("_Z") ||     // GCC/Clang C++
			name.startsWith("_R") ||        // Rust v0
			name.startsWith("__Z") ||       // macOS GCC
			name.startsWith("?") ||         // MSVC
			name.startsWith("_$");          // Rust legacy
	}
}
