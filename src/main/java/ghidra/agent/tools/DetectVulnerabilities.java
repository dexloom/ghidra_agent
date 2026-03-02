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

import java.util.*;

import com.google.gson.*;

import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.*;

/**
 * Scans the binary for common vulnerability patterns by inspecting cross-references
 * to known dangerous functions and identifying suspicious call patterns.
 */
public class DetectVulnerabilities implements AgentTool {

	private static final List<String> DANGEROUS_FUNCTIONS = List.of(
		// Buffer overflow risks
		"strcpy", "strcat", "sprintf", "vsprintf", "gets",
		"scanf", "sscanf", "fscanf", "stpcpy",
		// Integer overflow / size issues
		"malloc", "calloc", "realloc",
		// Format string risks
		"printf", "fprintf", "syslog",
		// Command injection
		"system", "popen", "exec", "execve", "execl", "execlp",
		// Use-after-free candidates
		"free",
		// Unsafe string length
		"strlen");

	@Override
	public String getName() {
		return "detect_vulnerabilities";
	}

	@Override
	public String getDescription() {
		return "Scan the binary for common vulnerability patterns: calls to dangerous functions " +
			"(strcpy, sprintf, system, etc.), format-string sinks, and unsafe memory operations. " +
			"Returns a list of findings with addresses and context.";
	}

	@Override
	public String getParameterSchema() {
		return """
				{
				  "type": "object",
				  "properties": {
				    "categories": {
				      "type": "array",
				      "items": { "type": "string" },
				      "description": "Optional list of categories to scan: \\"buffer_overflow\\", \\"format_string\\", \\"command_injection\\", \\"memory\\". Defaults to all."
				    },
				    "max_results": {
				      "type": "integer",
				      "description": "Maximum number of findings to return. Default: 100."
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

		int maxResults = args.has("max_results") ? args.get("max_results").getAsInt() : 100;

		Set<String> enabledCategories = new HashSet<>();
		if (args.has("categories")) {
			for (JsonElement cat : args.getAsJsonArray("categories")) {
				enabledCategories.add(cat.getAsString());
			}
		}
		if (enabledCategories.isEmpty()) {
			enabledCategories.addAll(List.of("buffer_overflow", "format_string",
				"command_injection", "memory"));
		}

		JsonArray findings = new JsonArray();
		SymbolTable symbolTable = program.getSymbolTable();
		ReferenceManager refManager = program.getReferenceManager();
		FunctionManager fm = program.getFunctionManager();

		for (String dangerousFn : DANGEROUS_FUNCTIONS) {
			if (findings.size() >= maxResults) {
				break;
			}

			String category = categorize(dangerousFn);
			if (!enabledCategories.contains(category)) {
				continue;
			}

			// Find all symbols matching this name
			for (Symbol sym : symbolTable.getSymbols(dangerousFn)) {
				// Get all callers
				for (Reference ref : refManager.getReferencesTo(sym.getAddress())) {
					if (findings.size() >= maxResults) {
						break;
					}
					if (ref.getReferenceType().isCall()) {
						JsonObject finding = new JsonObject();
						finding.addProperty("category", category);
						finding.addProperty("dangerous_function", dangerousFn);
						finding.addProperty("call_site", ref.getFromAddress().toString());

						// Identify the containing function
						Function caller = fm.getFunctionContaining(ref.getFromAddress());
						finding.addProperty("caller_function",
							caller != null ? caller.getName() : "<unknown>");
						finding.addProperty("caller_address",
							caller != null ? caller.getEntryPoint().toString() : "");
						finding.addProperty("severity", getSeverity(dangerousFn));
						findings.add(finding);
					}
				}
			}
		}

		JsonObject response = new JsonObject();
		response.addProperty("total_findings", findings.size());
		response.addProperty("scanned_functions", DANGEROUS_FUNCTIONS.size());
		response.add("findings", findings);
		if (findings.size() >= maxResults) {
			response.addProperty("note",
				"Results capped at " + maxResults + ". Increase max_results for more.");
		}
		return new Gson().toJson(response);
	}

	private String categorize(String fn) {
		return switch (fn) {
			case "strcpy", "strcat", "sprintf", "vsprintf", "gets", "scanf", "sscanf",
					"fscanf", "stpcpy" -> "buffer_overflow";
			case "printf", "fprintf", "syslog" -> "format_string";
			case "system", "popen", "exec", "execve", "execl", "execlp" -> "command_injection";
			default -> "memory";
		};
	}

	private String getSeverity(String fn) {
		return switch (fn) {
			case "gets", "strcpy", "sprintf", "system", "execve" -> "HIGH";
			case "strcat", "vsprintf", "popen", "exec", "execl", "execlp",
					"scanf", "sscanf" -> "MEDIUM";
			default -> "LOW";
		};
	}
}
