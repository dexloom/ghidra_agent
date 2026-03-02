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

import ghidra.app.util.cparser.C.CParserUtils;
import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;
import ghidra.program.model.symbol.SourceType;
import ghidra.util.task.TaskMonitor;

/**
 * Applies a C-style function signature (prototype) to a function, setting
 * parameter names, types, and the return type. Improves decompiler output.
 * All changes are transaction-wrapped for undo support.
 */
public class SetFunctionSignature implements AgentTool {

	@Override
	public String getName() {
		return "set_function_signature";
	}

	@Override
	public String getDescription() {
		return "Apply a C-style function prototype to a function to improve decompiler output. " +
			"Provide the full signature as a C declaration, e.g. " +
			"'int recv(int sockfd, void *buf, size_t len, int flags)'. " +
			"You can also set individual parameter names and types. " +
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
				      "description": "Hex address of the function."
				    },
				    "name": {
				      "type": "string",
				      "description": "Function name to look up."
				    },
				    "return_type": {
				      "type": "string",
				      "description": "Return type name, e.g. 'int', 'void *', 'BOOL'."
				    },
				    "parameters": {
				      "type": "array",
				      "description": "List of parameters to apply.",
				      "items": {
				        "type": "object",
				        "properties": {
				          "name": { "type": "string" },
				          "type": { "type": "string", "description": "C type name, e.g. 'int', 'char *', 'size_t'" }
				        },
				        "required": ["name", "type"]
				      }
				    },
				    "calling_convention": {
				      "type": "string",
				      "description": "Calling convention name, e.g. '__cdecl', '__stdcall', '__fastcall'. Leave blank for default."
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
		Function fn = resolveFunction(program, args);
		if (fn == null) {
			return "ERROR: Function not found. Provide a valid 'address' or 'name'.";
		}

		DataTypeManager dtm = program.getDataTypeManager();
		int tx = program.startTransaction("AI Agent: set function signature");
		try {
			// Apply return type if provided
			if (args.has("return_type")) {
				DataType retType = resolveType(dtm, args.get("return_type").getAsString());
				if (retType != null) {
					fn.setReturnType(retType, SourceType.USER_DEFINED);
				}
			}

			// Apply parameters if provided
			if (args.has("parameters")) {
				JsonArray params = args.getAsJsonArray("parameters");
				List<Variable> newParams = new ArrayList<>();
				for (int i = 0; i < params.size(); i++) {
					JsonObject param = params.get(i).getAsJsonObject();
					String paramName = param.get("name").getAsString();
					DataType paramType = param.has("type")
							? resolveType(dtm, param.get("type").getAsString())
							: DataType.DEFAULT;
					if (paramType == null) {
						paramType = DataType.DEFAULT;
					}
					ParameterImpl p =
						new ParameterImpl(paramName, paramType, program);
					newParams.add(p);
				}
				fn.replaceParameters(newParams, Function.FunctionUpdateType.DYNAMIC_STORAGE_ALL_PARAMS,
					true, SourceType.USER_DEFINED);
			}

			// Apply calling convention if provided
			if (args.has("calling_convention")) {
				String cc = args.get("calling_convention").getAsString();
				if (!cc.isBlank()) {
					fn.setCallingConvention(cc);
				}
			}

			program.endTransaction(tx, true);

			JsonObject response = new JsonObject();
			response.addProperty("success", true);
			response.addProperty("function", fn.getName());
			response.addProperty("address", fn.getEntryPoint().toString());
			response.addProperty("signature", fn.getSignature().getPrototypeString());
			return new Gson().toJson(response);
		}
		catch (Exception e) {
			program.endTransaction(tx, false);
			return "ERROR: Failed to set signature: " + e.getMessage();
		}
	}

	private DataType resolveType(DataTypeManager dtm, String typeName) {
		if (typeName == null || typeName.isBlank()) {
			return null;
		}
		// Try direct lookup
		Iterator<DataType> iter = dtm.getAllDataTypes();
		while (iter.hasNext()) {
			DataType dt = iter.next();
			if (dt.getName().equalsIgnoreCase(typeName) ||
				dt.getDisplayName().equalsIgnoreCase(typeName)) {
				return dt;
			}
		}
		// Try built-in types
		BuiltInDataTypeManager builtIn = BuiltInDataTypeManager.getDataTypeManager();
		Iterator<DataType> builtInIter = builtIn.getAllDataTypes();
		while (builtInIter.hasNext()) {
			DataType dt = builtInIter.next();
			if (dt.getName().equalsIgnoreCase(typeName) ||
				dt.getDisplayName().equalsIgnoreCase(typeName)) {
				return dtm.resolve(dt, DataTypeConflictHandler.DEFAULT_HANDLER);
			}
		}
		return null;
	}

	private Function resolveFunction(Program program, JsonObject args) {
		FunctionManager fm = program.getFunctionManager();
		if (args.has("address")) {
			try {
				Address addr = program.getAddressFactory()
						.getAddress(args.get("address").getAsString());
				if (addr != null) {
					Function fn = fm.getFunctionAt(addr);
					return fn != null ? fn : fm.getFunctionContaining(addr);
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
