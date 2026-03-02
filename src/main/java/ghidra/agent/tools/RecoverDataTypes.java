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

import java.util.Iterator;

import com.google.gson.*;

import ghidra.program.model.address.Address;
import ghidra.program.model.data.*;
import ghidra.program.model.listing.*;

/**
 * Applies a named data type to an address in the program listing.
 * Supports creating structs from a field-description JSON and applying
 * existing built-in types by name (e.g., "int", "char *", "DWORD").
 * All changes are transaction-wrapped for undo support.
 */
public class RecoverDataTypes implements AgentTool {

	@Override
	public String getName() {
		return "recover_data_types";
	}

	@Override
	public String getDescription() {
		return "Apply a data type to an address in the program to improve decompilation. " +
			"You can apply a built-in type by name (e.g. 'int', 'char *', 'DWORD') or define " +
			"a new struct with fields. Changes are undoable via Ctrl+Z.";
	}

	@Override
	public String getParameterSchema() {
		return """
				{
				  "type": "object",
				  "properties": {
				    "address": {
				      "type": "string",
				      "description": "Hex address where the type should be applied."
				    },
				    "type_name": {
				      "type": "string",
				      "description": "Name of an existing built-in or previously-defined type (e.g. 'int', 'char *', 'DWORD')."
				    },
				    "struct_name": {
				      "type": "string",
				      "description": "Name of a new struct type to create (used with 'fields')."
				    },
				    "fields": {
				      "type": "array",
				      "description": "List of struct fields for creating a new struct.",
				      "items": {
				        "type": "object",
				        "properties": {
				          "name": { "type": "string" },
				          "type": { "type": "string", "description": "Field type name, e.g. 'int', 'char *'" },
				          "comment": { "type": "string" }
				        },
				        "required": ["name", "type"]
				      }
				    }
				  },
				  "required": ["address"]
				}
				""";
	}

	@Override
	public String execute(AgentContext ctx, String argsJson) throws Exception {
		Program program = ctx.getProgram();
		JsonObject args = JsonParser.parseString(argsJson).getAsJsonObject();

		if (!args.has("address")) {
			return "ERROR: 'address' is required.";
		}

		Address addr = program.getAddressFactory().getAddress(args.get("address").getAsString());
		if (addr == null) {
			return "ERROR: Invalid address.";
		}

		DataTypeManager dtm = program.getDataTypeManager();
		DataType dataType = null;

		// Create a new struct if fields are provided
		if (args.has("struct_name") && args.has("fields")) {
			dataType = createStruct(dtm, args);
		}
		else if (args.has("type_name")) {
			dataType = resolveTypeName(dtm, args.get("type_name").getAsString());
		}

		if (dataType == null) {
			return "ERROR: Could not resolve data type. Provide 'type_name' or 'struct_name' + 'fields'.";
		}

		int tx = program.startTransaction("AI Agent: apply data type");
		try {
			Listing listing = program.getListing();
			// Clear any existing data at the location first
			listing.clearCodeUnits(addr, addr.add(dataType.getLength() - 1), false);
			Data data = listing.createData(addr, dataType);

			program.endTransaction(tx, true);

			JsonObject response = new JsonObject();
			response.addProperty("success", true);
			response.addProperty("address", addr.toString());
			response.addProperty("type_applied", dataType.getName());
			response.addProperty("length", data.getLength());
			return new Gson().toJson(response);
		}
		catch (Exception e) {
			program.endTransaction(tx, false);
			return "ERROR: Failed to apply data type: " + e.getMessage();
		}
	}

	private DataType createStruct(DataTypeManager dtm, JsonObject args) {
		String structName = args.get("struct_name").getAsString();
		StructureDataType struct =
			new StructureDataType(new CategoryPath("/AgentTypes"), structName, 0, dtm);

		for (JsonElement fieldElem : args.getAsJsonArray("fields")) {
			JsonObject field = fieldElem.getAsJsonObject();
			String fieldName = field.get("name").getAsString();
			String typeName = field.get("type").getAsString();
			String comment = field.has("comment") ? field.get("comment").getAsString() : "";

			DataType fieldType = resolveTypeName(dtm, typeName);
			if (fieldType != null) {
				struct.add(fieldType, fieldName, comment);
			}
		}

		// Add or replace in the data type manager
		int tx = dtm.startTransaction("AI Agent: create struct");
		try {
			DataType existing = dtm.getDataType("/AgentTypes/" + structName);
			if (existing != null) {
				dtm.remove(existing, null);
			}
			return dtm.addDataType(struct, DataTypeConflictHandler.REPLACE_HANDLER);
		}
		finally {
			dtm.endTransaction(tx, true);
		}
	}

	private DataType resolveTypeName(DataTypeManager dtm, String typeName) {
		// Try built-in C types first
		DataType dt = dtm.getDataType("/" + typeName);
		if (dt != null) {
			return dt;
		}

		// Search all data types
		Iterator<DataType> iter = dtm.getAllDataTypes();
		while (iter.hasNext()) {
			DataType candidate = iter.next();
			if (candidate.getName().equalsIgnoreCase(typeName)) {
				return candidate;
			}
		}

		// Fall back to BuiltInDataTypeManager
		BuiltInDataTypeManager builtIn = BuiltInDataTypeManager.getDataTypeManager();
		DataType builtInType = builtIn.getDataType("/" + typeName);
		if (builtInType != null) {
			return dtm.resolve(builtInType, DataTypeConflictHandler.DEFAULT_HANDLER);
		}

		return null;
	}
}
