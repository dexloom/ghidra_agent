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

import ghidra.program.model.address.Address;
import ghidra.program.model.block.*;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

/**
 * Returns the control-flow graph (CFG) of a function as a list of basic blocks
 * with their successors and predecessors.
 */
public class GetControlFlow implements AgentTool {

	@Override
	public String getName() {
		return "get_control_flow";
	}

	@Override
	public String getDescription() {
		return "Get the control-flow graph (CFG) of a function as a list of basic blocks. " +
			"Each block has a start/end address, the instructions it contains, and edges to " +
			"successor blocks. Useful for understanding loops, branches, and complex logic " +
			"before renaming or documenting a function.";
	}

	@Override
	public String getParameterSchema() {
		return """
				{
				  "type": "object",
				  "properties": {
				    "address": {
				      "type": "string",
				      "description": "Hex address of the function entry point."
				    },
				    "name": {
				      "type": "string",
				      "description": "Function name (used if address not provided)."
				    },
				    "include_instructions": {
				      "type": "boolean",
				      "description": "Include disassembly of each instruction in the block. Default: false."
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

		boolean includeInstr =
			args.has("include_instructions") && args.get("include_instructions").getAsBoolean();

		SimpleBlockModel model = new SimpleBlockModel(program);
		Listing listing = program.getListing();

		JsonArray blocks = new JsonArray();
		CodeBlockIterator iter =
			model.getCodeBlocksContaining(fn.getBody(), TaskMonitor.DUMMY);

		while (iter.hasNext()) {
			CodeBlock block = iter.next();
			JsonObject blockObj = new JsonObject();
			blockObj.addProperty("start", block.getFirstStartAddress().toString());
			blockObj.addProperty("end", block.getMaxAddress().toString());
			blockObj.addProperty("size", block.getNumAddresses());

			// Successors (outgoing edges)
			JsonArray successors = new JsonArray();
			CodeBlockReferenceIterator destIter =
				block.getDestinations(TaskMonitor.DUMMY);
			while (destIter.hasNext()) {
				CodeBlockReference ref = destIter.next();
				if (fn.getBody().contains(ref.getDestinationAddress())) {
					JsonObject edge = new JsonObject();
					edge.addProperty("to", ref.getDestinationAddress().toString());
					edge.addProperty("flow_type", ref.getFlowType().getName());
					successors.add(edge);
				}
			}
			blockObj.add("successors", successors);

			// Predecessors (incoming edges)
			JsonArray predecessors = new JsonArray();
			CodeBlockReferenceIterator srcIter = block.getSources(TaskMonitor.DUMMY);
			while (srcIter.hasNext()) {
				CodeBlockReference ref = srcIter.next();
				if (fn.getBody().contains(ref.getSourceAddress())) {
					predecessors.add(ref.getSourceAddress().toString());
				}
			}
			blockObj.add("predecessors", predecessors);

			if (includeInstr) {
				JsonArray instrs = new JsonArray();
				InstructionIterator instrIter = listing.getInstructions(block, true);
				while (instrIter.hasNext()) {
					Instruction instr = instrIter.next();
					instrs.add(instr.getAddress() + "  " + instr.toString());
				}
				blockObj.add("instructions", instrs);
			}

			blocks.add(blockObj);
		}

		JsonObject response = new JsonObject();
		response.addProperty("function", fn.getName());
		response.addProperty("entry_point", fn.getEntryPoint().toString());
		response.addProperty("block_count", blocks.size());
		response.add("blocks", blocks);
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
