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

import ghidra.app.decompiler.*;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.program.model.pcode.*;
import ghidra.util.task.TaskMonitor;

/**
 * Analyzes a function's P-code (SSA intermediate representation) to answer
 * data-flow questions: what feeds into a variable, where does a value go,
 * what operations use a particular varnode, etc.
 */
public class AnalyzePcode implements AgentTool {

	@Override
	public String getName() {
		return "analyze_pcode";
	}

	@Override
	public String getDescription() {
		return "Analyze the P-code (SSA intermediate representation) of a function to answer " +
			"data-flow questions. Modes: " +
			"'summary' — count operation types and identify call sites; " +
			"'calls' — list all function calls with argument varnodes; " +
			"'stores' — list all memory write operations; " +
			"'loads' — list all memory read operations; " +
			"'variables' — list high-level variables with their types and usage count. " +
			"Use this to understand data flow before renaming variables or detecting vulnerabilities.";
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
				      "description": "Function name (used if address not provided)."
				    },
				    "mode": {
				      "type": "string",
				      "enum": ["summary", "calls", "stores", "loads", "variables"],
				      "description": "Analysis mode. Default: \\"summary\\"."
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

		String mode = args.has("mode") ? args.get("mode").getAsString() : "summary";

		DecompInterface decompiler = new DecompInterface();
		try {
			decompiler.openProgram(program);
			DecompileResults result =
				decompiler.decompileFunction(fn, 60, TaskMonitor.DUMMY);

			if (!result.decompileCompleted()) {
				return "ERROR: Decompilation failed: " + result.getErrorMessage();
			}

			HighFunction hf = result.getHighFunction();
			if (hf == null) {
				return "ERROR: No high-level function produced.";
			}

			return switch (mode) {
				case "calls" -> analyzeCalls(fn, hf, program);
				case "stores" -> analyzeStores(fn, hf);
				case "loads" -> analyzeLoads(fn, hf);
				case "variables" -> analyzeVariables(fn, hf);
				default -> analyzeSummary(fn, hf);
			};
		}
		finally {
			decompiler.dispose();
		}
	}

	private String analyzeSummary(Function fn, HighFunction hf) {
		Map<String, Integer> opCounts = new TreeMap<>();
		int callCount = 0, storeCount = 0, loadCount = 0;

		Iterator<PcodeOpAST> ops = hf.getPcodeOps();
		while (ops.hasNext()) {
			PcodeOpAST op = ops.next();
			String mnemonic = op.getMnemonic();
			opCounts.merge(mnemonic, 1, Integer::sum);
			if (op.getOpcode() == PcodeOp.CALL || op.getOpcode() == PcodeOp.CALLIND) {
				callCount++;
			}
			if (op.getOpcode() == PcodeOp.STORE) {
				storeCount++;
			}
			if (op.getOpcode() == PcodeOp.LOAD) {
				loadCount++;
			}
		}

		JsonObject response = new JsonObject();
		response.addProperty("function", fn.getName());
		response.addProperty("address", fn.getEntryPoint().toString());
		response.addProperty("total_pcode_ops", opCounts.values().stream().mapToInt(i -> i).sum());
		response.addProperty("call_count", callCount);
		response.addProperty("store_count", storeCount);
		response.addProperty("load_count", loadCount);

		JsonArray opArr = new JsonArray();
		opCounts.entrySet().stream()
				.sorted(Map.Entry.<String, Integer> comparingByValue().reversed())
				.forEach(e -> {
					JsonObject entry = new JsonObject();
					entry.addProperty("op", e.getKey());
					entry.addProperty("count", e.getValue());
					opArr.add(entry);
				});
		response.add("op_counts", opArr);
		return new Gson().toJson(response);
	}

	private String analyzeCalls(Function fn, HighFunction hf, Program program) {
		JsonArray calls = new JsonArray();
		Iterator<PcodeOpAST> ops = hf.getPcodeOps();

		while (ops.hasNext()) {
			PcodeOpAST op = ops.next();
			if (op.getOpcode() != PcodeOp.CALL && op.getOpcode() != PcodeOp.CALLIND) {
				continue;
			}

			JsonObject callObj = new JsonObject();
			callObj.addProperty("site", op.getSeqnum().getTarget().toString());

			// Target address
			Varnode target = op.getInput(0);
			if (target != null && target.isAddress()) {
				Address targetAddr = target.getAddress();
				callObj.addProperty("target", targetAddr.toString());
				Function called = program.getFunctionManager().getFunctionAt(targetAddr);
				callObj.addProperty("callee", called != null ? called.getName() : "<indirect>");
			}
			else {
				callObj.addProperty("target", "<indirect>");
				callObj.addProperty("callee", "<computed>");
			}

			// Arguments
			JsonArray argArr = new JsonArray();
			for (int i = 1; i < op.getNumInputs(); i++) {
				Varnode arg = op.getInput(i);
				JsonObject argObj = new JsonObject();
				argObj.addProperty("index", i - 1);
				argObj.addProperty("varnode", varnodeToString(arg));
				if (arg.isConstant()) {
					argObj.addProperty("constant_value", "0x" + Long.toHexString(arg.getOffset()));
				}
				argArr.add(argObj);
			}
			callObj.add("arguments", argArr);
			calls.add(callObj);
		}

		JsonObject response = new JsonObject();
		response.addProperty("function", fn.getName());
		response.addProperty("call_count", calls.size());
		response.add("calls", calls);
		return new Gson().toJson(response);
	}

	private String analyzeStores(Function fn, HighFunction hf) {
		JsonArray stores = new JsonArray();
		Iterator<PcodeOpAST> ops = hf.getPcodeOps();
		while (ops.hasNext()) {
			PcodeOpAST op = ops.next();
			if (op.getOpcode() != PcodeOp.STORE) {
				continue;
			}
			JsonObject s = new JsonObject();
			s.addProperty("site", op.getSeqnum().getTarget().toString());
			s.addProperty("dest_addr", varnodeToString(op.getInput(1)));
			s.addProperty("value", varnodeToString(op.getInput(2)));
			s.addProperty("size_bytes", op.getInput(2).getSize());
			stores.add(s);
		}
		JsonObject response = new JsonObject();
		response.addProperty("function", fn.getName());
		response.addProperty("store_count", stores.size());
		response.add("stores", stores);
		return new Gson().toJson(response);
	}

	private String analyzeLoads(Function fn, HighFunction hf) {
		JsonArray loads = new JsonArray();
		Iterator<PcodeOpAST> ops = hf.getPcodeOps();
		while (ops.hasNext()) {
			PcodeOpAST op = ops.next();
			if (op.getOpcode() != PcodeOp.LOAD) {
				continue;
			}
			JsonObject l = new JsonObject();
			l.addProperty("site", op.getSeqnum().getTarget().toString());
			l.addProperty("src_addr", varnodeToString(op.getInput(1)));
			l.addProperty("result", op.getOutput() != null ? varnodeToString(op.getOutput()) : "");
			l.addProperty("size_bytes", op.getOutput() != null ? op.getOutput().getSize() : 0);
			loads.add(l);
		}
		JsonObject response = new JsonObject();
		response.addProperty("function", fn.getName());
		response.addProperty("load_count", loads.size());
		response.add("loads", loads);
		return new Gson().toJson(response);
	}

	private String analyzeVariables(Function fn, HighFunction hf) {
		JsonArray variables = new JsonArray();

		// Parameters
		LocalSymbolMap symMap = hf.getLocalSymbolMap();
		Iterator<HighSymbol> symbols = symMap.getSymbols();
		while (symbols.hasNext()) {
			HighSymbol sym = symbols.next();
			JsonObject varObj = new JsonObject();
			varObj.addProperty("name", sym.getName());
			varObj.addProperty("type", sym.getDataType() != null
					? sym.getDataType().getDisplayName()
					: "unknown");
			varObj.addProperty("is_parameter", sym.isParameter());
			variables.add(varObj);
		}

		JsonObject response = new JsonObject();
		response.addProperty("function", fn.getName());
		response.addProperty("variable_count", variables.size());
		response.add("variables", variables);
		return new Gson().toJson(response);
	}

	private String varnodeToString(Varnode vn) {
		if (vn == null) {
			return "null";
		}
		if (vn.isConstant()) {
			return "const:0x" + Long.toHexString(vn.getOffset());
		}
		if (vn.isRegister()) {
			return "reg:" + vn.getAddress().toString();
		}
		if (vn.isUnique()) {
			return "tmp:0x" + Long.toHexString(vn.getOffset());
		}
		return vn.getAddress().toString();
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
