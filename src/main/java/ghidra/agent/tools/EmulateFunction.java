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

import java.math.BigInteger;
import java.util.Map;

import com.google.gson.*;

import ghidra.app.emulator.EmulatorHelper;
import ghidra.program.model.address.Address;
import ghidra.program.model.listing.*;
import ghidra.util.task.TaskMonitor;

/**
 * Emulates a function using Ghidra's P-code emulator with configurable
 * initial register/memory state. Useful for decoding obfuscated strings,
 * resolving dynamic dispatch, or tracing crypto key schedules.
 *
 * Execution is bounded by a maximum instruction count to prevent infinite loops.
 */
public class EmulateFunction implements AgentTool {

	private static final int DEFAULT_MAX_INSTRUCTIONS = 1000;
	private static final int STACK_SIZE = 0x10000;

	@Override
	public String getName() {
		return "emulate_function";
	}

	@Override
	public String getDescription() {
		return "Emulate a function using Ghidra's P-code emulator. Set initial register values " +
			"and read the resulting register/memory state. Ideal for: decoding obfuscated " +
			"strings (pass the encoded bytes in memory and read the output), resolving " +
			"computed jumps, and tracing crypto initialization. Execution stops at a " +
			"RETURN instruction or after max_instructions steps.";
	}

	@Override
	public String getParameterSchema() {
		return """
				{
				  "type": "object",
				  "properties": {
				    "address": {
				      "type": "string",
				      "description": "Hex address of the function to emulate."
				    },
				    "name": {
				      "type": "string",
				      "description": "Function name (used if address not provided)."
				    },
				    "registers": {
				      "type": "object",
				      "description": "Initial register values as {regName: hexValue}, e.g. {\\"RDI\\": \\"0x1234\\", \\"RSI\\": \\"0x10\\"}."
				    },
				    "memory": {
				      "type": "array",
				      "description": "Memory regions to initialize before emulation.",
				      "items": {
				        "type": "object",
				        "properties": {
				          "address": { "type": "string" },
				          "bytes": { "type": "string", "description": "Hex bytes, e.g. \\"48 65 6c 6c 6f\\"." }
				        }
				      }
				    },
				    "read_registers": {
				      "type": "array",
				      "items": { "type": "string" },
				      "description": "Register names to read after execution, e.g. [\\"RAX\\", \\"RBX\\"]."
				    },
				    "read_memory": {
				      "type": "array",
				      "description": "Memory addresses to read after execution.",
				      "items": {
				        "type": "object",
				        "properties": {
				          "address": { "type": "string" },
				          "length": { "type": "integer" }
				        }
				      }
				    },
				    "max_instructions": {
				      "type": "integer",
				      "description": "Maximum instructions to execute. Default: 1000."
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

		int maxInstructions = args.has("max_instructions")
				? args.get("max_instructions").getAsInt()
				: DEFAULT_MAX_INSTRUCTIONS;

		EmulatorHelper emu = new EmulatorHelper(program);
		try {
			// Set up stack pointer in a scratch region
			long stackBase = 0x00100000L;
			emu.writeRegister(emu.getStackPointerRegister(), stackBase + STACK_SIZE / 2);

			// Set breakpoint at the return instruction(s) — we'll single-step instead
			Address entryPoint = fn.getEntryPoint();

			// Initialize caller-specified registers
			if (args.has("registers")) {
				JsonObject regs = args.getAsJsonObject("registers");
				for (Map.Entry<String, JsonElement> reg : regs.entrySet()) {
					try {
						long val = Long.parseUnsignedLong(
							reg.getValue().getAsString().replace("0x", ""), 16);
						emu.writeRegister(reg.getKey(), val);
					}
					catch (Exception e) {
						// skip invalid register values
					}
				}
			}

			// Initialize caller-specified memory
			if (args.has("memory")) {
				for (JsonElement memElem : args.getAsJsonArray("memory")) {
					JsonObject mem = memElem.getAsJsonObject();
					Address memAddr = program.getAddressFactory()
							.getAddress(mem.get("address").getAsString());
					if (memAddr != null && mem.has("bytes")) {
						String[] hexBytes = mem.get("bytes").getAsString().trim().split("\\s+");
						byte[] bytes = new byte[hexBytes.length];
						for (int i = 0; i < hexBytes.length; i++) {
							bytes[i] = (byte) Integer.parseInt(hexBytes[i], 16);
						}
						emu.writeMemory(memAddr, bytes);
					}
				}
			}

			// Step through execution
			emu.writeRegister(emu.getPCRegister(), entryPoint.getOffset());
			int stepped = 0;
			String stopReason = "max_instructions";

			while (stepped < maxInstructions) {
				Address pc = emu.getExecutionAddress();
				if (pc == null) {
					stopReason = "invalid_pc";
					break;
				}

				Instruction instr = program.getListing().getInstructionAt(pc);
				if (instr != null && instr.getFlowType().isTerminal()) {
					stopReason = "return";
					// Execute the return instruction so registers are updated
					emu.run(TaskMonitor.DUMMY);
					stepped++;
					break;
				}

				try {
					emu.run(TaskMonitor.DUMMY);
				}
				catch (Exception e) {
					stopReason = "error: " + e.getMessage();
					break;
				}
				stepped++;
			}

			// Collect results
			JsonObject response = new JsonObject();
			response.addProperty("function", fn.getName());
			response.addProperty("entry_point", entryPoint.toString());
			response.addProperty("instructions_executed", stepped);
			response.addProperty("stop_reason", stopReason);

			// Read requested registers
			if (args.has("read_registers")) {
				JsonObject regResults = new JsonObject();
				for (JsonElement regElem : args.getAsJsonArray("read_registers")) {
					String regName = regElem.getAsString();
					try {
						BigInteger val = emu.readRegister(regName);
						regResults.addProperty(regName, "0x" + val.toString(16));
					}
					catch (Exception e) {
						regResults.addProperty(regName, "error: " + e.getMessage());
					}
				}
				response.add("registers", regResults);
			}

			// Read requested memory regions
			if (args.has("read_memory")) {
				JsonArray memResults = new JsonArray();
				for (JsonElement memElem : args.getAsJsonArray("read_memory")) {
					JsonObject req = memElem.getAsJsonObject();
					Address memAddr = program.getAddressFactory()
							.getAddress(req.get("address").getAsString());
					int length = req.has("length") ? req.get("length").getAsInt() : 16;
					try {
						byte[] bytes = emu.readMemory(memAddr, length);
						StringBuilder hex = new StringBuilder();
						StringBuilder ascii = new StringBuilder();
						for (byte b : bytes) {
							hex.append(String.format("%02x ", b));
							ascii.append(b >= 32 && b < 127 ? (char) b : '.');
						}
						JsonObject memResult = new JsonObject();
						memResult.addProperty("address", memAddr.toString());
						memResult.addProperty("hex", hex.toString().trim());
						memResult.addProperty("ascii", ascii.toString());
						memResults.add(memResult);
					}
					catch (Exception e) {
						JsonObject memResult = new JsonObject();
						memResult.addProperty("address", memAddr.toString());
						memResult.addProperty("error", e.getMessage());
						memResults.add(memResult);
					}
				}
				response.add("memory", memResults);
			}

			return new Gson().toJson(response);
		}
		finally {
			emu.dispose();
		}
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
