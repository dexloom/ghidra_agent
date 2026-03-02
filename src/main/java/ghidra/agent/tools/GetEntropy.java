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

import ghidra.app.plugin.core.entropy.EntropyCalculate;
import ghidra.program.model.listing.Program;
import ghidra.program.model.mem.*;

/**
 * Calculates Shannon entropy across each memory block (segment) in the binary.
 * High entropy (>7.0) suggests encryption, compression, or packed code.
 * Low entropy (<3.0) suggests plaintext data or zero-filled regions.
 */
public class GetEntropy implements AgentTool {

	private static final int CHUNK_SIZE = 512;

	@Override
	public String getName() {
		return "get_entropy";
	}

	@Override
	public String getDescription() {
		return "Calculate Shannon entropy for each memory segment (section) in the binary. " +
			"High entropy (> 7.0 out of 8.0) indicates encrypted, compressed, or packed data. " +
			"Low entropy (< 3.0) indicates plaintext, sparse data, or zero-fill. " +
			"Use this during initial triage to find obfuscated payloads or crypto routines.";
	}

	@Override
	public String getParameterSchema() {
		return """
				{
				  "type": "object",
				  "properties": {
				    "threshold": {
				      "type": "number",
				      "description": "Only report blocks with average entropy above this value (0.0-8.0). Default: 0.0 (all blocks)."
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

		double threshold = args.has("threshold") ? args.get("threshold").getAsDouble() : 0.0;
		Program program = ctx.getProgram();
		Memory memory = program.getMemory();

		JsonArray blocks = new JsonArray();
		double overallSum = 0;
		int overallChunks = 0;

		for (MemoryBlock block : memory.getBlocks()) {
			if (!block.isInitialized() || block.getSize() == 0) {
				continue;
			}

			EntropyCalculate calc = new EntropyCalculate(block, CHUNK_SIZE);
			int numChunks = (int) Math.ceil((double) block.getSize() / CHUNK_SIZE);

			double sum = 0;
			double max = 0;
			double min = 8.0;

			for (int i = 0; i < numChunks; i++) {
				// getValue returns 0-255 mapped from 0.0-8.0 entropy
				double entropy = calc.getValue(i) / 32.0; // scale 0-255 → 0.0-8.0
				sum += entropy;
				if (entropy > max) {
					max = entropy;
				}
				if (entropy < min) {
					min = entropy;
				}
			}

			double avg = numChunks > 0 ? sum / numChunks : 0;
			overallSum += sum;
			overallChunks += numChunks;

			if (avg < threshold) {
				continue;
			}

			JsonObject entry = new JsonObject();
			entry.addProperty("name", block.getName());
			entry.addProperty("start", block.getStart().toString());
			entry.addProperty("end", block.getEnd().toString());
			entry.addProperty("size_bytes", block.getSize());
			entry.addProperty("permissions",
				(block.isRead() ? "r" : "-") + (block.isWrite() ? "w" : "-") +
					(block.isExecute() ? "x" : "-"));
			entry.addProperty("avg_entropy", Math.round(avg * 100.0) / 100.0);
			entry.addProperty("max_entropy", Math.round(max * 100.0) / 100.0);
			entry.addProperty("min_entropy", Math.round(min * 100.0) / 100.0);
			entry.addProperty("assessment", assess(avg));
			blocks.add(entry);
		}

		double overallAvg = overallChunks > 0 ? overallSum / overallChunks : 0;

		JsonObject response = new JsonObject();
		response.addProperty("overall_avg_entropy", Math.round(overallAvg * 100.0) / 100.0);
		response.addProperty("block_count", blocks.size());
		response.add("blocks", blocks);
		return new Gson().toJson(response);
	}

	private String assess(double entropy) {
		if (entropy >= 7.5) {
			return "VERY HIGH — likely encrypted or compressed";
		}
		if (entropy >= 6.5) {
			return "HIGH — possibly packed, obfuscated, or crypto";
		}
		if (entropy >= 4.5) {
			return "MEDIUM — typical code or mixed data";
		}
		if (entropy >= 2.5) {
			return "LOW — plaintext, structured data, or sparse";
		}
		return "VERY LOW — zero-filled or near-constant";
	}
}
