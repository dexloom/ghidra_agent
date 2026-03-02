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

import java.io.*;
import java.nio.file.*;

import com.google.gson.*;

import generic.jar.ResourceFile;
import ghidra.app.script.*;
import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Compiles and executes a GhidraScript (Java) provided as source code.
 * The script source is written to a temp file, compiled via Ghidra's OSGi
 * bundle system, and executed against the current program.
 * Output from the script's println() calls is captured and returned.
 */
public class ExecuteScript implements AgentTool {

	@Override
	public String getName() {
		return "execute_script";
	}

	@Override
	public String getDescription() {
		return "Write and execute a GhidraScript (Java) to perform custom analysis or automation. " +
			"The script must extend GhidraScript and implement run(). " +
			"Use currentProgram, currentAddress, and all standard GhidraScript methods. " +
			"Output from println() is captured and returned. The script runs in a transaction, " +
			"so modifications are undoable.";
	}

	@Override
	public String getParameterSchema() {
		return """
				{
				  "type": "object",
				  "properties": {
				    "class_name": {
				      "type": "string",
				      "description": "Simple class name for the script (no package, no .java extension), e.g. \\"MyAnalysis\\"."
				    },
				    "source_code": {
				      "type": "string",
				      "description": "Full Java source code of the script. Must extend GhidraScript and implement run()."
				    }
				  },
				  "required": ["class_name", "source_code"]
				}
				""";
	}

	@Override
	public String execute(AgentContext ctx, String argsJson) throws Exception {
		JsonObject args = JsonParser.parseString(argsJson).getAsJsonObject();

		if (!args.has("class_name") || !args.has("source_code")) {
			return "ERROR: 'class_name' and 'source_code' are required.";
		}

		String className = args.get("class_name").getAsString();
		String sourceCode = args.get("source_code").getAsString();

		// Write source to a temp file in the user scripts directory
		Path scriptsDir = GhidraScriptUtil.getUserScriptDirectory().getFile(false).toPath();
		Files.createDirectories(scriptsDir);
		Path scriptFile = scriptsDir.resolve(className + ".java");
		Files.writeString(scriptFile, sourceCode);

		StringWriter outputCapture = new StringWriter();
		PrintWriter writer = new PrintWriter(outputCapture);

		try {
			ResourceFile resourceFile = new ResourceFile(scriptFile.toFile().getAbsoluteFile());
			GhidraScriptProvider provider = GhidraScriptUtil.getProvider(resourceFile);
			if (provider == null) {
				return "ERROR: No script provider found for .java files. Ensure Ghidra's script system is initialized.";
			}

			GhidraScript script = provider.getScriptInstance(resourceFile, writer);

			Program program = ctx.getProgram();
			PluginTool tool = ctx.getTool();
			Project project = ctx.getProject();
			TaskMonitor monitor = ctx.getMonitor();

			GhidraState state = new GhidraState(tool, project, program, null, null, null);
			script.execute(state, monitor, writer);

			writer.flush();
			String output = outputCapture.toString();

			JsonObject response = new JsonObject();
			response.addProperty("success", true);
			response.addProperty("class_name", className);
			response.addProperty("output", output.isEmpty() ? "(no output)" : output);
			return new Gson().toJson(response);
		}
		catch (Exception e) {
			writer.flush();
			JsonObject response = new JsonObject();
			response.addProperty("success", false);
			response.addProperty("error", e.getMessage());
			response.addProperty("compile_output", outputCapture.toString());
			return new Gson().toJson(response);
		}
		finally {
			// Clean up the temp script file
			try {
				Files.deleteIfExists(scriptFile);
			}
			catch (IOException ignored) {
				// best-effort cleanup
			}
		}
	}
}
