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

/**
 * A tool that the AI agent can invoke to interact with the current Ghidra program.
 * Each tool exposes a JSON Schema for its parameters so the LLM can construct valid calls.
 */
public interface AgentTool {

	/** Tool name used by the LLM to identify and call this tool */
	String getName();

	/** Human-readable description telling the LLM when and how to use this tool */
	String getDescription();

	/**
	 * JSON Schema (as a string) describing the tool's parameters.
	 * Must be a valid JSON object with "type": "object" and a "properties" field.
	 */
	String getParameterSchema();

	/**
	 * Execute the tool using the provided context.
	 *
	 * @param ctx        runtime context (program, tool, project, monitor)
	 * @param argsJson   JSON string containing the arguments matching the schema
	 * @return           a plain-text or JSON result string to be sent back to the LLM
	 * @throws Exception if execution fails
	 */
	String execute(AgentContext ctx, String argsJson) throws Exception;
}
