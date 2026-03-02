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
package ghidra.agent.llm;

import java.util.List;

import ghidra.agent.tools.AgentTool;

/**
 * Abstraction over an LLM backend.
 * Implementations must handle tool-call serialization for their specific API.
 */
public interface LLMClient {

	/**
	 * Send the current conversation history and available tools to the LLM
	 * and return the model's next response.
	 *
	 * @param history  ordered list of messages (system, user, assistant, tool)
	 * @param tools    list of tools the model may invoke
	 * @return         the model's response (text and/or tool calls)
	 * @throws Exception on network or API errors
	 */
	LLMResponse chat(List<LLMMessage> history, List<AgentTool> tools) throws Exception;
}
