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

/**
 * Represents a response from the LLM. May contain text content, tool calls, or both.
 */
public class LLMResponse {

	/** Text content of the assistant message (may be null if only tool calls) */
	public final String content;
	/** Tool calls requested by the model (empty list if none) */
	public final List<LLMToolCall> toolCalls;
	/**
	 * The full assistant message to be appended to conversation history.
	 * This preserves the raw tool_calls array needed for subsequent requests.
	 */
	public final String rawAssistantMessageJson;

	public LLMResponse(String content, List<LLMToolCall> toolCalls,
			String rawAssistantMessageJson) {
		this.content = content;
		this.toolCalls = toolCalls;
		this.rawAssistantMessageJson = rawAssistantMessageJson;
	}

	public boolean hasToolCalls() {
		return toolCalls != null && !toolCalls.isEmpty();
	}
}
