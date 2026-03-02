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

/**
 * Represents a single message in the LLM conversation history.
 * Roles: "system", "user", "assistant", "tool"
 */
public class LLMMessage {

	public final String role;
	public final String content;
	/** For role="tool": the tool_call_id this result belongs to */
	public final String toolCallId;

	public LLMMessage(String role, String content) {
		this(role, content, null);
	}

	public LLMMessage(String role, String content, String toolCallId) {
		this.role = role;
		this.content = content;
		this.toolCallId = toolCallId;
	}

	public static LLMMessage system(String content) {
		return new LLMMessage("system", content);
	}

	public static LLMMessage user(String content) {
		return new LLMMessage("user", content);
	}

	public static LLMMessage assistant(String content) {
		return new LLMMessage("assistant", content);
	}

	public static LLMMessage toolResult(String toolCallId, String content) {
		return new LLMMessage("tool", content, toolCallId);
	}
}
