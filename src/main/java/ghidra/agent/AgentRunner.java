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
package ghidra.agent;

import java.util.*;
import java.util.concurrent.ExecutionException;
import java.util.function.Consumer;

import javax.swing.SwingWorker;

import ghidra.agent.llm.*;
import ghidra.agent.tools.*;
import ghidra.program.model.listing.Program;
import ghidra.util.Msg;

/**
 * Orchestrates the agentic loop: user message → LLM → tool calls → LLM → ... → final response.
 * Runs in a background SwingWorker so the Ghidra UI remains responsive.
 *
 * The loop is bounded by MAX_ITERATIONS to prevent runaway tool chains.
 */
public class AgentRunner {

	private static final int MAX_ITERATIONS = 20;

	private final LLMClient llmClient;
	private final List<AgentTool> tools;
	private final List<LLMMessage> history = new ArrayList<>();

	/** Called on the EDT with partial status updates (tool calls, etc.) */
	private Consumer<String> statusCallback;
	/** Called on the EDT when the final assistant response is ready */
	private Consumer<String> responseCallback;
	/** Called on the EDT when an error occurs */
	private Consumer<String> errorCallback;

	private AgentContext context;

	public AgentRunner(LLMClient llmClient) {
		this.llmClient = llmClient;
		this.tools = List.of(
			// Core analysis
			new ListFunctions(),
			new GetDecompiledCode(),
			new GetCallersCallees(),
			new GetControlFlow(),
			new AnalyzePcode(),
			// Search
			new SearchBytes(),
			new SearchStrings(),
			// Modifications
			new RenameFunction(),
			new SetFunctionSignature(),
			new RecoverDataTypes(),
			new AssemblePatch(),
			// Annotation
			new SetBookmark(),
			new ColorAddresses(),
			// Intelligence
			new DetectVulnerabilities(),
			new DemangleSymbol(),
			new GetEntropy(),
			new EmulateFunction(),
			// Scripting
			new ExecuteScript());
	}

	public void setStatusCallback(Consumer<String> cb) {
		this.statusCallback = cb;
	}

	public void setResponseCallback(Consumer<String> cb) {
		this.responseCallback = cb;
	}

	public void setErrorCallback(Consumer<String> cb) {
		this.errorCallback = cb;
	}

	public void setContext(AgentContext context) {
		this.context = context;
	}

	public void clearHistory() {
		history.clear();
	}

	/**
	 * Submit a user message and run the agentic loop asynchronously.
	 * Callbacks are invoked on the Event Dispatch Thread.
	 *
	 * @param userMessage the message typed by the user
	 * @param systemPrompt the system prompt (may be updated each call to reflect current program)
	 */
	public void submit(String userMessage, String systemPrompt) {

		// Build or refresh the system message (always first in history)
		if (history.isEmpty()) {
			history.add(LLMMessage.system(systemPrompt));
		}
		else {
			// Update the system message to reflect the current program state
			history.set(0, LLMMessage.system(systemPrompt));
		}

		history.add(LLMMessage.user(userMessage));

		new SwingWorker<String, String>() {
			@Override
			protected String doInBackground() throws Exception {
				return runLoop();
			}

			@Override
			protected void process(List<String> chunks) {
				if (statusCallback != null) {
					chunks.forEach(statusCallback);
				}
			}

			@Override
			protected void done() {
				try {
					String result = get();
					if (responseCallback != null) {
						responseCallback.accept(result);
					}
				}
				catch (InterruptedException | ExecutionException e) {
					Throwable cause = e instanceof ExecutionException ? e.getCause() : e;
					if (errorCallback != null) {
						errorCallback.accept("Agent error: " + cause.getMessage());
					}
					Msg.error(AgentRunner.class, "Agent loop failed", cause);
				}
			}

			private String runLoop() throws Exception {
				int iterations = 0;

				while (iterations++ < MAX_ITERATIONS) {
					LLMResponse response = llmClient.chat(history, tools);

					if (!response.hasToolCalls()) {
						// Final text response — add to history and return
						if (response.content != null) {
							history.add(LLMMessage.assistant(response.content));
						}
						return response.content != null ? response.content
								: "(Agent finished without a text response)";
					}

					// Append the raw assistant message (includes tool_calls) to history
					history.add(new LLMMessage("assistant_raw", response.rawAssistantMessageJson));

					// Execute each requested tool call
					for (LLMToolCall toolCall : response.toolCalls) {
						String toolStatus =
							"[Tool: " + toolCall.name + "] " + abbreviate(toolCall.argumentsJson);
						publish(toolStatus);

						String result = executeToolCall(toolCall);
						history.add(LLMMessage.toolResult(toolCall.id, result));
					}
				}

				return "Agent reached maximum iterations (" + MAX_ITERATIONS +
					"). Stopping to prevent runaway execution.";
			}
		}.execute();
	}

	private String executeToolCall(LLMToolCall toolCall) {
		AgentTool tool = tools.stream()
				.filter(t -> t.getName().equals(toolCall.name))
				.findFirst()
				.orElse(null);

		if (tool == null) {
			return "ERROR: Unknown tool: " + toolCall.name;
		}

		if (context == null || context.getProgram() == null) {
			return "ERROR: No program is currently open in Ghidra. Please open a binary first.";
		}

		try {
			return tool.execute(context, toolCall.argumentsJson);
		}
		catch (Exception e) {
			Msg.error(AgentRunner.class, "Tool execution failed: " + toolCall.name, e);
			return "ERROR: Tool execution failed: " + e.getMessage();
		}
	}

	private static String abbreviate(String json) {
		if (json == null || json.length() <= 120) {
			return json;
		}
		return json.substring(0, 117) + "...";
	}

	/**
	 * Build a system prompt that includes context about the currently open program.
	 */
	public static String buildSystemPrompt(Program program) {
		StringBuilder sb = new StringBuilder();
		sb.append("You are an expert reverse engineer embedded inside Ghidra, a binary analysis tool.\n\n");
		sb.append("Your job is to help the user analyze and understand binary code. ");
		sb.append("You have access to a set of tools that let you interact with the currently open binary.\n\n");

		if (program != null) {
			sb.append("## Currently open binary\n");
			sb.append("- Name: ").append(program.getName()).append("\n");
			sb.append("- Language: ").append(program.getLanguage().getLanguageID()).append("\n");
			sb.append("- Compiler spec: ").append(program.getCompilerSpec().getCompilerSpecID()).append("\n");
			sb.append("- Address size: ").append(program.getAddressFactory().getDefaultAddressSpace().getSize()).append(" bits\n");
			sb.append("\n");
		}
		else {
			sb.append("No binary is currently open. Ask the user to open a binary in Ghidra first.\n\n");
		}

		sb.append("## Guidelines\n");
		sb.append("- Always call `get_decompiled_code` before renaming or commenting a function.\n");
		sb.append("- Explain your reasoning before taking any action that modifies the binary.\n");
		sb.append("- When detecting vulnerabilities, group findings by severity and explain why each is risky.\n");
		sb.append("- For data type recovery, describe the struct layout before applying it.\n");
		sb.append("- All modifications (renames, types, comments) are undoable via Ctrl+Z.\n");

		return sb.toString();
	}
}
