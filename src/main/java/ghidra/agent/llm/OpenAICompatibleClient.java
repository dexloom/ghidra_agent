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

import java.io.*;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.List;

import com.google.gson.*;

import ghidra.agent.tools.AgentTool;

/**
 * LLM client that speaks the OpenAI Chat Completions API (v1/chat/completions).
 * Compatible with: OpenAI, Anthropic (via openai-compat endpoint), Ollama, LM Studio, and
 * any other OpenAI-compatible server.
 *
 * Uses HttpURLConnection for broad compatibility across all Java environments.
 */
public class OpenAICompatibleClient implements LLMClient {

	private static final int CONNECT_TIMEOUT_MS = 10_000;
	private static final int READ_TIMEOUT_MS = 300_000; // 5 min for large models

	private final String baseUrl;
	private final String model;
	private final String apiKey;
	private final Gson gson;

	public OpenAICompatibleClient(String baseUrl, String model, String apiKey) {
		this.baseUrl = baseUrl.endsWith("/") ? baseUrl.substring(0, baseUrl.length() - 1) : baseUrl;
		this.model = model;
		this.apiKey = apiKey;
		this.gson = new Gson();
	}

	@Override
	public LLMResponse chat(List<LLMMessage> history, List<AgentTool> tools) throws Exception {

		JsonObject body = new JsonObject();
		body.addProperty("model", model);

		// Build messages array
		JsonArray messages = new JsonArray();
		for (LLMMessage msg : history) {
			if (msg.role.equals("assistant_raw")) {
				// Pre-serialized assistant message with tool_calls — add verbatim
				messages.add(JsonParser.parseString(msg.content));
			}
			else {
				JsonObject m = new JsonObject();
				m.addProperty("role", msg.role);
				if (msg.toolCallId != null) {
					m.addProperty("tool_call_id", msg.toolCallId);
				}
				m.addProperty("content", msg.content != null ? msg.content : "");
				messages.add(m);
			}
		}
		body.add("messages", messages);

		// Build tools array
		if (tools != null && !tools.isEmpty()) {
			JsonArray toolsArray = new JsonArray();
			for (AgentTool tool : tools) {
				JsonObject toolDef = new JsonObject();
				toolDef.addProperty("type", "function");
				JsonObject function = new JsonObject();
				function.addProperty("name", tool.getName());
				function.addProperty("description", tool.getDescription());
				function.add("parameters", JsonParser.parseString(tool.getParameterSchema()));
				toolDef.add("function", function);
				toolsArray.add(toolDef);
			}
			body.add("tools", toolsArray);
		}

		String requestBody = gson.toJson(body);

		URL url = new URL(baseUrl + "/chat/completions");
		HttpURLConnection conn = (HttpURLConnection) url.openConnection();
		conn.setRequestMethod("POST");
		conn.setRequestProperty("Content-Type", "application/json");
		conn.setRequestProperty("anthropic-version", "2023-06-01");
		conn.setConnectTimeout(CONNECT_TIMEOUT_MS);
		conn.setReadTimeout(READ_TIMEOUT_MS);
		conn.setDoOutput(true);

		if (apiKey != null && !apiKey.isBlank()) {
			conn.setRequestProperty("Authorization", "Bearer " + apiKey);
		}

		try (OutputStream os = conn.getOutputStream()) {
			os.write(requestBody.getBytes(StandardCharsets.UTF_8));
		}

		int statusCode = conn.getResponseCode();
		InputStream is = statusCode >= 400 ? conn.getErrorStream() : conn.getInputStream();
		String responseBody;
		try (BufferedReader reader = new BufferedReader(new InputStreamReader(is, StandardCharsets.UTF_8))) {
			StringBuilder sb = new StringBuilder();
			String line;
			while ((line = reader.readLine()) != null) {
				sb.append(line).append('\n');
			}
			responseBody = sb.toString();
		}

		if (statusCode != 200) {
			throw new Exception("LLM API error " + statusCode + ": " + responseBody);
		}

		return parseResponse(responseBody);
	}

	private LLMResponse parseResponse(String responseBody) throws Exception {
		JsonObject root = JsonParser.parseString(responseBody).getAsJsonObject();

		JsonArray choices = root.getAsJsonArray("choices");
		if (choices == null || choices.size() == 0) {
			throw new Exception("No choices in LLM response: " + responseBody);
		}

		JsonObject choice = choices.get(0).getAsJsonObject();
		JsonObject message = choice.getAsJsonObject("message");

		// Extract text content; fall back to reasoning_content for reasoning models
		String content = null;
		if (message.has("content") && !message.get("content").isJsonNull()) {
			content = message.get("content").getAsString();
			if (content.isBlank() && message.has("reasoning_content") &&
				!message.get("reasoning_content").isJsonNull()) {
				content = message.get("reasoning_content").getAsString();
			}
		}
		else if (message.has("reasoning_content") &&
			!message.get("reasoning_content").isJsonNull()) {
			content = message.get("reasoning_content").getAsString();
		}

		// Extract tool calls
		List<LLMToolCall> toolCalls = new ArrayList<>();
		if (message.has("tool_calls") && !message.get("tool_calls").isJsonNull() &&
			message.getAsJsonArray("tool_calls").size() > 0) {
			JsonArray rawToolCalls = message.getAsJsonArray("tool_calls");
			for (JsonElement tcElem : rawToolCalls) {
				JsonObject tc = tcElem.getAsJsonObject();
				String id = tc.get("id").getAsString();
				JsonObject function = tc.getAsJsonObject("function");
				String name = function.get("name").getAsString();
				String args = function.get("arguments").getAsString();
				toolCalls.add(new LLMToolCall(id, name, args));
			}
		}

		// Store the raw assistant message JSON so the next request can replay it
		// exactly (the tool_calls array must be present for subsequent messages to be valid)
		String rawAssistantJson = gson.toJson(message);

		return new LLMResponse(content, toolCalls, rawAssistantJson);
	}
}
