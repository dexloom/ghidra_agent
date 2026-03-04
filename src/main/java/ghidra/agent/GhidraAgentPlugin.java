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

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;

import ghidra.app.events.ProgramActivatedPluginEvent;
import ghidra.app.plugin.PluginCategoryNames;
import ghidra.app.services.ProgramManager;
import ghidra.framework.options.OptionType;
import ghidra.framework.options.ToolOptions;
import ghidra.framework.plugintool.*;
import ghidra.framework.plugintool.util.PluginStatus;
import ghidra.program.model.listing.Program;

//@formatter:off
@PluginInfo(
	status = PluginStatus.RELEASED,
	packageName = "GhidraAgent",
	category = PluginCategoryNames.COMMON,
	shortDescription = "AI Agent",
	description = "Natural language AI agent for Ghidra automation: function renaming, " +
		"vulnerability detection, data type recovery, and custom scripting. " +
		"Supports any OpenAI-compatible LLM (Claude, GPT-4o, Ollama, etc.).",
	servicesRequired = { ProgramManager.class },
	eventsConsumed = { ProgramActivatedPluginEvent.class }
)
//@formatter:on
public class GhidraAgentPlugin extends Plugin {

	static final String OPTIONS_CATEGORY = "AI Agent";
	static final String OPTION_BASE_URL = "LLM Base URL";
	static final String OPTION_MODEL = "LLM Model";
	static final String OPTION_API_KEY = "LLM API Key";
	static final String OPTION_SYSTEM_PROMPT = "System Prompt";

	static final String DEFAULT_BASE_URL = "https://api.openai.com/v1";
	static final String DEFAULT_MODEL = "gpt-4o";

	private GhidraAgentProvider provider;

	public GhidraAgentPlugin(PluginTool tool) {
		super(tool);

		registerOptions();
		provider = new GhidraAgentProvider(tool, getName(), this);
	}

	private void registerOptions() {
		ToolOptions options = tool.getOptions(OPTIONS_CATEGORY);
		options.registerOption(OPTION_BASE_URL, DEFAULT_BASE_URL, null,
			"Base URL of the OpenAI-compatible LLM API endpoint. " +
				"Examples: https://api.openai.com/v1, https://api.anthropic.com/v1, " +
				"http://localhost:11434/v1 (Ollama)");
		options.registerOption(OPTION_MODEL, DEFAULT_MODEL, null,
			"Model name to use, e.g. gpt-4o, claude-sonnet-4-6, llama3");
		options.registerOption(OPTION_API_KEY, "", null,
			"API key for the LLM provider. Leave blank if using a local server that " +
				"does not require authentication.");
		options.registerOption(OPTION_SYSTEM_PROMPT, OptionType.FILE_TYPE, null, null,
			"Path to a text file that replaces the default system prompt entirely. " +
				"If unset or the file is missing, the built-in system prompt is used.");
	}

	/** Called by GhidraAgentProvider when it needs the current LLM configuration */
	String getLLMBaseUrl() {
		return tool.getOptions(OPTIONS_CATEGORY).getString(OPTION_BASE_URL, DEFAULT_BASE_URL);
	}

	String getLLMModel() {
		return tool.getOptions(OPTIONS_CATEGORY).getString(OPTION_MODEL, DEFAULT_MODEL);
	}

	String getLLMApiKey() {
		return tool.getOptions(OPTIONS_CATEGORY).getString(OPTION_API_KEY, "");
	}

	String getSystemPrompt() {
		File file = tool.getOptions(OPTIONS_CATEGORY).getFile(OPTION_SYSTEM_PROMPT, null);
		if (file == null || !file.exists()) {
			return "";
		}
		try {
			return Files.readString(file.toPath());
		}
		catch (IOException e) {
			return "";
		}
	}

	@Override
	public void processEvent(PluginEvent event) {
		if (event instanceof ProgramActivatedPluginEvent pae) {
			Program program = pae.getActiveProgram();
			provider.programChanged(program);
		}
	}

	@Override
	public void dispose() {
		provider.setVisible(false);
		provider.removeFromTool();
	}
}
