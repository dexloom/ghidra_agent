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

import java.awt.*;
import java.awt.event.*;
import java.time.LocalTime;
import java.time.format.DateTimeFormatter;

import javax.swing.*;
import javax.swing.text.*;

import docking.*;
import docking.action.*;
import ghidra.agent.llm.OpenAICompatibleClient;
import ghidra.agent.tools.*;
import ghidra.framework.plugintool.*;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;
import resources.Icons;

/**
 * Dockable chat panel for the Ghidra AI Agent.
 * Provides a conversation interface where users type natural-language requests
 * and the agent executes them against the open binary.
 */
public class GhidraAgentProvider extends ComponentProviderAdapter {

	private static final DateTimeFormatter TIME_FMT = DateTimeFormatter.ofPattern("HH:mm:ss");
	private static final Color COLOR_USER = new Color(0x1a73e8);
	private static final Color COLOR_ASSISTANT = new Color(0x188038);
	private static final Color COLOR_TOOL = new Color(0x7b5ea7);
	private static final Color COLOR_ERROR = new Color(0xc5221f);
	private static final Color COLOR_STATUS = new Color(0x80868b);

	private final GhidraAgentPlugin plugin;
	private AgentRunner runner;
	private Program currentProgram;

	// UI components
	private JPanel mainPanel;
	private JTextPane chatPane;
	private StyledDocument chatDoc;
	private JTextField inputField;
	private JButton sendButton;
	private JLabel statusLabel;

	public GhidraAgentProvider(PluginTool tool, String owner, GhidraAgentPlugin plugin) {
		super(tool, "AI Agent", owner);
		this.plugin = plugin;

		buildPanel();
		createActions();

		setTitle("AI Agent");
		setDefaultWindowPosition(WindowPosition.BOTTOM);
		setVisible(true);

		runner = createRunner();
	}

	private AgentRunner createRunner() {
		OpenAICompatibleClient client = new OpenAICompatibleClient(
			plugin.getLLMBaseUrl(), plugin.getLLMModel(), plugin.getLLMApiKey());

		AgentRunner r = new AgentRunner(client);
		r.setStatusCallback(msg -> appendMessage("tool", msg));
		r.setResponseCallback(msg -> {
			appendMessage("assistant", msg);
			setInputEnabled(true);
			statusLabel.setText("Ready");
		});
		r.setErrorCallback(msg -> {
			appendMessage("error", msg);
			setInputEnabled(true);
			statusLabel.setText("Error");
		});
		return r;
	}

	// -------------------------------------------------------------------------
	// UI construction
	// -------------------------------------------------------------------------

	private void buildPanel() {
		mainPanel = new JPanel(new BorderLayout(0, 4));
		mainPanel.setBorder(BorderFactory.createEmptyBorder(4, 4, 4, 4));

		// Chat history
		chatPane = new JTextPane();
		chatPane.setEditable(false);
		chatPane.setContentType("text/plain");
		chatDoc = chatPane.getStyledDocument();
		addStyles();

		JScrollPane scrollPane = new JScrollPane(chatPane);
		scrollPane.setVerticalScrollBarPolicy(JScrollPane.VERTICAL_SCROLLBAR_ALWAYS);
		mainPanel.add(scrollPane, BorderLayout.CENTER);

		// Input area
		JPanel inputPanel = new JPanel(new BorderLayout(4, 0));

		inputField = new JTextField();
		inputField.setFont(new Font(Font.MONOSPACED, Font.PLAIN, 13));
		inputField.addActionListener(e -> onSend());
		inputField.addKeyListener(new KeyAdapter() {
			@Override
			public void keyPressed(KeyEvent e) {
				if (e.getKeyCode() == KeyEvent.VK_ENTER && !e.isShiftDown()) {
					onSend();
				}
			}
		});
		inputPanel.add(inputField, BorderLayout.CENTER);

		sendButton = new JButton("Send");
		sendButton.addActionListener(e -> onSend());
		inputPanel.add(sendButton, BorderLayout.EAST);

		// Status bar
		JPanel bottomPanel = new JPanel(new BorderLayout());
		statusLabel = new JLabel("Ready — open a binary and start chatting");
		statusLabel.setFont(statusLabel.getFont().deriveFont(Font.ITALIC, 11f));
		statusLabel.setBorder(BorderFactory.createEmptyBorder(2, 2, 0, 0));
		bottomPanel.add(inputPanel, BorderLayout.CENTER);
		bottomPanel.add(statusLabel, BorderLayout.SOUTH);

		mainPanel.add(bottomPanel, BorderLayout.SOUTH);

		appendMessage("status",
			"AI Agent ready. Configure your LLM via Edit > Tool Options > AI Agent.\n" +
				"Open a binary and describe what you want to do.");
	}

	private void addStyles() {
		Style base = StyleContext.getDefaultStyleContext().getStyle(StyleContext.DEFAULT_STYLE);
		Style def = chatDoc.addStyle("default", base);
		StyleConstants.setFontFamily(def, Font.MONOSPACED);
		StyleConstants.setFontSize(def, 13);

		addColorStyle("user", COLOR_USER, true);
		addColorStyle("assistant", COLOR_ASSISTANT, false);
		addColorStyle("tool", COLOR_TOOL, false);
		addColorStyle("error", COLOR_ERROR, false);
		addColorStyle("status", COLOR_STATUS, true);
		addColorStyle("timestamp", COLOR_STATUS, false);
	}

	private void addColorStyle(String name, Color color, boolean bold) {
		Style style = chatDoc.addStyle(name, chatDoc.getStyle("default"));
		StyleConstants.setForeground(style, color);
		StyleConstants.setBold(style, bold);
	}

	private void appendMessage(String role, String text) {
		SwingUtilities.invokeLater(() -> {
			try {
				String timestamp = "[" + LocalTime.now().format(TIME_FMT) + "] ";
				String prefix = switch (role) {
					case "user" -> "You: ";
					case "assistant" -> "Agent: ";
					case "tool" -> "  -> ";
					case "error" -> "Error: ";
					default -> "";
				};

				chatDoc.insertString(chatDoc.getLength(), timestamp, chatDoc.getStyle("timestamp"));
				chatDoc.insertString(chatDoc.getLength(), prefix, chatDoc.getStyle(role));
				chatDoc.insertString(chatDoc.getLength(), text + "\n\n",
					chatDoc.getStyle("default"));

				// Auto-scroll to bottom
				chatPane.setCaretPosition(chatDoc.getLength());
			}
			catch (BadLocationException e) {
				// ignore — can't fail gracefully in a UI callback
			}
		});
	}

	private void onSend() {
		String text = inputField.getText().trim();
		if (text.isEmpty()) {
			return;
		}
		if (currentProgram == null) {
			appendMessage("error",
				"No binary is open. Please open a binary in Ghidra first.");
			return;
		}

		String url = plugin.getLLMBaseUrl();
		String model = plugin.getLLMModel();
		appendMessage("status", "Sending to " + url + " (model: " + model + ")");

		inputField.setText("");
		appendMessage("user", text);
		setInputEnabled(false);
		statusLabel.setText("Thinking...");

		// Rebuild the runner if LLM settings may have changed
		runner = createRunner();
		runner.setContext(new AgentContext(
			currentProgram,
			plugin.getTool(),
			plugin.getTool().getProject(),
			TaskMonitor.DUMMY));

		runner.submit(text, AgentRunner.buildSystemPrompt(currentProgram));
	}

	private void setInputEnabled(boolean enabled) {
		inputField.setEnabled(enabled);
		sendButton.setEnabled(enabled);
	}

	// -------------------------------------------------------------------------
	// Actions
	// -------------------------------------------------------------------------

	private void createActions() {
		DockingAction clearAction = new DockingAction("Clear Conversation", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				try {
					chatDoc.remove(0, chatDoc.getLength());
				}
				catch (BadLocationException e) {
					// ignore
				}
				if (runner != null) {
					runner.clearHistory();
				}
				appendMessage("status", "Conversation cleared.");
			}
		};
		clearAction.setToolBarData(new ToolBarData(Icons.DELETE_ICON));
		clearAction.setDescription("Clear conversation history");
		addLocalAction(clearAction);

		DockingAction settingsAction = new DockingAction("LLM Settings", getOwner()) {
			@Override
			public void actionPerformed(ActionContext context) {
				JOptionPane.showMessageDialog(getComponent(),
					"Configure LLM settings via:\n  Edit > Tool Options > AI Agent",
					"AI Agent Settings", JOptionPane.INFORMATION_MESSAGE);
			}
		};
		settingsAction.setToolBarData(new ToolBarData(Icons.CONFIGURE_FILTER_ICON));
		settingsAction.setDescription("Configure LLM provider, model, and API key");
		addLocalAction(settingsAction);
	}

	// -------------------------------------------------------------------------
	// Program lifecycle
	// -------------------------------------------------------------------------

	public void programChanged(Program program) {
		this.currentProgram = program;
		if (runner != null) {
			runner.clearHistory();
		}
		if (program != null) {
			appendMessage("status", "Binary loaded: " + program.getName() +
				" (" + program.getLanguage().getLanguageID() + ")");
			statusLabel.setText("Ready — " + program.getName());
		}
		else {
			statusLabel.setText("No binary open");
		}
	}

	// -------------------------------------------------------------------------
	// ComponentProvider
	// -------------------------------------------------------------------------

	@Override
	public JComponent getComponent() {
		return mainPanel;
	}
}
