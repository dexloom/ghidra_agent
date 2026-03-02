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

import ghidra.framework.model.Project;
import ghidra.framework.plugintool.PluginTool;
import ghidra.program.model.listing.Program;
import ghidra.util.task.TaskMonitor;

/**
 * Bundles all runtime context that agent tools may need.
 * Passed to each tool's execute() call by the AgentRunner.
 */
public class AgentContext {

	private final Program program;
	private final PluginTool tool;
	private final Project project;
	private final TaskMonitor monitor;

	public AgentContext(Program program, PluginTool tool, Project project, TaskMonitor monitor) {
		this.program = program;
		this.tool = tool;
		this.project = project;
		this.monitor = monitor;
	}

	public Program getProgram() {
		return program;
	}

	public PluginTool getTool() {
		return tool;
	}

	public Project getProject() {
		return project;
	}

	public TaskMonitor getMonitor() {
		return monitor;
	}
}
