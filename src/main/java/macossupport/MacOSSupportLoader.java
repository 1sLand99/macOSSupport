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
package macossupport;

import java.io.IOException;
import java.util.*;

import ghidra.app.util.Option;
import ghidra.app.util.bin.ByteProvider;
import ghidra.app.util.importer.MessageLog;
import ghidra.app.util.opinion.Loaded;
import ghidra.framework.model.DomainFolder;
import ghidra.framework.model.Project;
import ghidra.framework.model.ProjectData;
import ghidra.program.model.listing.Program;
import ghidra.util.exception.CancelledException;
import ghidra.util.task.TaskMonitor;
import ghidra.app.util.opinion.MachoLoader;

public class MacOSSupportLoader extends MachoLoader {
	
	public String getPreferredFileName(ByteProvider provider) {
		String original = super.getPreferredFileName(provider);
		String prettyString = provider.getFSRL().toPrettyFullpathString();
		String[] parentAndChild = prettyString.split("\\|");
		String parent = parentAndChild[0];
		if (parent == null) return original;
		String[] pathComponents = parent.split("\\/");
		String lastPathComponent = pathComponents[pathComponents.length - 1];
		return lastPathComponent+ "-" + original;
	}
	
	@Override
	protected void postLoadProgramFixups(List<Loaded<Program>> loadedPrograms, Project project,
			List<Option> options, MessageLog messageLog, TaskMonitor monitor)
			throws CancelledException, IOException {
		super.postLoadProgramFixups(loadedPrograms, project, options, messageLog, monitor);
		ProjectData projectData = project.getProjectData();
		for (Loaded<Program> loaded: loadedPrograms) {
			Program program = loaded.getDomainObject();
			int renameTransaction = program.startTransaction("rename");
			program.setName(loaded.getName());
			program.endTransaction(renameTransaction, true);
			
						
			String originalFolderPath = loaded.getProjectFolderPath();
			String[] originalFolderPathComponents = originalFolderPath.split("\\/");
			int newFolderPathComponentsLength = originalFolderPathComponents.length - 1;
			String[] newFolderPathComponents = new String[newFolderPathComponentsLength];
			System.arraycopy(originalFolderPathComponents, 0, newFolderPathComponents, 0, newFolderPathComponentsLength);
			String newFolderPath = String.join("/", newFolderPathComponents);
			System.out.println(projectData.getFileCount());
			loaded.setProjectFolderPath(newFolderPath);
			DomainFolder originalFolder = projectData.getFolder(originalFolderPath);
			originalFolder.delete();
		}
		
	}
}
