/*
 * Copyright 2002-2021 the original author or authors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package s101;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.UncheckedIOException;
import java.nio.file.Files;

import com.headway.assemblies.seaview.headless.S101Headless;
import org.gradle.api.DefaultTask;
import org.gradle.api.tasks.TaskAction;

import org.springframework.core.io.ClassPathResource;
import org.springframework.core.io.Resource;

public class S101Build extends DefaultTask {
	@TaskAction
	public void build() {
		doApply();
	}

	private void doApply() {
		File s101 = getStructure101Path();
		if (!s101.exists()) {
			throw new IllegalStateException("Structure101 needs to know the structure of your snapshots in order to run. " +
					"Please indicate the directory containing your project's *.hsp file using the s101Directory property");
		}
		File config = new File(s101, "config.xml");
		if (!config.exists()) {
			copyToProject("s101/config.xml", new File(s101, "config.xml"));
			File repository = new File(s101, "repository");
			File snapshots = new File(repository, "snapshots");
			if (!snapshots.exists() && !snapshots.mkdirs()) {
				throw new IllegalStateException("Unable to create snapshots directory");
			}
			copyToProject("s101/repository.xml", new File(repository, "repository.xml"));
			System.setProperty("s101.label", "baseline");
		} else {
			System.setProperty("s101.label", "recent");
		}
		if (getProject().hasProperty("s101.label")) {
			String label = (String) getProject().property("s101.label");
			System.setProperty("s101.label", label);
		}
		String licenseDirectoryProperty = "-licensedirectory=" + getLicenseDirectory();
		S101Headless.headlessRunner(new String[]{config.getAbsolutePath(), licenseDirectoryProperty});
	}

	private void copyToProject(String templateLocation, File destination) {
		Resource template = new ClassPathResource(templateLocation);
		try (InputStream is = template.getInputStream()) { // change to read in as template
			Files.copy(is, destination.toPath());
		} catch (IOException ex) {
			throw new UncheckedIOException(ex);
		}
	}

	private File getStructure101Path() {
		if (getProject().hasProperty("s101Directory")) {
			String property = (String) getProject().property("s101Directory");
			return new File(property);
		}
		return new File(getProject().getProjectDir(), "s101");
	}

	private String getLicenseDirectory() {
		if (getProject().hasProperty("s101.licensedirectory")) {
			return (String) getProject().property("s101.licensedirectory");
		}
		return System.getProperty("user.home") + "/.Structure101/java";
	}
}
