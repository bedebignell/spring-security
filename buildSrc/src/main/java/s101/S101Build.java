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
		File build = getProject().getBuildDir();
		doApply(build);
	}

	private void doApply(File build) {
		File s101 = new File(build, "s101");
		File repository = new File(s101, "repository");
		File project = new File(repository, "project");
		if (project.mkdirs()) {
			copyToBuildDirectory("s101/project.java.hsp", new File(s101, "project.java.hsp"));
			copyToBuildDirectory("s101/config.xml", new File(s101, "config.xml"));
			copyToBuildDirectory("s101/repository.xml", new File(repository, "repository.xml"));
		}
		System.setProperty("s101.label", "baseline");
		S101Headless.headlessRunner(new String[] { new File(s101, "config.xml").getAbsolutePath(),
			"-licensedirectory=" + System.getProperty("user.home") + "/.Structure101/java"});
	}

	private void copyToBuildDirectory(String templateLocation, File destination) {
		Resource template = new ClassPathResource(templateLocation);
		try (InputStream is = template.getInputStream()) { // change to read in as template
			Files.copy(is, destination.toPath());
		} catch (IOException ex) {
			throw new UncheckedIOException(ex);
		}
	}
}
