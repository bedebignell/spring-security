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
import java.util.Arrays;
import java.util.concurrent.TimeUnit;

import com.github.dockerjava.api.DockerClient;
import com.github.dockerjava.api.async.ResultCallback;
import com.github.dockerjava.api.command.CreateContainerResponse;
import com.github.dockerjava.api.model.Frame;
import com.github.dockerjava.api.model.HostConfig;
import com.github.dockerjava.api.model.Mount;
import com.github.dockerjava.api.model.MountType;
import com.github.dockerjava.core.DefaultDockerClientConfig;
import com.github.dockerjava.core.DockerClientConfig;
import com.github.dockerjava.core.DockerClientImpl;
import com.github.dockerjava.httpclient5.ApacheDockerHttpClient;
import com.github.dockerjava.transport.DockerHttpClient;
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
		DockerClientConfig standard = DefaultDockerClientConfig.createDefaultConfigBuilder().build();
		DockerHttpClient client = new ApacheDockerHttpClient.Builder()
				.dockerHost(standard.getDockerHost())
				.sslConfig(standard.getSSLConfig())
				.build();
		DockerClient dockerClient = DockerClientImpl.getInstance(standard, client);
		Mount mount = new Mount()
				.withType(MountType.BIND)
				.withSource(build.getParent())
				.withTarget("/etc/structure101");
		HostConfig hostConfig = new HostConfig().withMounts(Arrays.asList(mount));
		CreateContainerResponse created = dockerClient.createContainerCmd("jzheaux/structure101-build")
				.withHostConfig(hostConfig)
				.withWorkingDir("/etc/structure101/build/s101")
				.withEntrypoint("sh", "-c", "java -Ds101.label=baseline -jar /opt/structure101/structure101-java-build.jar /etc/structure101/build/s101/config.xml")
				.exec();
		dockerClient.startContainerCmd(created.getId()).exec();
		ResultCallback.Adapter<Frame> logs = dockerClient.logContainerCmd(created.getId())
				.withStdOut(true)
				.withStdErr(true)
				.withFollowStream(true)
				.withTailAll()
				.exec(new ResultCallback.Adapter<Frame>() {
					@Override
					public void onNext(Frame item) {
						S101Build.this.getLogger().info(item.toString());
					}
				});
		try {
			logs.awaitCompletion(2, TimeUnit.MINUTES);
		} catch (InterruptedException e) {
			Thread.currentThread().interrupt();
		} finally {
			dockerClient.startContainerCmd(created.getId()).exec();
			dockerClient.removeContainerCmd(created.getId()).exec();
		}
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
