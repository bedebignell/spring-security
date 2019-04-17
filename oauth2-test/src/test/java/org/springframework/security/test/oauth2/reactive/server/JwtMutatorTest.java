/*
 * Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.oauth2.reactive.server;

import static org.springframework.security.test.oauth2.reactive.server.OAuth2SecurityMockServerConfigurers.mockJwt;

import org.junit.Test;
import org.springframework.security.test.oauth2.reactive.server.TestControllers.AuthoritiesController;
import org.springframework.security.test.oauth2.reactive.server.TestControllers.GreetController;
import org.springframework.security.test.oauth2.reactive.server.TestControllers.JwtController;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class JwtMutatorTest {

	@Test
	public void testDefaultJwtConfigurer() {
		GreetController.clientBuilder()
				.apply(mockJwt())
				.build()
				.get()
				.exchange()
				.expectStatus()
				.isOk()
				.expectBody()
				.toString()
				.equals("Hello user!");

		AuthoritiesController.clientBuilder()
				.apply(mockJwt())
				.build()
				.get()
				.exchange()
				.expectStatus()
				.isOk()
				.expectBody()
				.toString()
				.equals("[\"ROLE_USER\"]");
	}

	@Test
	public void testCustomJwtConfigurer() {
		GreetController.clientBuilder()
				.apply(mockJwt().name("ch4mpy").scope("message:read"))
				.build()
				.get()
				.exchange()
				.expectStatus()
				.isOk()
				.expectBody()
				.toString()
				.equals("Hello ch4mpy!");

		AuthoritiesController.clientBuilder()
				.apply(mockJwt().name("ch4mpy").scope("message:read"))
				.build()
				.get()
				.exchange()
				.expectStatus()
				.isOk()
				.expectBody()
				.toString()
				.equals("[\"SCOPE_message:read\"]");

		JwtController.clientBuilder()
				.apply(mockJwt().name("ch4mpy").scope("message:read"))
				.build()
				.get()
				.exchange()
				.expectStatus()
				.isOk()
				.expectBody()
				.toString()
				.equals(
						"Hello,ch4mpy! You are sucessfully authenticated and granted with [message:read] scopes using a JavaWebToken.");
	}

	@Test
	public void testCustomJwtMutator() {
		GreetController.client()
				.mutateWith((mockJwt().name("ch4mpy").scope("message:read")))
				.get()
				.exchange()
				.expectStatus()
				.isOk()
				.expectBody()
				.toString()
				.equals("Hello ch4mpy!");

		AuthoritiesController.client()
				.mutateWith((mockJwt().name("ch4mpy").scope("message:read")))
				.get()
				.exchange()
				.expectStatus()
				.isOk()
				.expectBody()
				.toString()
				.equals("[\"SCOPE_message:read\"]");

		JwtController.client()
				.mutateWith(mockJwt().name("ch4mpy").scope("message:read"))
				.get()
				.exchange()
				.expectStatus()
				.isOk()
				.expectBody()
				.toString()
				.equals(
						"Hello,ch4mpy! You are sucessfully authenticated and granted with [message:read] scopes using a JavaWebToken.");
	}

}
