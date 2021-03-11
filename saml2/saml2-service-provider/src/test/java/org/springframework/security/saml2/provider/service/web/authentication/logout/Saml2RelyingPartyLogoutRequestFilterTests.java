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

package org.springframework.security.saml2.provider.service.web.authentication.logout;

import java.util.ArrayList;
import java.util.HashMap;

import org.junit.After;
import org.junit.Test;

import org.springframework.mock.web.MockFilterChain;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.saml2.provider.service.authentication.DefaultSaml2AuthenticatedPrincipal;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutRequest;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.registration.TestRelyingPartyRegistrations;
import org.springframework.security.saml2.provider.service.web.authentication.logout.Saml2LogoutRequestResolver.Saml2LogoutRequestPartial;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.BDDMockito.RETURNS_SELF;
import static org.mockito.BDDMockito.mock;
import static org.mockito.BDDMockito.when;
import static org.mockito.BDDMockito.willReturn;

/**
 * Tests for {@link Saml2RelyingPartyLogoutRequestFilter}
 *
 * @author Josh Cummings
 */
public class Saml2RelyingPartyLogoutRequestFilterTests {

	private final Saml2LogoutRequestResolver resolver = mock(Saml2LogoutRequestResolver.class);

	private final Saml2RelyingPartyLogoutRequestFilter handler = new Saml2RelyingPartyLogoutRequestFilter(
			this.resolver);

	@After
	public void tearDown() {
		SecurityContextHolder.clearContext();
	}

	@Test
	public void doFilterWhenRedirectThenRedirectsToAssertingParty() throws Exception {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full().build();
		Authentication authentication = authentication(registration);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest("request").build();
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/saml2/logout");
		request.setServletPath("/saml2/logout");
		MockHttpServletResponse response = new MockHttpServletResponse();
		Saml2LogoutRequestPartial<?> partial = mock(Saml2LogoutRequestPartial.class, RETURNS_SELF);
		when(partial.logoutRequest()).thenReturn(logoutRequest);
		willReturn(partial).given(this.resolver).resolveLogoutRequest(request, authentication);
		this.handler.doFilterInternal(request, response, new MockFilterChain());
		assertThat(response.getHeader("Location"))
				.startsWith(registration.getAssertingPartyDetails().getSingleLogoutServiceLocation());
	}

	@Test
	public void doFilterWhenPostThenPostsToAssertingParty() throws Exception {
		RelyingPartyRegistration registration = TestRelyingPartyRegistrations.full()
				.assertingPartyDetails((party) -> party.singleLogoutServiceBinding(Saml2MessageBinding.POST)).build();
		Authentication authentication = authentication(registration);
		SecurityContextHolder.getContext().setAuthentication(authentication);
		Saml2LogoutRequest logoutRequest = Saml2LogoutRequest.withRelyingPartyRegistration(registration)
				.samlRequest("request").build();
		MockHttpServletRequest request = new MockHttpServletRequest("POST", "/saml2/logout");
		request.setServletPath("/saml2/logout");
		MockHttpServletResponse response = new MockHttpServletResponse();
		Saml2LogoutRequestPartial<?> partial = mock(Saml2LogoutRequestPartial.class, RETURNS_SELF);
		when(partial.logoutRequest()).thenReturn(logoutRequest);
		willReturn(partial).given(this.resolver).resolveLogoutRequest(request, authentication);
		this.handler.doFilterInternal(request, response, new MockFilterChain());
		assertThat(response.getContentAsString())
				.contains(registration.getAssertingPartyDetails().getSingleLogoutServiceLocation());
	}

	private Saml2Authentication authentication(RelyingPartyRegistration registration) {
		return new Saml2Authentication(new DefaultSaml2AuthenticatedPrincipal("user", new HashMap<>()), "response",
				new ArrayList<>(), registration.getRegistrationId());
	}

}