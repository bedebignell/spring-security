/*
 * Copyright 2002-2013 the original author or authors.
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
package org.springframework.security.config.annotation.web.configurers

import org.springframework.mock.web.MockFilterChain
import org.springframework.mock.web.MockHttpServletRequest
import org.springframework.mock.web.MockHttpServletResponse
import org.springframework.security.authentication.AbstractAuthenticationToken
import org.springframework.security.authentication.AuthenticationProvider
import org.springframework.security.authentication.AuthenticationTrustResolver
import org.springframework.security.config.annotation.AnyObjectPostProcessor
import org.springframework.security.config.annotation.BaseSpringSpec
import org.springframework.security.config.annotation.authentication.builders.AuthenticationManagerBuilder
import org.springframework.security.config.annotation.web.builders.HttpSecurity
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity
import org.springframework.security.config.annotation.web.configuration.WebSecurityConfigurerAdapter
import org.springframework.security.config.http.SessionCreationPolicy
import org.springframework.security.core.Authentication
import org.springframework.security.core.AuthenticationException
import org.springframework.security.core.TransientAuthentication
import org.springframework.security.core.userdetails.PasswordEncodedUser
import org.springframework.security.web.access.ExceptionTranslationFilter
import org.springframework.security.web.authentication.session.AbstractSessionFixationProtectionStrategy
import org.springframework.security.web.authentication.session.CompositeSessionAuthenticationStrategy
import org.springframework.security.web.authentication.session.ConcurrentSessionControlAuthenticationStrategy
import org.springframework.security.web.authentication.session.RegisterSessionAuthenticationStrategy
import org.springframework.security.web.context.NullSecurityContextRepository
import org.springframework.security.web.context.SecurityContextPersistenceFilter
import org.springframework.security.web.context.SecurityContextRepository
import org.springframework.security.web.savedrequest.RequestCache
import org.springframework.security.web.session.ConcurrentSessionFilter
import org.springframework.security.web.session.HttpSessionDestroyedEvent
import org.springframework.security.web.session.SessionManagementFilter

import javax.servlet.http.HttpServletResponse
/**
 *
 * @author Rob Winch
 */
class SessionManagementConfigurerTests extends BaseSpringSpec {

	def "sessionManagement does not override explicit RequestCache"() {
		setup:
			SessionManagementDoesNotOverrideExplicitRequestCacheConfig.REQUEST_CACHE = Mock(RequestCache)
		when:
			loadConfig(SessionManagementDoesNotOverrideExplicitRequestCacheConfig)
		then:
			findFilter(ExceptionTranslationFilter).requestCache == SessionManagementDoesNotOverrideExplicitRequestCacheConfig.REQUEST_CACHE
	}

	@EnableWebSecurity
	static class SessionManagementDoesNotOverrideExplicitRequestCacheConfig extends WebSecurityConfigurerAdapter {
		static RequestCache REQUEST_CACHE

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.requestCache()
					.requestCache(REQUEST_CACHE)
					.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		}

	}

	def "sessionManagement does not override explict SecurityContextRepository"() {
		setup:
			SessionManagementDoesNotOverrideExplicitSecurityContextRepositoryConfig.SECURITY_CONTEXT_REPO = Mock(SecurityContextRepository)
		when:
			loadConfig(SessionManagementDoesNotOverrideExplicitSecurityContextRepositoryConfig)
		then:
			findFilter(SecurityContextPersistenceFilter).repo == SessionManagementDoesNotOverrideExplicitSecurityContextRepositoryConfig.SECURITY_CONTEXT_REPO
	}

	@EnableWebSecurity
	static class SessionManagementDoesNotOverrideExplicitSecurityContextRepositoryConfig extends WebSecurityConfigurerAdapter {
		static SecurityContextRepository SECURITY_CONTEXT_REPO

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.securityContext()
					.securityContextRepository(SECURITY_CONTEXT_REPO)
					.and()
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
		}

	}

	def "invoke sessionManagement twice does not override"() {
		when:
			loadConfig(InvokeTwiceDoesNotOverride)
		then:
			findFilter(SecurityContextPersistenceFilter).repo.class == NullSecurityContextRepository
	}

	@EnableWebSecurity
	static class InvokeTwiceDoesNotOverride extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.sessionManagement()
					.sessionCreationPolicy(SessionCreationPolicy.STATELESS)
					.and()
				.sessionManagement()
		}

	}

	def 'SEC-2137: disable session fixation and enable concurrency control'() {
		setup: "context where session fixation is disabled and concurrency control is enabled"
			loadConfig(DisableSessionFixationEnableConcurrencyControlConfig)
			String originalSessionId = request.session.id
			String credentials = "user:password"
			request.addHeader("Authorization", "Basic " + credentials.bytes.encodeBase64())
		when: "authenticate"
			springSecurityFilterChain.doFilter(request, response, new MockFilterChain())
		then: "session invalidate is not called"
			request.session.id == originalSessionId
	}

	@EnableWebSecurity
	static class DisableSessionFixationEnableConcurrencyControlConfig extends WebSecurityConfigurerAdapter {
		@Override
		public void configure(HttpSecurity http) {
			http
				.httpBasic()
					.and()
				.sessionManagement()
					.sessionFixation().none()
					.maximumSessions(1)
		}
		@Override
		protected void configure(AuthenticationManagerBuilder auth) {
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user())
		}
	}

	def 'session fixation and enable concurrency control'() {
		setup: "context where session fixation is disabled and concurrency control is enabled"
			loadConfig(ConcurrencyControlConfig)
			def authenticatedSession
		when: "authenticate successfully"
			request.servletPath = "/login"
			request.method = "POST"
			request.setParameter("username", "user");
			request.setParameter("password","password")
			springSecurityFilterChain.doFilter(request, response, chain)
			authenticatedSession = request.session
		then: "authentication is sucessful"
			response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
			response.redirectedUrl == "/"
		when: "authenticate with the same user"
			super.setup()
			request.servletPath = "/login"
			request.method = "POST"
			request.setParameter("username", "user");
			request.setParameter("password","password")
			springSecurityFilterChain.doFilter(request, response, chain)
		then:
			response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
			response.redirectedUrl == '/login?error'
		when: 'SEC-2574: When Session Expires and authentication attempted'
			context.publishEvent(new HttpSessionDestroyedEvent(authenticatedSession))
			super.setup()
			request.servletPath = "/login"
			request.method = "POST"
			request.setParameter("username", "user");
			request.setParameter("password","password")
			springSecurityFilterChain.doFilter(request, response, chain)
		then: "authentication is successful"
			response.status == HttpServletResponse.SC_MOVED_TEMPORARILY
			response.redirectedUrl == "/"
	}

	@EnableWebSecurity
	static class ConcurrencyControlConfig extends WebSecurityConfigurerAdapter {
		@Override
		public void configure(HttpSecurity http) {
			http
				.formLogin()
					.and()
				.sessionManagement()
					.maximumSessions(1)
						.maxSessionsPreventsLogin(true)
		}
		@Override
		protected void configure(AuthenticationManagerBuilder auth) {
			auth
				.inMemoryAuthentication()
					.withUser(PasswordEncodedUser.user())
		}
	}

	def "sessionManagement ObjectPostProcessor"() {
		setup:
			AnyObjectPostProcessor opp = Mock()
			HttpSecurity http = new HttpSecurity(opp, authenticationBldr, [:])
		when:
			http
				.sessionManagement()
					.maximumSessions(1)
						.and()
					.and()
				.build()

		then: "SessionManagementFilter is registered with ObjectPostProcessor"
			1 * opp.postProcess(_ as SessionManagementFilter) >> {SessionManagementFilter o -> o}
		and: "ConcurrentSessionFilter is registered with ObjectPostProcessor"
			1 * opp.postProcess(_ as ConcurrentSessionFilter) >> {ConcurrentSessionFilter o -> o}
		and: "ConcurrentSessionControlAuthenticationStrategy is registered with ObjectPostProcessor"
			1 * opp.postProcess(_ as ConcurrentSessionControlAuthenticationStrategy) >> {ConcurrentSessionControlAuthenticationStrategy o -> o}
		and: "CompositeSessionAuthenticationStrategy is registered with ObjectPostProcessor"
			1 * opp.postProcess(_ as CompositeSessionAuthenticationStrategy) >> {CompositeSessionAuthenticationStrategy o -> o}
		and: "RegisterSessionAuthenticationStrategy is registered with ObjectPostProcessor"
			1 * opp.postProcess(_ as RegisterSessionAuthenticationStrategy) >> {RegisterSessionAuthenticationStrategy o -> o}
		and: "SessionFixationProtectionStrategy is registered with ObjectPostProcessor"
			1 * opp.postProcess(_ as AbstractSessionFixationProtectionStrategy) >> {AbstractSessionFixationProtectionStrategy o -> o}
	}

	def "use sharedObject trustResolver"() {
		setup:
			SharedTrustResolverConfig.TR = Mock(AuthenticationTrustResolver)
		when:
			loadConfig(SharedTrustResolverConfig)
		then:
			findFilter(SecurityContextPersistenceFilter).repo.trustResolver == SharedTrustResolverConfig.TR
			findFilter(SessionManagementFilter).trustResolver == SharedTrustResolverConfig.TR
	}

	@EnableWebSecurity
	static class SharedTrustResolverConfig extends WebSecurityConfigurerAdapter {
		static AuthenticationTrustResolver TR

		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.setSharedObject(AuthenticationTrustResolver, TR)
		}
	}

	def doFilterWhenStatelessAuthenticationThenNoSessionCreated() {
		setup:
			MockHttpServletRequest request = new MockHttpServletRequest(method:'POST')
			request.servletPath = '/login'
			MockHttpServletResponse response  = new MockHttpServletResponse()
			MockFilterChain chain = new MockFilterChain()
		when:
			loadConfig(WithTransientAuthenticationConfig)
			springSecurityFilterChain.doFilter(request,response, chain)
		then:
			request.getSession(false) == null
	}

	def doFilterWhenStatelessAuthenticationThenAlwaysSessionOverrides() {
		setup:
			MockHttpServletRequest request = new MockHttpServletRequest(method:'POST')
			request.servletPath = '/login'
			MockHttpServletResponse response  = new MockHttpServletResponse()
			MockFilterChain chain = new MockFilterChain()
		when:
			loadConfig(AlwaysCreateSessionConfig)
			springSecurityFilterChain.doFilter(request,response, chain)
		then:
			request.getSession(false) != null
	}

	@EnableWebSecurity
	static class WithTransientAuthenticationConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			super.configure(http);
			http.csrf().disable();
		}

		@Override
		protected void configure(AuthenticationManagerBuilder auth) throws Exception {
			auth.authenticationProvider(new TransientAuthenticationProvider());
		}
	}

	@EnableWebSecurity
	static class AlwaysCreateSessionConfig extends WithTransientAuthenticationConfig {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			http
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.ALWAYS);
		}
	}

	static class TransientAuthenticationProvider implements AuthenticationProvider {

		@Override
		Authentication authenticate(Authentication authentication) throws AuthenticationException {
			return new SomeTransientAuthentication()
		}

		@Override
		boolean supports(Class<?> authentication) {
			return true
		}
	}

	@TransientAuthentication
	static class SomeTransientAuthentication extends AbstractAuthenticationToken {
		SomeTransientAuthentication() {
			super(null);
		}

		@Override
		Object getCredentials() {
			return null;
		}

		@Override
		Object getPrincipal() {
			return null;
		}
	}

	def doFilterWhenSharedObjectSessionCreationPolicyConfigurationThenOverrides() {
		setup:
			MockHttpServletRequest request = new MockHttpServletRequest(method:"GET")
			request.servletPath = "/"
			MockHttpServletResponse response  = new MockHttpServletResponse()
			MockFilterChain chain = new MockFilterChain()
		when:
			loadConfig(StatelessCreateSessionSharedObjectConfig)
			springSecurityFilterChain.doFilter(request,response, chain)
		then:
			request.getSession(false) == null
	}

	@EnableWebSecurity
	static class StatelessCreateSessionSharedObjectConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			super.configure(http);
			http.setSharedObject(SessionCreationPolicy.class, SessionCreationPolicy.STATELESS);
		}
	}

	def doFilterWhenUserSessionCreationPolicyConfigurationThenOverrides() {
		setup:
			MockHttpServletRequest request = new MockHttpServletRequest(method:"GET")
			request.servletPath = "/"
			MockHttpServletResponse response  = new MockHttpServletResponse()
			MockFilterChain chain = new MockFilterChain()
		when:
			loadConfig(StatelessCreateSessionUserConfig)
			springSecurityFilterChain.doFilter(request,response, chain)
		then:
			request.getSession(false) == null
	}

	@EnableWebSecurity
	static class StatelessCreateSessionUserConfig extends WebSecurityConfigurerAdapter {
		@Override
		protected void configure(HttpSecurity http) throws Exception {
			super.configure(http);
			http
				.sessionManagement().sessionCreationPolicy(SessionCreationPolicy.STATELESS);

			http.setSharedObject(SessionCreationPolicy.class, SessionCreationPolicy.ALWAYS);
		}
	}
}
