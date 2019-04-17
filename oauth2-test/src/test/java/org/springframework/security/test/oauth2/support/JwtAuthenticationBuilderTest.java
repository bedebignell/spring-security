/* Copyright 2002-2019 the original author or authors.
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
package org.springframework.security.test.oauth2.support;

import static org.assertj.core.api.Assertions.assertThat;

import java.time.Instant;
import java.util.Collection;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import org.junit.Test;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public class JwtAuthenticationBuilderTest {
	static class TestJwtAuthenticationBuilder extends JwtAuthenticationBuilder<TestJwtAuthenticationBuilder> {
	}

	@Test
	public void defaultNameAndAuthority() {
		final JwtAuthenticationToken actual = new TestJwtAuthenticationBuilder().build();

		assertThat(actual.getName()).isEqualTo("user");
		assertThat(actual.getAuthorities()).containsExactly(new SimpleGrantedAuthority("ROLE_USER"));
	}

	@Test
	public void defaultNameAndRoleOverides() {
		assertThat(new TestJwtAuthenticationBuilder().name("ch4mpy").build().getName()).isEqualTo("ch4mpy");
		assertThat(new TestJwtAuthenticationBuilder().authority("TEST").build().getAuthorities())
				.containsExactly(new SimpleGrantedAuthority("TEST"));
		assertThat(new TestJwtAuthenticationBuilder().role("TEST").build().getAuthorities())
				.containsExactly(new SimpleGrantedAuthority("ROLE_TEST"));
		assertThat(new TestJwtAuthenticationBuilder().scope("TEST").build().getAuthorities())
				.containsExactly(new SimpleGrantedAuthority("SCOPE_TEST"));
	}

	@Test
	public void authenticationNameAndTokenSubjectClaimAreSet() {
		final JwtAuthenticationToken actual = new TestJwtAuthenticationBuilder().name("ch4mpy").build();

		assertThat(actual.getName()).isEqualTo("ch4mpy");
		assertThat(actual.getTokenAttributes().get(JwtClaimNames.SUB)).isEqualTo("ch4mpy");
	}

	@Test
	public void tokenIatIsSetFromClaims() {
		final Jwt actual = new TestJwtAuthenticationBuilder().name("ch4mpy")
				.claim(JwtClaimNames.IAT, Instant.parse("2019-03-21T13:52:25Z"))
				.build()
				.getToken();

		assertThat(actual.getIssuedAt()).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
		assertThat(actual.getExpiresAt()).isNull();
		assertThat(actual.getClaimAsInstant(JwtClaimNames.IAT)).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
		assertThat(actual.getClaimAsInstant(JwtClaimNames.EXP)).isNull();
	}

	@Test
	public void tokenExpIsSetFromClaims() {
		final Jwt actual = new TestJwtAuthenticationBuilder().name("ch4mpy")
				.claim(JwtClaimNames.EXP, Instant.parse("2019-03-21T13:52:25Z"))
				.build()
				.getToken();

		assertThat(actual.getIssuedAt()).isNull();
		assertThat(actual.getExpiresAt()).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
		assertThat(actual.getClaimAsInstant(JwtClaimNames.IAT)).isNull();
		assertThat(actual.getClaimAsInstant(JwtClaimNames.EXP)).isEqualTo(Instant.parse("2019-03-21T13:52:25Z"));
	}

	@Test
	public void scopesCollectionAndScopeClaimAreAddedToAuthorities() {
		final JwtAuthenticationToken actual = new TestJwtAuthenticationBuilder().name("ch4mpy")
				.authority("TEST_AUTHORITY")
				.scope("scope:collection")
				.claim("scope", Collections.singleton("scope:claim"))
				.build();

		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("TEST_AUTHORITY"),
				new SimpleGrantedAuthority("SCOPE_scope:collection"),
				new SimpleGrantedAuthority("SCOPE_scope:claim"));
	}

	@SuppressWarnings("unchecked")
	@Test
	public void scopesCollectionAndScopeAuthoritiesAreAddedToScopeClaim() {
		final JwtAuthenticationToken actual = new TestJwtAuthenticationBuilder().name("ch4mpy")
				.authorities("SCOPE_scope:authority")
				.scope("scope:collection")
				.claim("scope", Collections.singleton("scope:claim"))
				.build();

		assertThat((Collection<String>) actual.getToken().getClaims().get("scope"))
				.containsExactlyInAnyOrder("scope:authority", "scope:collection", "scope:claim");
	}

	/**
	 * "scp" is the an usual name for "scope" claim
	 */

	@Test
	public void scopesCollectionAndScpClaimAreAddedToAuthorities() {
		final JwtAuthenticationToken actual = new TestJwtAuthenticationBuilder().name("ch4mpy")
				.authorities("TEST_AUTHORITY")
				.scopes("scope:collection")
				.claim("scp", Collections.singleton("scope:claim"))
				.scopesClaimName("scp")
				.build();

		assertThat(actual.getAuthorities()).containsExactlyInAnyOrder(
				new SimpleGrantedAuthority("TEST_AUTHORITY"),
				new SimpleGrantedAuthority("SCOPE_scope:collection"),
				new SimpleGrantedAuthority("SCOPE_scope:claim"));
	}

	@Test
	public void fromJwt() {
		final Jwt jwt = new Jwt(
				"test-token",
				null,
				null,
				Collections.singletonMap("test-header", "test"),
				Collections.singletonMap(JwtClaimNames.SUB, "ch4mpy"));
		final JwtAuthenticationToken actual = new TestJwtAuthenticationBuilder().jwt(jwt).build();
		assertThat(actual.getAuthorities()).containsExactly(new SimpleGrantedAuthority("ROLE_USER"));
		assertThat(actual.getName()).isEqualTo("ch4mpy");
		assertThat(actual.getTokenAttributes()).hasSize(1);
		assertThat(actual.getTokenAttributes().get(JwtClaimNames.SUB)).isEqualTo("ch4mpy");
	}

	@Test(expected = RuntimeException.class)
	public void fromInconsistentJwtInstants() {
		final Map<String, Object> claims = new HashMap<>();
		claims.put(JwtClaimNames.SUB, "ch4mpy");
		claims.put(JwtClaimNames.IAT, Instant.parse("2018-01-01T01:01:01Z"));
		claims.put(JwtClaimNames.EXP, Instant.parse("2018-02-02T02:02:02Z"));
		final Jwt jwt = new Jwt(
				"test-token",
				Instant.parse("2019-01-01T01:01:01Z"),
				Instant.parse("2019-02-02T02:02:02Z"),
				Collections.singletonMap("test-header", "test"),
				claims);

		final JwtAuthenticationToken actual = new TestJwtAuthenticationBuilder().jwt(jwt).build();
	}

}
