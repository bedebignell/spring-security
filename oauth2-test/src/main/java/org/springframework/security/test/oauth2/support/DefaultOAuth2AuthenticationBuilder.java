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
package org.springframework.security.test.oauth2.support;

import static org.springframework.security.test.oauth2.support.CollectionsSupport.asSet;

import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Stream;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public abstract class DefaultOAuth2AuthenticationBuilder<T extends DefaultOAuth2AuthenticationBuilder<T>> {

	public static final String DEFAULT_AUTH_NAME = "user";

	public static final String[] DEFAULT_AUTHORITIES = { "ROLE_USER" };

	private static final String ROLE_PREFIX = "ROLE_";

	private static final String SCOPE_PREFIX = "SCOPE_";

	protected String name;

	protected final Set<String> authorities;

	private boolean isAuthoritiesSet = false;

	protected final Set<String> scopes = new HashSet<>();

	protected final Map<String, Object> attributes = new HashMap<>();

	public DefaultOAuth2AuthenticationBuilder(final String defaultName, final String[] defaultAuthorities) {
		this.name = defaultName;
		this.authorities = new HashSet<>(asSet(defaultAuthorities));
	}

	public DefaultOAuth2AuthenticationBuilder() {
		this(DEFAULT_AUTH_NAME, DEFAULT_AUTHORITIES);
	}

	public T name(final String name) {
		this.name = name;
		return downCast();
	}

	public T authority(final String authority) {
		assert (authority != null);
		if (!this.isAuthoritiesSet) {
			this.authorities.clear();
			this.isAuthoritiesSet = true;
		}
		this.authorities.add(authority);
		if (authority.startsWith(SCOPE_PREFIX)) {
			this.scopes.add(authority.substring(SCOPE_PREFIX.length()));
		}
		return downCast();
	}

	public T authorities(final String... authorities) {
		Stream.of(authorities).forEach(this::authority);
		return downCast();
	}

	public T role(final String role) {
		assert (role != null);
		assert (!role.startsWith(ROLE_PREFIX));
		return authority(ROLE_PREFIX + role);
	}

	public T roles(final String... roles) {
		Stream.of(roles).forEach(this::role);
		return downCast();
	}

	public T scope(final String role) {
		assert (role != null);
		assert (!role.startsWith(SCOPE_PREFIX));
		return authority(SCOPE_PREFIX + role);
	}

	public T scopes(final String... scope) {
		Stream.of(scope).forEach(this::scope);
		return downCast();
	}

	public T attributes(final Map<String, Object> attributes) {
		assert (attributes != null);
		attributes.entrySet().stream().forEach(e -> this.attribute(e.getKey(), e.getValue()));
		return downCast();
	}

	public T attribute(final String name, final Object value) {
		assert (name != null);
		this.attributes.put(name, value);
		return downCast();
	}

	@SuppressWarnings("unchecked")
	protected T downCast() {
		return (T) this;
	}

}
