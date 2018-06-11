/*
 * Copyright 2002-2018 the original author or authors.
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

package org.springframework.security.oauth2.core.scope;

import org.springframework.security.core.GrantedAuthority;

/**
 * A {@link GrantedAuthority} that represents an OAuth 2.0
 * <a href="https://tools.ietf.org/html/rfc6749#section-3.3" target="_blank">scope</a>.
 *
 * @author Josh Cummings
 * @since 5.1
 */
public class ScopeGrantedAuthority implements GrantedAuthority {
	private final String scope;

	public ScopeGrantedAuthority(String scope) {
		this.scope = scope;
	}

	@Override
	public String getAuthority() {
		return this.scope;
	}

	@Override
	public boolean equals(Object obj) {
		if (this == obj) {
			return true;
		}

		if (obj instanceof ScopeGrantedAuthority) {
			return this.scope.equals(((ScopeGrantedAuthority) obj).scope);
		}

		return false;
	}

	@Override
	public int hashCode() {
		return this.scope.hashCode();
	}

	@Override
	public String toString() {
		return this.scope;
	}
}
