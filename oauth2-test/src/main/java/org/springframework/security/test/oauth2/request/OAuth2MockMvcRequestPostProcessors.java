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
package org.springframework.security.test.oauth2.request;

import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.OAuth2AccessToken;
import org.springframework.security.oauth2.core.oidc.OidcIdToken;
import org.springframework.security.oauth2.jwt.Jwt;

/**
 * @author Jérôme Wacongne &lt;ch4mp@c4-soft.com&gt;
 * @since 5.2.0
 */
public final class OAuth2MockMvcRequestPostProcessors {
	public static final AuthorizationGrantType DEFAULT_REQUEST_AUTHORIZATION_GRANT_TYPE =
			AuthorizationGrantType.AUTHORIZATION_CODE;

	public static JwtRequestPostProcessor mockJwt() {
		return new JwtRequestPostProcessor();
	}

	public static JwtRequestPostProcessor mockJwt(final Jwt jwt) {
		return mockJwt().jwt(jwt);
	}

	public static AccessTokenRequestPostProcessor mockAccessToken() {
		return new AccessTokenRequestPostProcessor();
	}

	public static AccessTokenRequestPostProcessor mockAccessToken(final OAuth2AccessToken token) {
		return new AccessTokenRequestPostProcessor().accessToken(token);
	}

	public static OidcIdTokenRequestPostProcessor mockOidcId(final AuthorizationGrantType authorizationGrantType) {
		return new OidcIdTokenRequestPostProcessor(authorizationGrantType);
	}

	public static OidcIdTokenRequestPostProcessor mockOidcId() {
		return mockOidcId(DEFAULT_REQUEST_AUTHORIZATION_GRANT_TYPE);
	}

	public static OidcIdTokenRequestPostProcessor
			mockOidcId(final OidcIdToken token, final AuthorizationGrantType requestAuthorizationGrantType) {
		return mockOidcId(requestAuthorizationGrantType).token(token);
	}

	public static OidcIdTokenRequestPostProcessor mockOidcId(final OidcIdToken token) {
		return mockOidcId().token(token);
	}

}
