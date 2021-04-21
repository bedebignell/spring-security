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

package org.springframework.security.authorization.method;

import javax.annotation.security.DenyAll;
import javax.annotation.security.PermitAll;
import javax.annotation.security.RolesAllowed;

import org.springframework.aop.Advisor;
import org.springframework.security.access.annotation.Secured;
import org.springframework.security.access.prepost.PostAuthorize;
import org.springframework.security.access.prepost.PreAuthorize;

/**
 * A static factory for constructing common authorization {@link Advisor}s
 *
 * @author Josh Cummings
 * @since 5.6
 * @see PreAuthorizeAuthorizationManager
 * @see PostAuthorizeAuthorizationManager
 * @see SecuredAuthorizationManager
 * @see Jsr250AuthorizationManager
 */
public final class AuthorizationAdvisors {

	public static final int PRE_FILTER_ADVISOR_ORDER = 100;

	public static final int PRE_AUTHORIZE_ADVISOR_ORDER = 200;

	public static final int POST_AUTHORIZE_ADVISOR_ORDER = 300;

	public static final int POST_FILTER_ADVISOR_ORDER = 400;

	public static final int SECURED_ADVISOR_ORDER = 500;

	public static final int JSR250_ADVISOR_ORDER = 600;

	public static Advisor preAuthorize() {
		return preAuthorize(new PreAuthorizeAuthorizationManager());
	}

	public static Advisor preAuthorize(PreAuthorizeAuthorizationManager manager) {
		return new AuthorizationManagerBeforeMethodInterceptor(PRE_AUTHORIZE_ADVISOR_ORDER,
				AuthorizationMethodPointcuts.forAnnotations(PreAuthorize.class), manager);
	}

	public static Advisor postAuthorize() {
		return postAuthorize(new PostAuthorizeAuthorizationManager());
	}

	public static Advisor postAuthorize(PostAuthorizeAuthorizationManager manager) {
		return new AuthorizationManagerAfterMethodInterceptor(POST_AUTHORIZE_ADVISOR_ORDER,
				AuthorizationMethodPointcuts.forAnnotations(PostAuthorize.class), manager);
	}

	public static Advisor secured() {
		return secured(new SecuredAuthorizationManager());
	}

	public static Advisor secured(SecuredAuthorizationManager manager) {
		return new AuthorizationManagerBeforeMethodInterceptor(SECURED_ADVISOR_ORDER,
				AuthorizationMethodPointcuts.forAnnotations(Secured.class), manager);
	}

	public static Advisor jsr250() {
		return jsr250(new Jsr250AuthorizationManager());
	}

	public static Advisor jsr250(Jsr250AuthorizationManager manager) {
		return new AuthorizationManagerBeforeMethodInterceptor(JSR250_ADVISOR_ORDER,
				AuthorizationMethodPointcuts.forAnnotations(DenyAll.class, PermitAll.class, RolesAllowed.class),
				manager);
	}

	private AuthorizationAdvisors() {

	}

}
