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

package org.springframework.security.config.annotation.method.configuration;

import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.config.BeanDefinition;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Role;
import org.springframework.core.annotation.Order;
import org.springframework.security.access.expression.method.MethodSecurityExpressionHandler;
import org.springframework.security.authorization.method.AuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.AuthorizationMethodInterceptors;
import org.springframework.security.authorization.method.PostAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PostFilterAuthorizationMethodInterceptor;
import org.springframework.security.authorization.method.PreAuthorizeAuthorizationManager;
import org.springframework.security.authorization.method.PreFilterAuthorizationMethodInterceptor;

/**
 * Base {@link Configuration} for enabling Spring Security Method Security.
 *
 * @author Evgeniy Cheban
 * @author Josh Cummings
 * @see EnableMethodSecurity
 * @since 5.6
 */
@Configuration(proxyBeanMethods = false)
@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
final class PrePostMethodSecurityConfiguration {

	public static final int PRE_FILTER_INTERCEPTOR_ORDER = 100;

	public static final int PRE_AUTHORIZE_INTERCEPTOR_ORDER = 200;

	public static final int POST_AUTHORIZE_INTERCEPTOR_ORDER = 300;

	public static final int POST_FILTER_INTERCEPTOR_ORDER = 400;

	private final PreFilterAuthorizationMethodInterceptor preFilterAuthorizationMethodInterceptor = new PreFilterAuthorizationMethodInterceptor();

	private final PreAuthorizeAuthorizationManager preAuthorizeAuthorizationManager = new PreAuthorizeAuthorizationManager();

	private final PostAuthorizeAuthorizationManager postAuthorizeAuthorizationManager = new PostAuthorizeAuthorizationManager();

	private final PostFilterAuthorizationMethodInterceptor postFilterAuthorizationMethodInterceptor = new PostFilterAuthorizationMethodInterceptor();

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	@Order(PRE_FILTER_INTERCEPTOR_ORDER)
	AuthorizationMethodInterceptor preFilterAuthorizationMethodInterceptor() {
		return this.preFilterAuthorizationMethodInterceptor;
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	@Order(PRE_AUTHORIZE_INTERCEPTOR_ORDER)
	AuthorizationMethodInterceptor preAuthorizeAuthorizationMethodInterceptor() {
		return AuthorizationMethodInterceptors.preAuthorize(this.preAuthorizeAuthorizationManager);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	@Order(POST_AUTHORIZE_INTERCEPTOR_ORDER)
	AuthorizationMethodInterceptor postAuthorizeAuthorizationMethodInterceptor() {
		return AuthorizationMethodInterceptors.postAuthorize(this.postAuthorizeAuthorizationManager);
	}

	@Bean
	@Role(BeanDefinition.ROLE_INFRASTRUCTURE)
	@Order(POST_FILTER_INTERCEPTOR_ORDER)
	AuthorizationMethodInterceptor postFilterAuthorizationMethodInterceptor() {
		return this.postFilterAuthorizationMethodInterceptor;
	}

	@Autowired(required = false)
	void setMethodSecurityExpressionHandler(MethodSecurityExpressionHandler methodSecurityExpressionHandler) {
		this.preFilterAuthorizationMethodInterceptor.setExpressionHandler(methodSecurityExpressionHandler);
		this.preAuthorizeAuthorizationManager.setExpressionHandler(methodSecurityExpressionHandler);
		this.postAuthorizeAuthorizationManager.setExpressionHandler(methodSecurityExpressionHandler);
		this.postFilterAuthorizationMethodInterceptor.setExpressionHandler(methodSecurityExpressionHandler);
	}

}
