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

import java.lang.reflect.AccessibleObject;
import java.lang.reflect.Method;
import java.util.Collections;
import java.util.List;
import java.util.function.Supplier;

import org.aopalliance.intercept.MethodInvocation;

import org.springframework.aop.support.AopUtils;
import org.springframework.security.core.Authentication;

/**
 * @author Josh Cummings
 */
final class AuthorizationMethodInvocation implements MethodInvocation {

	private final MethodInvocation methodInvocation;

	private final Class<?> targetClass;

	AuthorizationMethodInvocation(Supplier<Authentication> authentication, MethodInvocation methodInvocation) {
		this(authentication, methodInvocation, Collections.emptyList());
	}

	AuthorizationMethodInvocation(Supplier<Authentication> authentication, MethodInvocation methodInvocation,
			List<AuthorizationMethodInterceptor> interceptors) {
		this.methodInvocation = methodInvocation;
		Object target = methodInvocation.getThis();
		this.targetClass = (target != null) ? AopUtils.getTargetClass(target) : null;
	}

	@Override
	public Method getMethod() {
		return this.methodInvocation.getMethod();
	}

	@Override
	public Object[] getArguments() {
		return this.methodInvocation.getArguments();
	}

	/**
	 * Return the target class.
	 * @return the target class
	 */
	Class<?> getTargetClass() {
		return this.targetClass;
	}

	@Override
	public Object proceed() throws Throwable {
		return this.methodInvocation.proceed();
	}

	@Override
	public Object getThis() {
		return this.methodInvocation.getThis();
	}

	@Override
	public AccessibleObject getStaticPart() {
		return this.methodInvocation.getStaticPart();
	}

}
