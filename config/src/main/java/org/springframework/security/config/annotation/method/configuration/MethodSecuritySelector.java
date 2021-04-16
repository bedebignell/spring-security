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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.Map;

import org.springframework.context.annotation.AdviceMode;
import org.springframework.context.annotation.AdviceModeImportSelector;
import org.springframework.context.annotation.AutoProxyRegistrar;
import org.springframework.context.annotation.ImportSelector;
import org.springframework.core.annotation.AnnotationAttributes;
import org.springframework.core.type.AnnotationMetadata;
import org.springframework.lang.NonNull;

/**
 * Dynamically determines which imports to include using the {@link EnableMethodSecurity}
 * annotation.
 *
 * @author Evgeniy Cheban
 * @since 5.6
 */
final class MethodSecuritySelector implements ImportSelector {

	private final ImportSelector autoProxy = new AutoProxyRegistrarSelector();

	@Override
	public String[] selectImports(@NonNull AnnotationMetadata importMetadata) {
		Map<String, Object> attributes = importMetadata.getAnnotationAttributes(EnableMethodSecurity.class.getName());
		AnnotationAttributes annotationAttributes = AnnotationAttributes.fromMap(attributes);
		if (annotationAttributes == null) {
			return new String[0];
		}
		List<String> imports = new ArrayList<>(Arrays.asList(this.autoProxy.selectImports(importMetadata)));
		if (isPrePostEnabled(annotationAttributes)) {
			imports.add(PrePostMethodSecurityConfiguration.class.getName());
		}
		if (isSecuredEnabled(annotationAttributes)) {
			imports.add(SecuredMethodSecurityConfiguration.class.getName());
		}
		if (isJsr250Enabled(annotationAttributes)) {
			imports.add(Jsr250MethodSecurityConfiguration.class.getName());
		}
		return imports.toArray(new String[0]);
	}

	private boolean isPrePostEnabled(AnnotationAttributes attributes) {
		return attributes.getBoolean("prePostEnabled");
	}

	private boolean isSecuredEnabled(AnnotationAttributes attributes) {
		return attributes.getBoolean("securedEnabled");
	}

	private boolean isJsr250Enabled(AnnotationAttributes attributes) {
		return attributes.getBoolean("jsr250Enabled");
	}

	private static final class AutoProxyRegistrarSelector extends AdviceModeImportSelector<EnableMethodSecurity> {

		@Override
		protected String[] selectImports(@NonNull AdviceMode adviceMode) {
			if (adviceMode == AdviceMode.PROXY) {
				return getProxyImports();
			}
			throw new IllegalStateException("AdviceMode '" + adviceMode + "' is not supported");
		}

		private String[] getProxyImports() {
			List<String> result = new ArrayList<>();
			result.add(AutoProxyRegistrar.class.getName());
			return result.toArray(new String[0]);
		}

	}

}
