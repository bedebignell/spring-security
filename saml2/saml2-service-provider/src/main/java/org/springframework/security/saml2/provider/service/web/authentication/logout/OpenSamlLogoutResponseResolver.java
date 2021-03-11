/*
 * Copyright 2002-2020 the original author or authors.
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

import java.nio.charset.StandardCharsets;
import java.util.Map;
import java.util.UUID;
import java.util.function.Consumer;

import javax.servlet.http.HttpServletRequest;

import net.shibboleth.utilities.java.support.xml.SerializeSupport;
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.LogoutResponse;
import org.opensaml.saml.saml2.core.Status;
import org.opensaml.saml.saml2.core.StatusCode;
import org.opensaml.saml.saml2.core.impl.IssuerBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutResponseBuilder;
import org.opensaml.saml.saml2.core.impl.LogoutResponseMarshaller;
import org.opensaml.saml.saml2.core.impl.StatusBuilder;
import org.opensaml.saml.saml2.core.impl.StatusCodeBuilder;
import org.w3c.dom.Element;

import org.springframework.security.core.Authentication;
import org.springframework.security.saml2.Saml2Exception;
import org.springframework.security.saml2.core.OpenSamlInitializationService;
import org.springframework.security.saml2.provider.service.authentication.Saml2Authentication;
import org.springframework.security.saml2.provider.service.authentication.logout.Saml2LogoutResponse;
import org.springframework.security.saml2.provider.service.registration.RelyingPartyRegistration;
import org.springframework.security.saml2.provider.service.registration.Saml2MessageBinding;
import org.springframework.security.saml2.provider.service.web.RelyingPartyRegistrationResolver;
import org.springframework.util.Assert;

/**
 * We want to generate a logout response
 */
public final class OpenSamlLogoutResponseResolver implements Saml2LogoutResponseResolver {

	private final RelyingPartyRegistrationResolver relyingPartyRegistrationResolver;

	public OpenSamlLogoutResponseResolver(RelyingPartyRegistrationResolver relyingPartyRegistrationResolver) {
		this.relyingPartyRegistrationResolver = relyingPartyRegistrationResolver;
	}

	@Override
	public OpenSamlLogoutResponsePartial resolveLogoutResponse(HttpServletRequest request,
			Authentication authentication) {
		Assert.isTrue(authentication instanceof Saml2Authentication,
				"authentication must be of type Saml2Authentication");
		Saml2Authentication saml2Authentication = (Saml2Authentication) authentication;
		RelyingPartyRegistration registration = this.relyingPartyRegistrationResolver.resolve(request,
				saml2Authentication.getRelyingPartyRegistrationId());
		if (registration == null) {
			return null;
		}
		return new OpenSamlLogoutResponsePartial(registration)
				.destination(registration.getAssertingPartyDetails().getSingleLogoutServiceResponseLocation())
				.issuer(registration.getEntityId()).status(StatusCode.SUCCESS);
	}

	/**
	 * A partial application, useful for overriding any aspects of the SAML 2.0 Logout
	 * Response that the resolver supplied.
	 *
	 * The request returned from the {@link #logoutResponse()} method is signed and
	 * serialized.
	 *
	 * This partial is specifically handy for getting access to the underlying
	 * {@link LogoutResponse} to make changes before it gets signed and serialized
	 */
	public static final class OpenSamlLogoutResponsePartial
			implements Saml2LogoutResponsePartial<OpenSamlLogoutResponsePartial> {

		static {
			OpenSamlInitializationService.initialize();
		}

		private final LogoutResponseMarshaller marshaller;

		private final LogoutResponseBuilder logoutResponseBuilder;

		private final IssuerBuilder issuerBuilder;

		private final StatusBuilder statusBuilder;

		private final StatusCodeBuilder statusCodeBuilder;

		private final RelyingPartyRegistration registration;

		private final LogoutResponse logoutResponse;

		/**
		 * Construct a {@link OpenSamlLogoutResponsePartial} using the provided parameters
		 * @param registration the {@link RelyingPartyRegistration} to use
		 */
		public OpenSamlLogoutResponsePartial(RelyingPartyRegistration registration) {
			Assert.notNull(registration, "registration cannot be null");
			this.registration = registration;
			XMLObjectProviderRegistry registry = ConfigurationService.get(XMLObjectProviderRegistry.class);
			this.marshaller = (LogoutResponseMarshaller) registry.getMarshallerFactory()
					.getMarshaller(LogoutResponse.DEFAULT_ELEMENT_NAME);
			Assert.notNull(this.marshaller, "logoutResponseMarshaller must be configured in OpenSAML");
			this.logoutResponseBuilder = (LogoutResponseBuilder) registry.getBuilderFactory()
					.getBuilder(LogoutResponse.DEFAULT_ELEMENT_NAME);
			Assert.notNull(this.logoutResponseBuilder, "logoutResponseBuilder must be configured in OpenSAML");
			this.issuerBuilder = (IssuerBuilder) registry.getBuilderFactory().getBuilder(Issuer.DEFAULT_ELEMENT_NAME);
			Assert.notNull(this.issuerBuilder, "issuerBuilder must be configured in OpenSAML");
			this.statusBuilder = (StatusBuilder) registry.getBuilderFactory().getBuilder(Status.DEFAULT_ELEMENT_NAME);
			Assert.notNull(this.statusBuilder, "statusBuilder must be configured in OpenSAML");
			this.statusCodeBuilder = (StatusCodeBuilder) registry.getBuilderFactory()
					.getBuilder(StatusCode.DEFAULT_ELEMENT_NAME);
			Assert.notNull(this.statusCodeBuilder, "statusCodeBuilder must be configured in OpenSAML");
			this.logoutResponse = this.logoutResponseBuilder.buildObject();
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public OpenSamlLogoutResponsePartial inResponseTo(String inResponseTo) {
			this.logoutResponse.setInResponseTo(inResponseTo);
			return this;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public OpenSamlLogoutResponsePartial status(String status) {
			StatusCode code = this.statusCodeBuilder.buildObject();
			code.setValue(status);
			Status s = this.statusBuilder.buildObject();
			s.setStatusCode(code);
			this.logoutResponse.setStatus(s);
			return this;
		}

		/**
		 * Mutate the {@link LogoutResponse} using the provided {@link Consumer}
		 * @param response the Logout Response {@link Consumer} to use
		 * @return the partial application for further customizations
		 */
		public OpenSamlLogoutResponsePartial logoutResponse(Consumer<LogoutResponse> response) {
			response.accept(this.logoutResponse);
			return this;
		}

		private OpenSamlLogoutResponsePartial destination(String destination) {
			this.logoutResponse.setDestination(destination);
			return this;
		}

		private OpenSamlLogoutResponsePartial issuer(String issuer) {
			Issuer iss = this.issuerBuilder.buildObject();
			iss.setValue(issuer);
			this.logoutResponse.setIssuer(iss);
			return this;
		}

		/**
		 * {@inheritDoc}
		 */
		@Override
		public Saml2LogoutResponse logoutResponse() {
			Saml2LogoutResponse.Builder result = Saml2LogoutResponse.withRelyingPartyRegistration(this.registration);
			if (this.logoutResponse.getID() == null) {
				this.logoutResponse.setID("LR" + UUID.randomUUID());
			}
			if (this.registration.getAssertingPartyDetails()
					.getSingleLogoutServiceBinding() == Saml2MessageBinding.POST) {
				String xml = serialize(OpenSamlSigningUtils.sign(this.logoutResponse, this.registration));
				return result.samlResponse(Saml2Utils.samlEncode(xml.getBytes(StandardCharsets.UTF_8))).build();
			}
			else {
				String xml = serialize(this.logoutResponse);
				String deflatedAndEncoded = Saml2Utils.samlEncode(Saml2Utils.samlDeflate(xml));
				result.samlResponse(deflatedAndEncoded);
				Map<String, String> parameters = OpenSamlSigningUtils.sign(this.registration)
						.param("SAMLResponse", deflatedAndEncoded).parameters();
				return result.parameters((params) -> params.putAll(parameters)).build();
			}
		}

		private String serialize(LogoutResponse logoutResponse) {
			try {
				Element element = this.marshaller.marshall(logoutResponse);
				return SerializeSupport.nodeToString(element);
			}
			catch (MarshallingException ex) {
				throw new Saml2Exception(ex);
			}
		}

	}

}