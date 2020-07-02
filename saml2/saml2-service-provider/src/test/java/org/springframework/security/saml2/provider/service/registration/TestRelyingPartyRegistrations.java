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

package org.springframework.security.saml2.provider.service.registration;

import org.springframework.security.saml2.credentials.Saml2X509Credential;
import org.springframework.security.saml2.provider.service.servlet.filter.Saml2WebSsoAuthenticationFilter;

import static org.springframework.security.saml2.credentials.TestSaml2X509Credentials.relyingPartySigningCredential;
import static org.springframework.security.saml2.credentials.TestSaml2X509Credentials.relyingPartyVerifyingCredential;

/**
 * Preconfigured test data for {@link RelyingPartyRegistration} objects
 */
public class TestRelyingPartyRegistrations {

	public static RelyingPartyRegistration.Builder relyingPartyRegistration() {
		String registrationId = "simplesamlphp";

		String rpEntityId = "{baseUrl}/saml2/service-provider-metadata/{registrationId}";
		Saml2X509Credential signingCredential = relyingPartySigningCredential();
		String assertionConsumerServiceLocation = "{baseUrl}" + Saml2WebSsoAuthenticationFilter.DEFAULT_FILTER_PROCESSES_URI;

		String apEntityId = "https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/metadata.php";
		Saml2X509Credential verificationCertificate = relyingPartyVerifyingCredential();
		String singleSignOnServiceLocation = "https://simplesaml-for-spring-saml.cfapps.io/saml2/idp/SSOService.php";

		return RelyingPartyRegistration.withRegistrationId(registrationId)
				.entityId(rpEntityId)
				.signingX509Credentials(c -> c.add(signingCredential))
				.assertionConsumerServiceLocation(assertionConsumerServiceLocation)
				.providerDetails(assertingParty -> assertingParty
						.entityId(apEntityId)
						.verificationX509Credentials(c -> c.add(verificationCertificate))
						.singleSignOnServiceLocation(singleSignOnServiceLocation)
				);
	}


}
