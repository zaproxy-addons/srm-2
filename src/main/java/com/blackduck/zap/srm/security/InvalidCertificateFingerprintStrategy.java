/*
 * Zed Attack Proxy (ZAP) and its related class files.
 *
 * ZAP is an HTTP/HTTPS proxy for assessing web application security.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.blackduck.zap.srm.security;

import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

public class InvalidCertificateFingerprintStrategy implements InvalidCertificateStrategy {

	private final String fingerprint;
	private final boolean acceptPermanently;

	public InvalidCertificateFingerprintStrategy(String fingerprint, boolean acceptPermanently) {
		this.fingerprint = fingerprint.replaceAll("\\s", "");
		this.acceptPermanently = acceptPermanently;
	}

	@Override
	public CertificateAcceptance checkAcceptance(Certificate cert, CertificateException certError) {
		try {
			byte[] encoded = InvalidCertificateDialogStrategy.getSHA1(cert.getEncoded());
			String obsPrint = InvalidCertificateDialogStrategy.toHexString(encoded, "");
			if (obsPrint.equalsIgnoreCase(fingerprint)) {
				if (acceptPermanently) return CertificateAcceptance.ACCEPT_PERMANENTLY;
				else return CertificateAcceptance.ACCEPT_TEMPORARILY;
			} else {
				return CertificateAcceptance.REJECT;
			}
		} catch (CertificateEncodingException e) {
			return CertificateAcceptance.REJECT;
		}
	}
}
