package org.jahia.modules.upa.mfa.webauthn;

import org.jahia.modules.upa.mfa.MfaException;
import org.jahia.modules.upa.mfa.MfaFactorProvider;
import org.jahia.modules.upa.mfa.PreparationContext;
import org.jahia.modules.upa.mfa.VerificationContext;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Serializable;

/**
 * STUB — phishing-resistant WebAuthn / FIDO2 factor.
 * <p>
 * This is a non-functional skeleton reserving the {@code webauthn} factor type. It is
 * intentionally inert: both {@link #prepare} and {@link #verify} throw
 * {@code factor.webauthn.not_implemented}, so even if an operator mistakenly adds
 * {@code webauthn} to {@code mfaEnabledFactors} it cannot silently grant access.
 * <p>
 * To complete it:
 * <ul>
 *   <li>{@code prepare} → build {@code PublicKeyCredentialCreationOptions} (registration) or
 *       {@code PublicKeyCredentialRequestOptions} (authentication) with a fresh challenge, and
 *       return it for the browser {@code navigator.credentials} ceremony;</li>
 *   <li>{@code verify} → validate the authenticator attestation/assertion (signature, origin
 *       binding, challenge match, and the signature counter for clone detection);</li>
 *   <li>persist credential ids / public keys per user (a {@code upaWebAuthn:credential} mixin),
 *       mirroring {@code TotpUserStore}.</li>
 * </ul>
 * Unlike TOTP, WebAuthn assertions are origin-bound and therefore resistant to real-time
 * phishing — which is why it belongs in the roadmap as its own factor.
 */
@Component(service = MfaFactorProvider.class, immediate = true)
public class WebAuthnFactorProvider implements MfaFactorProvider {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnFactorProvider.class);

    public static final String FACTOR_TYPE = "webauthn";
    private static final String ERROR_NOT_IMPLEMENTED = "factor.webauthn.not_implemented";

    @Override
    public String getFactorType() {
        return FACTOR_TYPE;
    }

    @Override
    public Serializable prepare(PreparationContext preparationContext) throws MfaException {
        logger.warn("WebAuthn factor is a stub and not yet implemented (prepare called)");
        throw new MfaException(ERROR_NOT_IMPLEMENTED);
    }

    @Override
    public boolean verify(VerificationContext verificationContext) throws MfaException {
        logger.warn("WebAuthn factor is a stub and not yet implemented (verify called)");
        throw new MfaException(ERROR_NOT_IMPLEMENTED);
    }
}
