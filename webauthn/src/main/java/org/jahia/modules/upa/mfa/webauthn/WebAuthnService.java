package org.jahia.modules.upa.mfa.webauthn;

import com.yubico.webauthn.AssertionRequest;
import com.yubico.webauthn.AssertionResult;
import com.yubico.webauthn.FinishAssertionOptions;
import com.yubico.webauthn.FinishRegistrationOptions;
import com.yubico.webauthn.RegistrationResult;
import com.yubico.webauthn.RelyingParty;
import com.yubico.webauthn.StartAssertionOptions;
import com.yubico.webauthn.StartRegistrationOptions;
import com.yubico.webauthn.data.AuthenticatorSelectionCriteria;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredential;
import com.yubico.webauthn.data.PublicKeyCredentialCreationOptions;
import com.yubico.webauthn.data.RelyingPartyIdentity;
import com.yubico.webauthn.data.UserIdentity;
import com.yubico.webauthn.data.UserVerificationRequirement;
import com.yubico.webauthn.exception.AssertionFailedException;
import com.yubico.webauthn.exception.RegistrationFailedException;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Drives the WebAuthn ceremonies via the yubico {@link RelyingParty}. The relying party is
 * rebuilt from the (hot-reloadable) {@link WebAuthnConfig} on each call — construction is cheap
 * — using {@link WebAuthnCredentialStore} as the credential repository.
 * <p>
 * Ceremony state (the {@code AssertionRequest} / {@code PublicKeyCredentialCreationOptions}
 * carrying the server challenge) is serialized to JSON so callers can stash it in the MFA / HTTP
 * session between the {@code start} and {@code finish} GraphQL calls; the client-facing options
 * JSON is produced separately via the {@code toCredentials*Json()} helpers.
 */
@Component(service = WebAuthnService.class, immediate = true)
public class WebAuthnService {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnService.class);

    private WebAuthnConfig config;
    private WebAuthnCredentialStore credentialStore;

    @Reference
    public void setConfig(WebAuthnConfig config) {
        this.config = config;
    }

    @Reference
    public void setCredentialStore(WebAuthnCredentialStore credentialStore) {
        this.credentialStore = credentialStore;
    }

    private RelyingParty relyingParty() {
        RelyingPartyIdentity identity = RelyingPartyIdentity.builder()
                .id(config.getRpId())
                .name(config.getRpName())
                .build();
        // Origins are ALWAYS set explicitly: WebAuthnConfig derives {https,http}://<rpId> when
        // none are configured — the library default would be https-only and reject plain-http
        // localhost deployments at finish time ("incorrect origin").
        return RelyingParty.builder()
                .identity(identity)
                .credentialRepository(credentialStore)
                .allowOriginPort(true)
                .origins(config.getOrigins())
                .build();
    }

    // --- Registration (dashboard self-service, while authenticated) ----------------------

    /** Outcome of {@link #startRegistration}: state to persist + the client create-options JSON. */
    public static final class RegistrationCeremony {
        private final String requestJson;
        private final String clientOptionsJson;

        RegistrationCeremony(String requestJson, String clientOptionsJson) {
            this.requestJson = requestJson;
            this.clientOptionsJson = clientOptionsJson;
        }

        public String getRequestJson()       { return requestJson; }
        public String getClientOptionsJson() { return clientOptionsJson; }
    }

    public RegistrationCeremony startRegistration(String username, String displayName, ByteArray userHandle)
            throws IOException {
        PublicKeyCredentialCreationOptions options = relyingParty().startRegistration(
                StartRegistrationOptions.builder()
                        .user(UserIdentity.builder()
                                .name(username)
                                .displayName(displayName == null ? username : displayName)
                                .id(userHandle)
                                .build())
                        .authenticatorSelection(AuthenticatorSelectionCriteria.builder()
                                .userVerification(UserVerificationRequirement.PREFERRED)
                                .build())
                        .build());
        return new RegistrationCeremony(options.toJson(), options.toCredentialsCreateJson());
    }

    /** Outcome of {@link #finishRegistration}: the data to persist as a stored credential. */
    public static final class RegistrationOutcome {
        private final String credentialIdB64;
        private final String publicKeyCoseB64;
        private final long signCount;
        private final List<String> transports;
        private final String aaguidB64;

        RegistrationOutcome(String credentialIdB64, String publicKeyCoseB64, long signCount,
                            List<String> transports, String aaguidB64) {
            this.credentialIdB64 = credentialIdB64;
            this.publicKeyCoseB64 = publicKeyCoseB64;
            this.signCount = signCount;
            this.transports = transports;
            this.aaguidB64 = aaguidB64;
        }

        public String getCredentialIdB64()  { return credentialIdB64; }
        public String getPublicKeyCoseB64() { return publicKeyCoseB64; }
        public long getSignCount()          { return signCount; }
        public List<String> getTransports() { return transports; }
        public String getAaguidB64()        { return aaguidB64; }
    }

    public RegistrationOutcome finishRegistration(String requestJson, String responseJson)
            throws IOException, RegistrationFailedException {
        PublicKeyCredentialCreationOptions request = PublicKeyCredentialCreationOptions.fromJson(requestJson);
        RegistrationResult result = relyingParty().finishRegistration(FinishRegistrationOptions.builder()
                .request(request)
                .response(PublicKeyCredential.parseRegistrationResponseJson(responseJson))
                .build());
        List<String> transports = new ArrayList<>();
        result.getKeyId().getTransports().ifPresent(set ->
                transports.addAll(set.stream().map(t -> t.getId()).collect(Collectors.toList())));
        String aaguid = result.getAaguid() == null ? null : result.getAaguid().getBase64Url();
        return new RegistrationOutcome(
                result.getKeyId().getId().getBase64Url(),
                result.getPublicKeyCose().getBase64Url(),
                result.getSignatureCount(),
                transports,
                aaguid);
    }

    // --- Assertion (login-time second factor) --------------------------------------------

    /** Outcome of {@link #startAssertion}: state to persist + the client get-options JSON. */
    public static final class AssertionCeremony {
        private final String requestJson;
        private final String clientOptionsJson;

        AssertionCeremony(String requestJson, String clientOptionsJson) {
            this.requestJson = requestJson;
            this.clientOptionsJson = clientOptionsJson;
        }

        public String getRequestJson()       { return requestJson; }
        public String getClientOptionsJson() { return clientOptionsJson; }
    }

    public AssertionCeremony startAssertion(String username) throws IOException {
        AssertionRequest request = relyingParty().startAssertion(StartAssertionOptions.builder()
                .username(username)
                .userVerification(UserVerificationRequirement.PREFERRED)
                .build());
        return new AssertionCeremony(request.toJson(), request.toCredentialsGetJson());
    }

    /** Outcome of {@link #finishAssertion}. */
    public static final class AssertionOutcome {
        private final boolean success;
        private final String credentialIdB64;
        private final long newSignCount;

        AssertionOutcome(boolean success, String credentialIdB64, long newSignCount) {
            this.success = success;
            this.credentialIdB64 = credentialIdB64;
            this.newSignCount = newSignCount;
        }

        public boolean isSuccess()          { return success; }
        public String getCredentialIdB64()  { return credentialIdB64; }
        public long getNewSignCount()       { return newSignCount; }
    }

    public AssertionOutcome finishAssertion(String requestJson, String responseJson) throws IOException {
        AssertionRequest request = AssertionRequest.fromJson(requestJson);
        try {
            AssertionResult result = relyingParty().finishAssertion(FinishAssertionOptions.builder()
                    .request(request)
                    .response(PublicKeyCredential.parseAssertionResponseJson(responseJson))
                    .build());
            if (!result.isSuccess()) {
                return new AssertionOutcome(false, null, 0L);
            }
            // getCredential() (not the deprecated getCredentialId()/getSignatureCount() on the result).
            return new AssertionOutcome(true,
                    result.getCredential().getCredentialId().getBase64Url(),
                    result.getSignatureCount());
        } catch (AssertionFailedException e) {
            logger.debug("WebAuthn assertion failed: {}", e.getMessage());
            return new AssertionOutcome(false, null, 0L);
        }
    }
}
