package org.jahia.modules.upa.mfa.webauthn;

import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.metatype.annotations.AttributeDefinition;
import org.osgi.service.metatype.annotations.Designate;
import org.osgi.service.metatype.annotations.ObjectClassDefinition;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Set;
import java.util.concurrent.atomic.AtomicReference;

/**
 * Relying-Party configuration for the WebAuthn factor (PID {@code org.jahia.modules.webauthn}).
 * <p>
 * WebAuthn ceremonies are bound to a <b>Relying Party ID</b> (an effective domain, e.g.
 * {@code localhost} or {@code example.com}) and validated against a set of allowed
 * <b>origins</b> (scheme + host + port). These MUST match the domain the browser is actually
 * on; WebAuthn additionally requires a secure context (HTTPS) except on {@code localhost}.
 * Hot-reloaded via {@code @Modified} so an operator can adjust them without a restart.
 */
@Component(service = WebAuthnConfig.class, immediate = true, configurationPid = "org.jahia.modules.webauthn")
@Designate(ocd = WebAuthnConfig.Config.class)
public class WebAuthnConfig {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnConfig.class);

    private static final String DEFAULT_RP_ID = "localhost";
    private static final String DEFAULT_RP_NAME = "Jahia";

    @ObjectClassDefinition(name = "MFA WebAuthn factor")
    public @interface Config {
        @AttributeDefinition(name = "Relying Party ID",
                description = "Effective domain the credentials are scoped to (e.g. localhost or example.com). "
                        + "Must be a registrable suffix of the browsing origin's host.")
        String rpId() default "localhost";

        @AttributeDefinition(name = "Relying Party display name",
                description = "Human-readable site name shown by the authenticator during registration.")
        String rpName() default "Jahia";

        @AttributeDefinition(name = "Allowed origins",
                description = "Full origins (scheme://host[:port]) permitted in ceremonies, e.g. "
                        + "https://example.com. Leave empty to let the library derive it from the RP ID.")
        String[] origins() default {};
    }

    // Each holds an immutable value, swapped atomically on (re)configuration — avoids a
    // volatile reference to a mutable collection (java:S3077).
    private final AtomicReference<String> rpId = new AtomicReference<>(DEFAULT_RP_ID);
    private final AtomicReference<String> rpName = new AtomicReference<>(DEFAULT_RP_NAME);
    private final AtomicReference<Set<String>> origins = new AtomicReference<>(Collections.emptySet());

    @Activate
    @Modified
    public void activate(Config config) {
        rpId.set(StringUtils.defaultIfBlank(config.rpId(), DEFAULT_RP_ID).trim());
        rpName.set(StringUtils.defaultIfBlank(config.rpName(), DEFAULT_RP_NAME).trim());
        Set<String> parsed = new LinkedHashSet<>();
        if (config.origins() != null) {
            for (String origin : config.origins()) {
                String trimmed = StringUtils.trimToNull(origin);
                if (trimmed != null) {
                    parsed.add(trimmed);
                }
            }
        }
        Set<String> immutableOrigins = Collections.unmodifiableSet(parsed);
        origins.set(immutableOrigins);
        logger.info("WebAuthn factor configured (rpId={}, rpName={}, origins={})",
                rpId.get(), rpName.get(), immutableOrigins);
    }

    public String getRpId() {
        return rpId.get();
    }

    public String getRpName() {
        return rpName.get();
    }

    /** Allowed origins (immutable); empty means "derive from the RP ID". */
    public Set<String> getOrigins() {
        return origins.get();
    }
}
