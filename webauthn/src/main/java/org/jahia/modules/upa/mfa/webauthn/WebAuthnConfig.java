package org.jahia.modules.upa.mfa.webauthn;

import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.Map;
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
 * <p>
 * Properties are self-parsed from the raw map on purpose — an OSGi {@code String[]} property
 * cannot be expressed reliably in a {@code .cfg} file (SCR coerces a comma string to a single
 * bogus element, and indexed {@code key.N} entries are distinct property names that never bind),
 * the same trap as UPA's {@code mfaEnabledFactors}:
 * <ul>
 *   <li>{@code rpId} — the Relying Party ID (default {@code localhost});</li>
 *   <li>{@code rpName} — display name shown by the authenticator (default {@code Jahia});</li>
 *   <li>{@code origins} — comma-separated full origins; indexed {@code origins.N} keys are
 *       accepted too. When NONE are configured, {@link #getOrigins()} derives
 *       <b>both</b> {@code https://<rpId>} and {@code http://<rpId>}: the yubico library
 *       alone would default to https only and reject plain-http localhost deployments at
 *       finish time ("incorrect origin"). Browsers run WebAuthn only in secure contexts, so
 *       an http origin can legitimately reach the server just on localhost-style hosts —
 *       deriving http alongside https is therefore safe.</li>
 * </ul>
 */
@Component(service = WebAuthnConfig.class, immediate = true, configurationPid = "org.jahia.modules.webauthn")
public class WebAuthnConfig {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnConfig.class);

    private static final String DEFAULT_RP_ID = "localhost";
    private static final String DEFAULT_RP_NAME = "Jahia";

    static final String CONFIG_RP_ID = "rpId";
    static final String CONFIG_RP_NAME = "rpName";
    static final String CONFIG_ORIGINS = "origins";

    // Each holds an immutable value, swapped atomically on (re)configuration — avoids a
    // volatile reference to a mutable collection (java:S3077).
    private final AtomicReference<String> rpId = new AtomicReference<>(DEFAULT_RP_ID);
    private final AtomicReference<String> rpName = new AtomicReference<>(DEFAULT_RP_NAME);
    private final AtomicReference<Set<String>> origins =
            new AtomicReference<>(deriveOrigins(DEFAULT_RP_ID));

    @Activate
    @Modified
    public void activate(Map<String, Object> properties) {
        String id = stringProperty(properties, CONFIG_RP_ID, DEFAULT_RP_ID);
        String name = stringProperty(properties, CONFIG_RP_NAME, DEFAULT_RP_NAME);
        Set<String> parsed = parseOrigins(properties);
        Set<String> effective = parsed.isEmpty() ? deriveOrigins(id) : parsed;
        rpId.set(id);
        rpName.set(name);
        origins.set(effective);
        logger.info("WebAuthn factor configured (rpId={}, rpName={}, origins={})", id, name, effective);
    }

    private static String stringProperty(Map<String, Object> properties, String key, String fallback) {
        Object raw = properties == null ? null : properties.get(key);
        return StringUtils.defaultIfBlank(raw == null ? null : raw.toString(), fallback).trim();
    }

    /**
     * Collect allowed origins from a comma-separated {@code origins} value AND any indexed
     * {@code origins.N} keys (operators use either form in {@code .cfg} files). Trimmed,
     * deduped, order preserved; empty when nothing is configured.
     */
    static Set<String> parseOrigins(Map<String, Object> properties) {
        Set<String> parsed = new LinkedHashSet<>();
        if (properties == null) {
            return Collections.unmodifiableSet(parsed);
        }
        addSplit(parsed, properties.get(CONFIG_ORIGINS));
        properties.keySet().stream()
                .filter(key -> key.startsWith(CONFIG_ORIGINS + "."))
                .sorted()
                .forEach(key -> addSplit(parsed, properties.get(key)));
        return Collections.unmodifiableSet(parsed);
    }

    private static void addSplit(Set<String> target, Object raw) {
        if (raw == null || StringUtils.isBlank(raw.toString())) {
            return;
        }
        for (String part : raw.toString().split(",")) {
            String origin = part.trim();
            if (!origin.isEmpty()) {
                target.add(origin);
            }
        }
    }

    /** Origins derived from the RP ID when none are configured: https first, http for localhost-style dev. */
    static Set<String> deriveOrigins(String rpId) {
        Set<String> derived = new LinkedHashSet<>();
        derived.add("https://" + rpId);
        derived.add("http://" + rpId);
        return Collections.unmodifiableSet(derived);
    }

    public String getRpId() {
        return rpId.get();
    }

    public String getRpName() {
        return rpName.get();
    }

    /** Allowed origins (immutable, never empty): as configured, or derived from the RP ID. */
    public Set<String> getOrigins() {
        return origins.get();
    }
}
