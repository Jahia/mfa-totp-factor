package org.jahia.modules.upa.mfa.extensions;

import org.apache.commons.lang3.StringUtils;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

/**
 * The global MFA enrollment policy shared by every factor (TOTP, WebAuthn, ...).
 * <p>
 * Enforcement used to be a per-site flag on each factor; it is now ONE platform-wide setting:
 * {@code enforcedFactors} lists the factor types a user may satisfy enforcement with — a user must
 * have <b>at least one</b> of them configured and verify one of them at sign-in. An empty list
 * (the default) means no enforcement: factors stay opt-in per site and never block a user who has
 * not set them up. {@code graceDays} is the global window during which a user with none of the
 * enforced factors configured may still sign in (per-user start is tracked by each factor's
 * existing grace plumbing).
 * <p>
 * Configuration (PID {@code org.jahia.modules.mfa.extensions}, hot-reloaded via {@code @Modified}):
 * <ul>
 *   <li>{@code enforcedFactors} — comma-separated factor types (e.g. {@code totp,webauthn}).
 *       Parsed by this class as a plain string on purpose: an OSGi {@code String[]} property
 *       cannot be expressed reliably in a {@code .cfg} file (SCR coerces a comma string to a
 *       single bogus element), so we own the splitting.</li>
 *   <li>{@code graceDays} — long, clamped to {@code [0, 365]}; default {@code 0} (immediate).</li>
 * </ul>
 */
@Component(service = MfaGlobalPolicy.class, immediate = true,
        configurationPid = "org.jahia.modules.mfa.extensions")
public class MfaGlobalPolicy {

    private static final Logger logger = LoggerFactory.getLogger(MfaGlobalPolicy.class);

    static final String CONFIG_ENFORCED_FACTORS = "enforcedFactors";
    static final String CONFIG_GRACE_DAYS = "graceDays";

    /** Upper bound for the grace window — an unbounded value would disable enforcement forever. */
    public static final long MAX_GRACE_DAYS = 365L;

    private final AtomicReference<List<String>> enforcedFactors =
            new AtomicReference<>(Collections.emptyList());
    private final AtomicLong graceDays = new AtomicLong(0L);

    @Activate
    @Modified
    public void activate(Map<String, Object> properties) {
        List<String> factors = parseEnforcedFactors(
                properties == null ? null : properties.get(CONFIG_ENFORCED_FACTORS));
        long grace = parseGraceDays(properties == null ? null : properties.get(CONFIG_GRACE_DAYS));
        enforcedFactors.set(factors);
        graceDays.set(grace);
        logger.info("MFA global policy {} (enforcedFactors={}, graceDays={})",
                factors.isEmpty() ? "INACTIVE" : "ACTIVE", factors, grace);
    }

    /** Parse the comma-separated factor list: trimmed, lowercased, deduped, order preserved. */
    static List<String> parseEnforcedFactors(Object raw) {
        if (raw == null || StringUtils.isBlank(raw.toString())) {
            return Collections.emptyList();
        }
        Set<String> factors = new LinkedHashSet<>();
        for (String part : raw.toString().split(",")) {
            String factor = part.trim().toLowerCase(Locale.ROOT);
            if (!factor.isEmpty()) {
                factors.add(factor);
            }
        }
        return Collections.unmodifiableList(new ArrayList<>(factors));
    }

    /** Parse the grace window, clamped to {@code [0, MAX_GRACE_DAYS]}; malformed values mean 0. */
    static long parseGraceDays(Object raw) {
        if (raw == null || StringUtils.isBlank(raw.toString())) {
            return 0L;
        }
        try {
            long parsed = Long.parseLong(raw.toString().trim());
            return Math.min(Math.max(0L, parsed), MAX_GRACE_DAYS);
        } catch (NumberFormatException e) {
            logger.warn("Ignoring invalid {} value: '{}' (expected a number of days)",
                    CONFIG_GRACE_DAYS, raw);
            return 0L;
        }
    }

    /** The enforced factor types (lowercased, deduped); empty = enforcement OFF. */
    public List<String> getEnforcedFactors() {
        return enforcedFactors.get();
    }

    /** Whether the given factor type is part of the global enforcement policy. */
    public boolean isEnforced(String factorType) {
        return factorType != null
                && enforcedFactors.get().contains(factorType.toLowerCase(Locale.ROOT));
    }

    /** Whether any factor is enforced at all. */
    public boolean isEnforcementActive() {
        return !enforcedFactors.get().isEmpty();
    }

    /** The global grace window in days, clamped to {@code [0, 365]}. */
    public long getGraceDays() {
        return graceDays.get();
    }
}
