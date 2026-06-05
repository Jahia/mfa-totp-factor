package org.jahia.modules.upa.mfa.totp;

import java.io.Serializable;

/**
 * Transient enrollment state held in the {@code MfaFactorState.preparationResult} slot
 * between {@code enroll} and {@code confirmEnroll}. Holds the freshly-generated secret
 * (Base32) that has NOT yet been persisted on the user node.
 * <p>
 * Once confirmEnroll succeeds the holding {@code MfaFactorState} is cleared so the
 * secret no longer lingers in the HTTP session. To bound exposure if the user simply
 * abandons the flow (e.g. closes the tab), the state carries a creation timestamp
 * and is considered expired after {@link #TTL_MILLIS}; callers must call
 * {@link #isExpired()} before honouring it.
 */
public class TotpEnrollmentState implements Serializable {
    private static final long serialVersionUID = 2L;

    /** Maximum lifetime of an unconfirmed enrollment state in the HTTP session: 5 minutes. */
    public static final long TTL_MILLIS = 5L * 60L * 1000L;

    private final String secretBase32;
    private final long createdAtMillis;

    public TotpEnrollmentState(String secretBase32) {
        this(secretBase32, System.currentTimeMillis());
    }

    TotpEnrollmentState(String secretBase32, long createdAtMillis) {
        this.secretBase32 = secretBase32;
        this.createdAtMillis = createdAtMillis;
    }

    public String getSecretBase32() {
        return secretBase32;
    }

    public long getCreatedAtMillis() {
        return createdAtMillis;
    }

    public boolean isExpired() {
        return (System.currentTimeMillis() - createdAtMillis) > TTL_MILLIS;
    }
}
