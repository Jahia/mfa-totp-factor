package org.jahia.modules.upa.mfa.totp;

import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRTemplate;
import org.jahia.services.content.decorator.JCRUserNode;
import org.jahia.services.usermanager.JahiaGroupManagerService;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Reference;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.Node;
import javax.jcr.NodeIterator;
import javax.jcr.RepositoryException;
import javax.jcr.Value;
import javax.jcr.query.Query;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;

/**
 * Reads and writes the {@code upaTotp:userSettings} mixin on user nodes via a JCR system session.
 * <p>
 * Centralizes all JCR access for the TOTP factor — providers and mutations never touch JCR
 * directly. All writes go through a system session so {@code protected} properties can be
 * modified by the module itself.
 */
@Component(service = TotpUserStore.class, immediate = true)
public class TotpUserStore {

    private static final Logger logger = LoggerFactory.getLogger(TotpUserStore.class);

    public static final String MIXIN_USER_SETTINGS = "upaTotp:userSettings";
    public static final String PROP_SECRET = "upaTotp:secret";
    public static final String PROP_ENROLLED = "upaTotp:enrolled";
    public static final String PROP_LAST_USED_COUNTER = "upaTotp:lastUsedCounter";
    public static final String PROP_BACKUP_CODES = "upaTotp:backupCodes";

    public static final String MIXIN_GRACE_TRACKING = "upaTotp:graceTracking";
    public static final String PROP_GRACE_STARTED_AT = "upaTotp:graceStartedAt";

    private JahiaUserManagerService userManagerService;
    private JahiaGroupManagerService groupManagerService;
    private TotpSecretCipher secretCipher;

    @Reference
    public void setUserManagerService(JahiaUserManagerService userManagerService) {
        this.userManagerService = userManagerService;
    }

    @Reference
    public void setGroupManagerService(JahiaGroupManagerService groupManagerService) {
        this.groupManagerService = groupManagerService;
    }

    @Reference
    public void setSecretCipher(TotpSecretCipher secretCipher) {
        this.secretCipher = secretCipher;
    }

    /**
     * Whether the user belongs to at least one of the given group names (matched on the last
     * path segment of their group membership). An empty/null {@code groupNames} means
     * "no group restriction" and returns {@code true}.
     */
    public boolean isMemberOfAnyGroup(String userId, java.util.Collection<String> groupNames) throws RepositoryException {
        if (groupNames == null || groupNames.isEmpty()) {
            return true;
        }
        return Boolean.TRUE.equals(JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            JCRUserNode user = userManagerService.lookupUser(userId, session);
            if (user == null) {
                return false;
            }
            List<String> membership = groupManagerService.getMembershipByPath(user.getPath());
            if (membership == null) {
                return false;
            }
            for (String groupPath : membership) {
                String name = org.apache.commons.lang3.StringUtils.substringAfterLast(groupPath, "/");
                if (groupNames.contains(name)) {
                    return true;
                }
            }
            return false;
        }));
    }

    /**
     * Snapshot of the stored TOTP user settings.
     */
    public static class TotpUserSettings {
        private final boolean enrolled;
        private final String secretBase32;
        private final long lastUsedCounter;
        private final List<String> backupCodeHashes;

        public TotpUserSettings(boolean enrolled, String secretBase32, long lastUsedCounter,
                                List<String> backupCodeHashes) {
            this.enrolled = enrolled;
            this.secretBase32 = secretBase32;
            this.lastUsedCounter = lastUsedCounter;
            this.backupCodeHashes = backupCodeHashes == null
                    ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(backupCodeHashes));
        }

        public boolean isEnrolled() { return enrolled; }
        public String getSecretBase32() { return secretBase32; }
        public long getLastUsedCounter() { return lastUsedCounter; }
        public List<String> getBackupCodeHashes() { return backupCodeHashes; }
    }

    /**
     * Lightweight check that the user is enrolled in TOTP. Reads only the enrolled flag and
     * never loads the secret into the heap.
     */
    public boolean isEnrolled(String userId) throws RepositoryException {
        return Boolean.TRUE.equals(JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user == null || !user.isNodeType(MIXIN_USER_SETTINGS)) {
                return false;
            }
            return user.hasProperty(PROP_ENROLLED) && user.getProperty(PROP_ENROLLED).getBoolean();
        }));
    }

    /**
     * Load the user's TOTP settings or return an empty (not-enrolled) snapshot.
     */
    public TotpUserSettings load(String userId) throws RepositoryException {
        return JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user == null || !user.isNodeType(MIXIN_USER_SETTINGS)) {
                return new TotpUserSettings(false, null, 0L, Collections.emptyList());
            }
            boolean enrolled = user.hasProperty(PROP_ENROLLED) && user.getProperty(PROP_ENROLLED).getBoolean();
            String secret = user.hasProperty(PROP_SECRET)
                    ? secretCipher.decrypt(user.getProperty(PROP_SECRET).getString()) : null;
            long counter = user.hasProperty(PROP_LAST_USED_COUNTER) ? user.getProperty(PROP_LAST_USED_COUNTER).getLong() : 0L;
            List<String> hashes = new ArrayList<>();
            if (user.hasProperty(PROP_BACKUP_CODES)) {
                Value[] values = user.getProperty(PROP_BACKUP_CODES).getValues();
                for (Value v : values) {
                    hashes.add(v.getString());
                }
            }
            return new TotpUserSettings(enrolled, secret, counter, hashes);
        });
    }

    /**
     * Persist a freshly-confirmed enrollment in a SINGLE JCR transaction: applies the mixin
     * if missing, sets secret, marks enrolled, stores backup-code hashes, AND sets
     * {@code lastUsedCounter} to the matched counter so the very code used to confirm
     * enrollment cannot be replayed at login.
     */
    public void saveEnrollment(String userId, String secretBase32, List<String> backupCodeHashes,
                               long matchedCounter) throws RepositoryException {
        JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user == null) {
                throw new RepositoryException("User not found: " + userId);
            }
            ensureMixin(user);
            user.setProperty(PROP_SECRET, secretCipher.encrypt(secretBase32));
            user.setProperty(PROP_ENROLLED, true);
            user.setProperty(PROP_LAST_USED_COUNTER, matchedCounter);
            user.setProperty(PROP_BACKUP_CODES, backupCodeHashes.toArray(new String[0]));
            systemSession.save();
            logger.info("TOTP enrollment persisted for user {}", user.getName());
            return null;
        });
    }

    /**
     * Atomically verify a submitted TOTP code AND consume the matched counter in a SINGLE
     * JCR transaction. This is the chokepoint used by both the login-time verify path
     * ({@link TotpFactorProvider}) and the management mutations ({@code TotpFactorMutation}).
     * <p>
     * Reads {@code lastUsedCounter} and the secret from the (system) session, runs the
     * code through {@link TotpService#verifyCode}, and on success persists the matched
     * counter in the same transaction — guaranteeing that the same code cannot be replayed
     * by a concurrent / subsequent call.
     *
     * @return the matched counter on success, empty on rejection (no match, replay,
     *         or not enrolled)
     */
    public Optional<Long> verifyAndConsumeTotp(String userId, TotpService totpService,
                                               String submittedCode, long nowSeconds,
                                               int driftWindows) throws RepositoryException {
        return JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user == null || !user.isNodeType(MIXIN_USER_SETTINGS)) {
                return Optional.<Long>empty();
            }
            boolean enrolled = user.hasProperty(PROP_ENROLLED) && user.getProperty(PROP_ENROLLED).getBoolean();
            if (!enrolled || !user.hasProperty(PROP_SECRET)) {
                return Optional.<Long>empty();
            }
            String storedSecret = user.getProperty(PROP_SECRET).getString();
            String secretBase32 = secretCipher.decrypt(storedSecret);
            long lastUsed = user.hasProperty(PROP_LAST_USED_COUNTER)
                    ? user.getProperty(PROP_LAST_USED_COUNTER).getLong() : 0L;
            byte[] secret = totpService.fromBase32(secretBase32);
            Optional<Long> matched = totpService.verifyCode(secret, submittedCode, nowSeconds,
                    lastUsed, driftWindows);
            if (!matched.isPresent()) {
                return Optional.<Long>empty();
            }
            // Persist the consumed counter atomically before returning success.
            user.setProperty(PROP_LAST_USED_COUNTER, matched.get());
            // Lazy migration: re-encrypt a legacy plaintext secret on a successful verify.
            if (!secretCipher.isEncrypted(storedSecret)) {
                user.setProperty(PROP_SECRET, secretCipher.encrypt(secretBase32));
            }
            systemSession.save();
            return matched;
        });
    }

    /**
     * Return the epoch-millis at which the enrollment grace window started for this user,
     * initializing it to {@code nowMillis} on first call (when an enforcing site first
     * prompts a not-yet-enrolled user). Used by {@link TotpFactorProvider} to decide whether
     * a grace period is still running.
     */
    public long getOrStartGraceMillis(String userId, long nowMillis) throws RepositoryException {
        Long result = JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user == null) {
                return nowMillis;
            }
            if (user.isNodeType(MIXIN_GRACE_TRACKING) && user.hasProperty(PROP_GRACE_STARTED_AT)
                    && user.getProperty(PROP_GRACE_STARTED_AT).getLong() > 0L) {
                return user.getProperty(PROP_GRACE_STARTED_AT).getLong();
            }
            if (!user.isNodeType(MIXIN_GRACE_TRACKING)) {
                user.addMixin(MIXIN_GRACE_TRACKING);
            }
            user.setProperty(PROP_GRACE_STARTED_AT, nowMillis);
            systemSession.save();
            return nowMillis;
        });
        return result == null ? nowMillis : result;
    }

    /** Aggregate enrollment report for the admin "who hasn't enrolled?" view. */
    public static final class EnrollmentReport {
        private final long totalUsers;
        private final long enrolledUsers;
        private final List<String> notEnrolled;
        private final boolean truncated;

        public EnrollmentReport(long totalUsers, long enrolledUsers, List<String> notEnrolled, boolean truncated) {
            this.totalUsers = totalUsers;
            this.enrolledUsers = enrolledUsers;
            this.notEnrolled = Collections.unmodifiableList(new ArrayList<>(notEnrolled));
            this.truncated = truncated;
        }

        public long getTotalUsers()    { return totalUsers; }
        public long getEnrolledUsers() { return enrolledUsers; }
        public List<String> getNotEnrolled() { return notEnrolled; }
        public boolean isTruncated()   { return truncated; }
    }

    /** Maximum jnt:user nodes scanned when building the enrollment report. */
    private static final int REPORT_SCAN_CAP = 5000;

    /**
     * Build the enrollment report: total users scanned, how many are enrolled in TOTP, and a
     * capped list of users who are not. Enrollment is global (one secret per user), so the
     * report is global; it is gated by a site-admin permission check in the GraphQL layer.
     */
    public EnrollmentReport buildEnrollmentReport(int listLimit) throws RepositoryException {
        int listCap = Math.max(1, Math.min(listLimit, 1000));
        return JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            // Names of users currently enrolled (the mixin sits on the jnt:user node).
            Set<String> enrolled = new HashSet<>();
            Query enrolledQuery = session.getWorkspace().getQueryManager().createQuery(
                    "SELECT * FROM [" + MIXIN_USER_SETTINGS + "] WHERE [" + PROP_ENROLLED + "] = true",
                    Query.JCR_SQL2);
            NodeIterator enrolledIt = enrolledQuery.execute().getNodes();
            while (enrolledIt.hasNext()) {
                enrolled.add(enrolledIt.nextNode().getName());
            }

            // Scan users, classify, collect a capped list of the not-enrolled.
            Query usersQuery = session.getWorkspace().getQueryManager().createQuery(
                    "SELECT * FROM [jnt:user]", Query.JCR_SQL2);
            usersQuery.setLimit(REPORT_SCAN_CAP);
            NodeIterator usersIt = usersQuery.execute().getNodes();
            long total = 0;
            List<String> notEnrolled = new ArrayList<>();
            boolean truncated = false;
            while (usersIt.hasNext()) {
                Node u = usersIt.nextNode();
                String name = u.getName();
                if ("guest".equals(name)) {
                    continue; // never an MFA subject
                }
                total++;
                if (!enrolled.contains(name)) {
                    if (notEnrolled.size() < listCap) {
                        notEnrolled.add(name);
                    } else {
                        truncated = true;
                    }
                }
            }
            return new EnrollmentReport(total, enrolled.size(), notEnrolled, truncated);
        });
    }

    /** Clear any grace-period tracking for the user (called once they enroll or are reset). */
    public void clearGrace(String userId) throws RepositoryException {
        JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user != null && user.isNodeType(MIXIN_GRACE_TRACKING)
                    && user.hasProperty(PROP_GRACE_STARTED_AT)) {
                user.setProperty(PROP_GRACE_STARTED_AT, 0L);
                systemSession.save();
            }
            return null;
        });
    }

    /**
     * Update the last-used counter (replay protection).
     */
    public void updateLastUsedCounter(String userId, long counter) throws RepositoryException {
        JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user == null || !user.isNodeType(MIXIN_USER_SETTINGS)) {
                return null;
            }
            user.setProperty(PROP_LAST_USED_COUNTER, counter);
            systemSession.save();
            return null;
        });
    }

    /**
     * Atomically verify a submitted backup code AND remove the matched hash (single-use
     * consumption) in a SINGLE JCR transaction — the backup-code analogue of
     * {@link #verifyAndConsumeTotp}.
     * <p>
     * The hash list is re-read from JCR inside the same transaction that persists the
     * shrunken list. Verifying against a pre-loaded snapshot and then removing "by index"
     * in a second transaction would let two parallel requests submitting the same code both
     * succeed (double-spend) — and the second removal would delete whichever <i>innocent</i>
     * code had shifted into that index.
     *
     * @return {@code true} if a code matched and its hash was consumed
     */
    public boolean verifyAndConsumeBackupCode(String userId, BackupCodes backupCodes, String submitted)
            throws RepositoryException {
        return Boolean.TRUE.equals(JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user == null || !user.hasProperty(PROP_BACKUP_CODES)) {
                return false;
            }
            Value[] values = user.getProperty(PROP_BACKUP_CODES).getValues();
            List<String> hashes = new ArrayList<>(values.length);
            for (Value v : values) {
                hashes.add(v.getString());
            }
            Optional<Integer> matched = backupCodes.verifyAndIndex(hashes, submitted);
            if (!matched.isPresent()) {
                return false;
            }
            hashes.remove(matched.get().intValue());
            user.setProperty(PROP_BACKUP_CODES, hashes.toArray(new String[0]));
            systemSession.save();
            logger.info("Backup code consumed for user {} (remaining: {})", user.getName(), hashes.size());
            return true;
        }));
    }

    /**
     * Replace the entire backup-code list (used on regeneration).
     */
    public void replaceBackupCodes(String userId, List<String> newHashes) throws RepositoryException {
        JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user == null) {
                throw new RepositoryException("User not found: " + userId);
            }
            ensureMixin(user);
            user.setProperty(PROP_BACKUP_CODES, newHashes.toArray(new String[0]));
            systemSession.save();
            return null;
        });
    }

    /**
     * Disable TOTP for the user: removes the secret, clears backup codes, marks not enrolled.
     */
    public void disable(String userId) throws RepositoryException {
        JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRUserNode user = userManagerService.lookupUser(userId, systemSession);
            if (user == null || !user.isNodeType(MIXIN_USER_SETTINGS)) {
                return null;
            }
            if (user.hasProperty(PROP_SECRET)) {
                user.getProperty(PROP_SECRET).remove();
            }
            if (user.hasProperty(PROP_BACKUP_CODES)) {
                user.getProperty(PROP_BACKUP_CODES).remove();
            }
            user.setProperty(PROP_ENROLLED, false);
            user.setProperty(PROP_LAST_USED_COUNTER, 0L);
            systemSession.save();
            logger.info("TOTP disabled for user {}", user.getName());
            return null;
        });
    }

    private static void ensureMixin(JCRNodeWrapper user) throws RepositoryException {
        if (!user.isNodeType(MIXIN_USER_SETTINGS)) {
            user.addMixin(MIXIN_USER_SETTINGS);
        }
    }
}
