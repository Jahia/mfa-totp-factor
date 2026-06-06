package org.jahia.modules.upa.mfa.webauthn;

import com.yubico.webauthn.CredentialRepository;
import com.yubico.webauthn.RegisteredCredential;
import com.yubico.webauthn.data.AuthenticatorTransport;
import com.yubico.webauthn.data.ByteArray;
import com.yubico.webauthn.data.PublicKeyCredentialDescriptor;
import com.yubico.webauthn.data.exception.Base64UrlException;
import org.apache.commons.lang3.StringUtils;
import org.jahia.services.content.JCRTemplate;
import org.jahia.services.content.decorator.JCRUserNode;
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
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Optional;
import java.util.Set;
import java.util.TreeSet;

/**
 * Stores WebAuthn credentials on the user node (a {@code upaWebauthn:credential} child per
 * authenticator, under the {@code upaWebauthn:userSettings} mixin) via a JCR system session,
 * and adapts that storage to the yubico {@link CredentialRepository} SPI used by the relying
 * party during the assertion/registration ceremonies.
 * <p>
 * The WebAuthn <i>user handle</i> is the user node's JCR identifier (UTF-8 bytes) — stable per
 * user and reversible without extra storage. All reads/writes use the system session so the
 * {@code protected} properties can be set by the module itself; the sign counter is updated
 * atomically on each successful assertion (authenticator clone detection).
 */
@Component(service = WebAuthnCredentialStore.class, immediate = true)
public class WebAuthnCredentialStore implements CredentialRepository {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnCredentialStore.class);

    public static final String MIXIN_USER_SETTINGS = "upaWebauthn:userSettings";
    public static final String NT_CREDENTIAL = "upaWebauthn:credential";
    public static final String PROP_CREDENTIAL_ID = "upaWebauthn:credentialId";
    public static final String PROP_PUBLIC_KEY_COSE = "upaWebauthn:publicKeyCose";
    public static final String PROP_SIGN_COUNT = "upaWebauthn:signCount";
    public static final String PROP_USER_HANDLE = "upaWebauthn:userHandle";
    public static final String PROP_TRANSPORTS = "upaWebauthn:transports";
    public static final String PROP_AAGUID = "upaWebauthn:aaguid";
    public static final String PROP_NICKNAME = "upaWebauthn:nickname";
    public static final String PROP_LAST_USED_AT = "upaWebauthn:lastUsedAt";
    public static final String PROP_GRACE_STARTED_AT = "upaWebauthn:graceStartedAt";

    private JahiaUserManagerService userManagerService;

    @Reference
    public void setUserManagerService(JahiaUserManagerService userManagerService) {
        this.userManagerService = userManagerService;
    }

    /** Immutable view of a stored credential for the dashboard listing. */
    public static final class StoredCredential {
        private final String credentialId;
        private final String nickname;
        private final long signCount;
        private final long createdAt;
        private final long lastUsedAt;
        private final List<String> transports;
        private final String aaguid;

        public StoredCredential(String credentialId, String nickname, long signCount, long createdAt,
                                long lastUsedAt, List<String> transports, String aaguid) {
            this.credentialId = credentialId;
            this.nickname = nickname;
            this.signCount = signCount;
            this.createdAt = createdAt;
            this.lastUsedAt = lastUsedAt;
            this.transports = transports == null ? Collections.emptyList()
                    : Collections.unmodifiableList(new ArrayList<>(transports));
            this.aaguid = aaguid;
        }

        public String getCredentialId() { return credentialId; }
        public String getNickname()     { return nickname; }
        public long getSignCount()      { return signCount; }
        public long getCreatedAt()      { return createdAt; }
        public long getLastUsedAt()     { return lastUsedAt; }
        public List<String> getTransports() { return transports; }
        public String getAaguid()       { return aaguid; }
    }

    /** Whether the user has at least one registered credential. */
    public boolean hasCredentials(String userId) throws RepositoryException {
        return Boolean.TRUE.equals(JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            JCRUserNode user = userManagerService.lookupUser(userId, session);
            if (user == null || !user.isNodeType(MIXIN_USER_SETTINGS)) {
                return false;
            }
            // Only count actual credential nodes: user nodes have unrelated children
            // (j:profile, preferences, ...) and the mixin survives a deleteAll() reset
            // because it still carries the grace-window property.
            NodeIterator it = user.getNodes();
            while (it.hasNext()) {
                if (it.nextNode().isNodeType(NT_CREDENTIAL)) {
                    return true;
                }
            }
            return false;
        }));
    }

    /** List the user's registered credentials (newest first by creation). */
    public List<StoredCredential> listCredentials(String userId) throws RepositoryException {
        return JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            List<StoredCredential> out = new ArrayList<>();
            JCRUserNode user = userManagerService.lookupUser(userId, session);
            if (user == null || !user.isNodeType(MIXIN_USER_SETTINGS)) {
                return out;
            }
            NodeIterator it = user.getNodes();
            while (it.hasNext()) {
                Node n = it.nextNode();
                if (!n.isNodeType(NT_CREDENTIAL)) {
                    continue;
                }
                out.add(new StoredCredential(
                        strProp(n, PROP_CREDENTIAL_ID), strProp(n, PROP_NICKNAME),
                        longProp(n, PROP_SIGN_COUNT), createdAt(n), longProp(n, PROP_LAST_USED_AT),
                        multiProp(n, PROP_TRANSPORTS), strProp(n, PROP_AAGUID)));
            }
            out.sort((a, b) -> Long.compare(b.getCreatedAt(), a.getCreatedAt()));
            return out;
        });
    }

    /** Data for a freshly-registered credential to persist (groups the fields so the store API
     *  stays within the parameter-count limit). */
    public static final class NewCredential {
        private final String credentialIdB64;
        private final String publicKeyCoseB64;
        private final long signCount;
        private final String userHandleB64;
        private final List<String> transports;
        private final String aaguid;
        private final String nickname;

        public NewCredential(String credentialIdB64, String publicKeyCoseB64, long signCount,
                             String userHandleB64, List<String> transports, String aaguid, String nickname) {
            this.credentialIdB64 = credentialIdB64;
            this.publicKeyCoseB64 = publicKeyCoseB64;
            this.signCount = signCount;
            this.userHandleB64 = userHandleB64;
            this.transports = transports;
            this.aaguid = aaguid;
            this.nickname = nickname;
        }
    }

    /** Persist a freshly-registered credential under the user node. */
    public void addCredential(String userId, NewCredential c) throws RepositoryException {
        JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            JCRUserNode user = userManagerService.lookupUser(userId, session);
            if (user == null) {
                throw new RepositoryException("User not found: " + userId);
            }
            if (!user.isNodeType(MIXIN_USER_SETTINGS)) {
                user.addMixin(MIXIN_USER_SETTINGS);
            }
            Node cred = user.addNode("c-" + java.util.UUID.randomUUID(), NT_CREDENTIAL);
            cred.setProperty(PROP_CREDENTIAL_ID, c.credentialIdB64);
            cred.setProperty(PROP_PUBLIC_KEY_COSE, c.publicKeyCoseB64);
            cred.setProperty(PROP_SIGN_COUNT, c.signCount);
            if (c.userHandleB64 != null) {
                cred.setProperty(PROP_USER_HANDLE, c.userHandleB64);
            }
            if (c.transports != null && !c.transports.isEmpty()) {
                cred.setProperty(PROP_TRANSPORTS, c.transports.toArray(new String[0]));
            }
            if (c.aaguid != null) {
                cred.setProperty(PROP_AAGUID, c.aaguid);
            }
            cred.setProperty(PROP_NICKNAME, StringUtils.defaultIfBlank(c.nickname, "Passkey"));
            cred.setProperty(PROP_LAST_USED_AT, 0L);
            session.save();
            logger.info("WebAuthn credential registered for user {}", user.getName());
            return null;
        });
    }

    /**
     * Update the sign counter (+ last-used) for a credential after a successful assertion.
     * <p>
     * The counter is read and written in the SAME system-session transaction and only ever
     * advanced — never regressed. {@code newSignCount == 0} means the authenticator does not
     * keep a counter (clone detection is not possible for it); we still record last-used.
     * This guards the single-node read-modify-write; a JCR {@code save()} conflict between two
     * concurrent assertions on a cluster makes the loser's transaction retry/fail rather than
     * silently roll the counter back.
     */
    public void updateOnAssertion(String userId, String credentialIdB64, long newSignCount)
            throws RepositoryException {
        JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            Node cred = findCredentialNode(userManagerService.lookupUser(userId, session), credentialIdB64);
            if (cred != null) {
                long current = cred.hasProperty(PROP_SIGN_COUNT) ? cred.getProperty(PROP_SIGN_COUNT).getLong() : 0L;
                if (newSignCount > current) {
                    cred.setProperty(PROP_SIGN_COUNT, newSignCount);
                }
                cred.setProperty(PROP_LAST_USED_AT, System.currentTimeMillis());
                session.save();
            }
            return null;
        });
    }

    /** Rename a credential (user-facing label). Returns true if it existed. */
    public boolean renameCredential(String userId, String credentialIdB64, String nickname)
            throws RepositoryException {
        return Boolean.TRUE.equals(JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            Node cred = findCredentialNode(userManagerService.lookupUser(userId, session), credentialIdB64);
            if (cred == null) {
                return false;
            }
            cred.setProperty(PROP_NICKNAME, StringUtils.defaultIfBlank(nickname, "Passkey"));
            session.save();
            return true;
        }));
    }

    /** Delete a single credential. Returns true if it existed. */
    public boolean deleteCredential(String userId, String credentialIdB64) throws RepositoryException {
        return Boolean.TRUE.equals(JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            Node cred = findCredentialNode(userManagerService.lookupUser(userId, session), credentialIdB64);
            if (cred == null) {
                return false;
            }
            cred.remove();
            session.save();
            return true;
        }));
    }

    /** Admin recovery: remove ALL of a user's WebAuthn credentials. */
    public void deleteAll(String userId) throws RepositoryException {
        JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            JCRUserNode user = userManagerService.lookupUser(userId, session);
            if (user == null || !user.isNodeType(MIXIN_USER_SETTINGS)) {
                return null;
            }
            List<Node> toRemove = new ArrayList<>();
            NodeIterator it = user.getNodes();
            while (it.hasNext()) {
                Node n = it.nextNode();
                if (n.isNodeType(NT_CREDENTIAL)) {
                    toRemove.add(n);
                }
            }
            for (Node n : toRemove) {
                n.remove();
            }
            session.save();
            logger.info("All WebAuthn credentials reset for user {}", user.getName());
            return null;
        });
    }

    /**
     * Return the epoch-millis at which the enrollment grace window started for this user,
     * initializing it to {@code nowMillis} on first call. Mirrors {@code TotpUserStore}.
     */
    public long getOrStartGraceMillis(String userId, long nowMillis) throws RepositoryException {
        Long result = JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            JCRUserNode user = userManagerService.lookupUser(userId, session);
            if (user == null) {
                return nowMillis;
            }
            if (user.isNodeType(MIXIN_USER_SETTINGS) && user.hasProperty(PROP_GRACE_STARTED_AT)
                    && user.getProperty(PROP_GRACE_STARTED_AT).getLong() > 0L) {
                return user.getProperty(PROP_GRACE_STARTED_AT).getLong();
            }
            if (!user.isNodeType(MIXIN_USER_SETTINGS)) {
                user.addMixin(MIXIN_USER_SETTINGS);
            }
            user.setProperty(PROP_GRACE_STARTED_AT, nowMillis);
            session.save();
            return nowMillis;
        });
        return result == null ? nowMillis : result;
    }

    /** Clear grace tracking (once the user registers a credential or is reset). */
    public void clearGrace(String userId) throws RepositoryException {
        JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            JCRUserNode user = userManagerService.lookupUser(userId, session);
            if (user != null && user.isNodeType(MIXIN_USER_SETTINGS) && user.hasProperty(PROP_GRACE_STARTED_AT)) {
                user.setProperty(PROP_GRACE_STARTED_AT, 0L);
                session.save();
            }
            return null;
        });
    }

    /** Whether the user belongs to at least one of the given groups (empty = no restriction). */
    public boolean isMemberOfAnyGroup(String userId, java.util.Collection<String> groupNames,
                                      org.jahia.services.usermanager.JahiaGroupManagerService groupManager)
            throws RepositoryException {
        if (groupNames == null || groupNames.isEmpty()) {
            return true;
        }
        return Boolean.TRUE.equals(JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            JCRUserNode user = userManagerService.lookupUser(userId, session);
            if (user == null) {
                return false;
            }
            List<String> membership = groupManager.getMembershipByPath(user.getPath());
            if (membership == null) {
                return false;
            }
            for (String groupPath : membership) {
                String name = StringUtils.substringAfterLast(groupPath, "/");
                if (groupNames.contains(name)) {
                    return true;
                }
            }
            return false;
        }));
    }

    /** Aggregate registration report for the admin "who hasn't registered a passkey?" view. */
    public static final class RegistrationReport {
        private final long totalUsers;
        private final long registeredUsers;
        private final List<String> notRegistered;
        private final boolean truncated;

        public RegistrationReport(long totalUsers, long registeredUsers, List<String> notRegistered, boolean truncated) {
            this.totalUsers = totalUsers;
            this.registeredUsers = registeredUsers;
            this.notRegistered = Collections.unmodifiableList(new ArrayList<>(notRegistered));
            this.truncated = truncated;
        }

        public long getTotalUsers()      { return totalUsers; }
        public long getRegisteredUsers() { return registeredUsers; }
        public List<String> getNotRegistered() { return notRegistered; }
        public boolean isTruncated()     { return truncated; }
    }

    private static final int REPORT_SCAN_CAP = 5000;

    /**
     * Build the registration report: total users scanned, how many have ≥1 WebAuthn credential,
     * and a capped list of those who do not. Registration is global (per user); the report is
     * gated by a site-admin check in the GraphQL layer.
     */
    public RegistrationReport buildRegistrationReport(int listLimit) throws RepositoryException {
        int listCap = Math.max(1, Math.min(listLimit, 1000));
        return JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            Set<String> registered = new LinkedHashSet<>();
            Query credQuery = session.getWorkspace().getQueryManager().createQuery(
                    "SELECT * FROM [" + NT_CREDENTIAL + "]", Query.JCR_SQL2);
            NodeIterator credIt = credQuery.execute().getNodes();
            while (credIt.hasNext()) {
                Node cred = credIt.nextNode();
                registered.add(cred.getParent().getName());
            }

            Query usersQuery = session.getWorkspace().getQueryManager().createQuery(
                    "SELECT * FROM [jnt:user]", Query.JCR_SQL2);
            usersQuery.setLimit(REPORT_SCAN_CAP);
            NodeIterator usersIt = usersQuery.execute().getNodes();
            long total = 0;
            List<String> notRegistered = new ArrayList<>();
            boolean truncated = false;
            while (usersIt.hasNext()) {
                String name = usersIt.nextNode().getName();
                if ("guest".equals(name)) {
                    continue;
                }
                total++;
                if (!registered.contains(name)) {
                    if (notRegistered.size() < listCap) {
                        notRegistered.add(name);
                    } else {
                        truncated = true;
                    }
                }
            }
            return new RegistrationReport(total, registered.size(), notRegistered, truncated);
        });
    }

    /** The stable per-user WebAuthn handle = the user node identifier's UTF-8 bytes. */
    public Optional<ByteArray> userHandleFor(String userId) throws RepositoryException {
        return JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            JCRUserNode user = userManagerService.lookupUser(userId, session);
            if (user == null) {
                return Optional.<ByteArray>empty();
            }
            return Optional.of(new ByteArray(user.getIdentifier().getBytes(StandardCharsets.UTF_8)));
        });
    }

    // --- CredentialRepository (yubico) ---------------------------------------------------

    @Override
    public Set<PublicKeyCredentialDescriptor> getCredentialIdsForUsername(String username) {
        try {
            return JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
                Set<PublicKeyCredentialDescriptor> out = new LinkedHashSet<>();
                JCRUserNode user = userManagerService.lookupUser(username, session);
                if (user == null || !user.isNodeType(MIXIN_USER_SETTINGS)) {
                    return out;
                }
                NodeIterator it = user.getNodes();
                while (it.hasNext()) {
                    toDescriptor(it.nextNode()).ifPresent(out::add);
                }
                return out;
            });
        } catch (RepositoryException e) {
            logger.warn("Failed to list WebAuthn credential ids for {}: {}", username, e.getMessage());
            return Collections.emptySet();
        }
    }

    @Override
    public Optional<ByteArray> getUserHandleForUsername(String username) {
        try {
            return userHandleFor(username);
        } catch (RepositoryException e) {
            return Optional.empty();
        }
    }

    @Override
    public Optional<String> getUsernameForUserHandle(ByteArray userHandle) {
        try {
            return JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
                String identifier = new String(userHandle.getBytes(), StandardCharsets.UTF_8);
                try {
                    Node node = session.getNodeByIdentifier(identifier);
                    return Optional.of(node.getName());
                } catch (RepositoryException e) {
                    return Optional.<String>empty();
                }
            });
        } catch (RepositoryException e) {
            return Optional.empty();
        }
    }

    @Override
    public Optional<RegisteredCredential> lookup(ByteArray credentialId, ByteArray userHandle) {
        try {
            return JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
                String identifier = new String(userHandle.getBytes(), StandardCharsets.UTF_8);
                Node user;
                try {
                    user = session.getNodeByIdentifier(identifier);
                } catch (RepositoryException e) {
                    return Optional.<RegisteredCredential>empty();
                }
                Node cred = findCredentialNode(user, credentialId.getBase64Url());
                if (cred == null) {
                    return Optional.<RegisteredCredential>empty();
                }
                return buildRegisteredCredential(cred, credentialId, userHandle);
            });
        } catch (RepositoryException e) {
            logger.warn("WebAuthn credential lookup failed: {}", e.getMessage());
            return Optional.empty();
        }
    }

    @Override
    public Set<RegisteredCredential> lookupAll(ByteArray credentialId) {
        try {
            return JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
                Set<RegisteredCredential> out = new LinkedHashSet<>();
                String sql = "SELECT * FROM [" + NT_CREDENTIAL + "] WHERE [" + PROP_CREDENTIAL_ID + "] = $id";
                Query q = session.getWorkspace().getQueryManager().createQuery(sql, Query.JCR_SQL2);
                q.bindValue("id", session.getValueFactory().createValue(credentialId.getBase64Url()));
                NodeIterator it = q.execute().getNodes();
                while (it.hasNext()) {
                    Node cred = it.nextNode();
                    String handleB64 = strProp(cred, PROP_USER_HANDLE);
                    ByteArray userHandle = parseB64(handleB64);
                    if (userHandle == null) {
                        continue;
                    }
                    buildRegisteredCredential(cred, credentialId, userHandle).ifPresent(out::add);
                }
                return out;
            });
        } catch (RepositoryException e) {
            logger.warn("WebAuthn lookupAll failed: {}", e.getMessage());
            return Collections.emptySet();
        }
    }

    // --- helpers -------------------------------------------------------------------------

    /** Map a credential node to a {@link PublicKeyCredentialDescriptor} (empty for non-credential/invalid nodes). */
    private Optional<PublicKeyCredentialDescriptor> toDescriptor(Node n) throws RepositoryException {
        ByteArray id = n.isNodeType(NT_CREDENTIAL) ? parseB64(strProp(n, PROP_CREDENTIAL_ID)) : null;
        if (id == null) {
            return Optional.empty();
        }
        PublicKeyCredentialDescriptor.PublicKeyCredentialDescriptorBuilder b =
                PublicKeyCredentialDescriptor.builder().id(id);
        Set<AuthenticatorTransport> transports = parseTransports(multiProp(n, PROP_TRANSPORTS));
        if (!transports.isEmpty()) {
            b.transports(transports);
        }
        return Optional.of(b.build());
    }

    private Optional<RegisteredCredential> buildRegisteredCredential(Node cred, ByteArray credentialId,
                                                                     ByteArray userHandle) throws RepositoryException {
        ByteArray cose = parseB64(strProp(cred, PROP_PUBLIC_KEY_COSE));
        if (cose == null) {
            return Optional.empty();
        }
        return Optional.of(RegisteredCredential.builder()
                .credentialId(credentialId)
                .userHandle(userHandle)
                .publicKeyCose(cose)
                .signatureCount(longProp(cred, PROP_SIGN_COUNT))
                .build());
    }

    private Node findCredentialNode(JCRUserNode user, String credentialIdB64) throws RepositoryException {
        return findCredentialNode((Node) user, credentialIdB64);
    }

    private Node findCredentialNode(Node user, String credentialIdB64) throws RepositoryException {
        if (user == null || credentialIdB64 == null || !user.isNodeType(MIXIN_USER_SETTINGS)) {
            return null;
        }
        NodeIterator it = user.getNodes();
        while (it.hasNext()) {
            Node n = it.nextNode();
            if (n.isNodeType(NT_CREDENTIAL) && credentialIdB64.equals(strProp(n, PROP_CREDENTIAL_ID))) {
                return n;
            }
        }
        return null;
    }

    private static Set<AuthenticatorTransport> parseTransports(List<String> ids) {
        Set<AuthenticatorTransport> out = new TreeSet<>();
        if (ids == null) {
            return out;
        }
        for (String id : ids) {
            if (StringUtils.isNotBlank(id)) {
                out.add(AuthenticatorTransport.of(id.trim()));
            }
        }
        return out;
    }

    private static ByteArray parseB64(String b64) {
        if (StringUtils.isBlank(b64)) {
            return null;
        }
        try {
            return ByteArray.fromBase64Url(b64);
        } catch (Base64UrlException e) {
            return null;
        }
    }

    private static String strProp(Node n, String name) throws RepositoryException {
        return n.hasProperty(name) ? n.getProperty(name).getString() : null;
    }

    private static long longProp(Node n, String name) throws RepositoryException {
        return n.hasProperty(name) ? n.getProperty(name).getLong() : 0L;
    }

    private static long createdAt(Node n) throws RepositoryException {
        if (n.hasProperty("jcr:created")) {
            return n.getProperty("jcr:created").getDate().getTimeInMillis();
        }
        return 0L;
    }

    private static List<String> multiProp(Node n, String name) throws RepositoryException {
        List<String> out = new ArrayList<>();
        if (n.hasProperty(name)) {
            for (Value v : n.getProperty(name).getValues()) {
                out.add(v.getString());
            }
        }
        return out;
    }
}
