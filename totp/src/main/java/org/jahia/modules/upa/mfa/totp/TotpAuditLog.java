package org.jahia.modules.upa.mfa.totp;

import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.Node;
import javax.jcr.NodeIterator;
import javax.jcr.RepositoryException;
import javax.jcr.query.Query;
import javax.jcr.query.QueryResult;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * Append-only audit trail for TOTP MFA events (enroll, confirm, verify, disable, regenerate,
 * admin reset, lockout). Events are stored as {@code upaTotp:auditEvent} nodes under
 * {@code /settings/mfaTotpAuditLog} via a system session, and queried back (newest first,
 * scoped by site) for the admin reporting UI.
 * <p>
 * Recording is best-effort: an audit failure is logged but never breaks the operation being
 * audited. Codes/secrets are never written to the trail.
 */
@Component(service = TotpAuditLog.class, immediate = true)
public class TotpAuditLog {

    private static final Logger logger = LoggerFactory.getLogger(TotpAuditLog.class);

    private static final String LOG_PATH = "/settings/mfaTotpAuditLog";
    private static final String NT_LOG = "upaTotp:auditLog";
    private static final String NT_EVENT = "upaTotp:auditEvent";

    static final String PROP_EVENT_TYPE = "upaTotp:eventType";
    static final String PROP_OUTCOME = "upaTotp:outcome";
    static final String PROP_USER_ID = "upaTotp:userId";
    static final String PROP_SITE_KEY = "upaTotp:siteKey";
    static final String PROP_TIMESTAMP = "upaTotp:timestamp";
    static final String PROP_DETAIL = "upaTotp:detail";

    /** Immutable view of one audit event, returned by {@link #recentEvents}. */
    public static final class AuditEvent {
        private final String eventType;
        private final String outcome;
        private final String userId;
        private final String siteKey;
        private final long timestamp;
        private final String detail;

        public AuditEvent(String eventType, String outcome, String userId, String siteKey,
                          long timestamp, String detail) {
            this.eventType = eventType;
            this.outcome = outcome;
            this.userId = userId;
            this.siteKey = siteKey;
            this.timestamp = timestamp;
            this.detail = detail;
        }

        public String getEventType() { return eventType; }
        public String getOutcome()   { return outcome; }
        public String getUserId()    { return userId; }
        public String getSiteKey()   { return siteKey; }
        public long getTimestamp()   { return timestamp; }
        public String getDetail()    { return detail; }
    }

    /**
     * Record an event. Best-effort: never throws into the caller's flow.
     */
    public void recordEvent(String eventType, String outcome, String userId, String siteKey, String detail) {
        try {
            JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
                JCRNodeWrapper log = ensureLogNode(session);
                JCRNodeWrapper event = log.addNode("e-" + UUID.randomUUID(), NT_EVENT);
                event.setProperty(PROP_EVENT_TYPE, safe(eventType));
                event.setProperty(PROP_OUTCOME, safe(outcome));
                event.setProperty(PROP_USER_ID, safe(userId));
                event.setProperty(PROP_SITE_KEY, safe(siteKey));
                event.setProperty(PROP_TIMESTAMP, System.currentTimeMillis());
                if (detail != null) {
                    event.setProperty(PROP_DETAIL, detail);
                }
                session.save();
                return null;
            });
        } catch (RepositoryException e) {
            logger.warn("Failed to record TOTP audit event {}/{} for user {}: {}",
                    eventType, outcome, userId, e.getMessage());
        }
    }

    /**
     * Return the most recent events for a site, newest first, capped at {@code limit}.
     */
    public List<AuditEvent> recentEvents(String siteKey, int limit) throws RepositoryException {
        int cap = Math.max(1, Math.min(limit, 500));
        return JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            List<AuditEvent> out = new ArrayList<>();
            String sql = "SELECT * FROM [" + NT_EVENT + "] WHERE [" + PROP_SITE_KEY + "] = $site"
                    + " ORDER BY [" + PROP_TIMESTAMP + "] DESC";
            Query q = session.getWorkspace().getQueryManager().createQuery(sql, Query.JCR_SQL2);
            q.bindValue("site", session.getValueFactory().createValue(siteKey == null ? "" : siteKey));
            q.setLimit(cap);
            QueryResult result = q.execute();
            NodeIterator it = result.getNodes();
            while (it.hasNext()) {
                Node n = it.nextNode();
                out.add(new AuditEvent(
                        strProp(n, PROP_EVENT_TYPE), strProp(n, PROP_OUTCOME),
                        strProp(n, PROP_USER_ID), strProp(n, PROP_SITE_KEY),
                        n.hasProperty(PROP_TIMESTAMP) ? n.getProperty(PROP_TIMESTAMP).getLong() : 0L,
                        strProp(n, PROP_DETAIL)));
            }
            return out;
        });
    }

    private JCRNodeWrapper ensureLogNode(JCRSessionWrapper session) throws RepositoryException {
        if (session.nodeExists(LOG_PATH)) {
            return session.getNode(LOG_PATH);
        }
        JCRNodeWrapper settings = session.getNode("/settings");
        JCRNodeWrapper log = settings.addNode("mfaTotpAuditLog", NT_LOG);
        session.save();
        return log;
    }

    private static String safe(String s) {
        return s == null ? "" : s;
    }

    private static String strProp(Node n, String name) throws RepositoryException {
        return n.hasProperty(name) ? n.getProperty(name).getString() : null;
    }
}
