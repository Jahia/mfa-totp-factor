package org.jahia.modules.upa.mfa.webauthn;

import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.PathNotFoundException;
import javax.jcr.RepositoryException;
import javax.jcr.Value;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Reads and writes the {@code upaWebauthn:siteSettings} mixin on site nodes — the per-site
 * WebAuthn policy (enabled / enforced / graceDays / enabledGroups). Mirrors
 * {@code TotpSiteSettingsStore} (without the login/logout URL fields, which are TOTP-specific).
 */
@Component(service = WebAuthnSiteSettingsStore.class, immediate = true)
public class WebAuthnSiteSettingsStore {

    private static final Logger logger = LoggerFactory.getLogger(WebAuthnSiteSettingsStore.class);

    public static final String MIXIN_SITE_SETTINGS = "upaWebauthn:siteSettings";
    public static final String PROP_ENABLED = "upaWebauthn:enabled";
    public static final String PROP_ENFORCED = "upaWebauthn:enforced";
    public static final String PROP_GRACE_DAYS = "upaWebauthn:graceDays";
    public static final String PROP_ENABLED_GROUPS = "upaWebauthn:enabledGroups";

    public static final long MAX_GRACE_DAYS = 365L;

    /** Snapshot of the WebAuthn settings for a site. */
    public static final class WebAuthnSiteSettings {
        public static final WebAuthnSiteSettings DISABLED =
                new WebAuthnSiteSettings(false, false, 0L, Collections.emptyList());

        private final boolean enabled;
        private final boolean enforced;
        private final long graceDays;
        private final List<String> enabledGroups;

        public WebAuthnSiteSettings(boolean enabled, boolean enforced, long graceDays, List<String> enabledGroups) {
            this.enabled = enabled;
            this.enforced = enforced;
            this.graceDays = graceDays;
            this.enabledGroups = enabledGroups == null
                    ? Collections.emptyList() : Collections.unmodifiableList(new ArrayList<>(enabledGroups));
        }

        public boolean isEnabled()  { return enabled; }
        public boolean isEnforced() { return enforced; }
        public long getGraceDays()  { return graceDays; }
        public List<String> getEnabledGroups() { return enabledGroups; }
    }

    public WebAuthnSiteSettings load(String siteKey) throws RepositoryException {
        if (siteKey == null || siteKey.isEmpty()) {
            return WebAuthnSiteSettings.DISABLED;
        }
        return JCRTemplate.getInstance().doExecuteWithSystemSession(systemSession -> {
            JCRNodeWrapper siteNode;
            try {
                siteNode = systemSession.getNode("/sites/" + siteKey);
            } catch (PathNotFoundException e) {
                return WebAuthnSiteSettings.DISABLED;
            }
            if (!siteNode.isNodeType(MIXIN_SITE_SETTINGS)) {
                return WebAuthnSiteSettings.DISABLED;
            }
            boolean enabled = siteNode.hasProperty(PROP_ENABLED) && siteNode.getProperty(PROP_ENABLED).getBoolean();
            boolean enforced = siteNode.hasProperty(PROP_ENFORCED) && siteNode.getProperty(PROP_ENFORCED).getBoolean();
            long graceDays = siteNode.hasProperty(PROP_GRACE_DAYS)
                    ? siteNode.getProperty(PROP_GRACE_DAYS).getLong() : 0L;
            return new WebAuthnSiteSettings(enabled, enforced, graceDays, readGroups(siteNode));
        });
    }

    /**
     * Whether at least one site has WebAuthn {@code enabled + enforced}. Used by the shared
     * {@code /cms/login} gate on its no-resolvable-site code path: that endpoint authenticates
     * globally, so a single enforcing site makes it a second-factor bypass vector.
     */
    public boolean isAnySiteEnforcing() throws RepositoryException {
        return Boolean.TRUE.equals(JCRTemplate.getInstance().doExecuteWithSystemSession(session -> {
            javax.jcr.query.Query query = session.getWorkspace().getQueryManager().createQuery(
                    "SELECT * FROM [" + MIXIN_SITE_SETTINGS + "] WHERE [" + PROP_ENABLED + "] = true AND ["
                            + PROP_ENFORCED + "] = true",
                    javax.jcr.query.Query.JCR_SQL2);
            query.setLimit(1);
            return query.execute().getNodes().hasNext();
        }));
    }

    private static List<String> readGroups(JCRNodeWrapper siteNode) throws RepositoryException {
        List<String> groups = new ArrayList<>();
        if (!siteNode.hasProperty(PROP_ENABLED_GROUPS)) {
            return groups;
        }
        for (Value v : siteNode.getProperty(PROP_ENABLED_GROUPS).getValues()) {
            String g = v.getString();
            if (g != null && !g.trim().isEmpty()) {
                groups.add(g.trim());
            }
        }
        return groups;
    }

    /**
     * Persist the settings via the caller's (admin) session. graceDays is clamped to
     * {@code [0, MAX_GRACE_DAYS]}. The caller MUST have validated site-admin access.
     */
    public void save(JCRSessionWrapper session, String siteKey, WebAuthnSiteSettings settings)
            throws RepositoryException {
        if (siteKey == null || siteKey.isEmpty()) {
            throw new IllegalArgumentException("siteKey must not be empty");
        }
        JCRNodeWrapper siteNode = session.getNode("/sites/" + siteKey);
        if (!siteNode.isNodeType(MIXIN_SITE_SETTINGS)) {
            siteNode.addMixin(MIXIN_SITE_SETTINGS);
        }
        siteNode.setProperty(PROP_ENABLED, settings.isEnabled());
        siteNode.setProperty(PROP_ENFORCED, settings.isEnforced());
        siteNode.setProperty(PROP_GRACE_DAYS, Math.min(Math.max(0L, settings.getGraceDays()), MAX_GRACE_DAYS));
        List<String> cleaned = new ArrayList<>();
        for (String g : settings.getEnabledGroups()) {
            if (g != null && !g.trim().isEmpty()) {
                cleaned.add(g.trim());
            }
        }
        siteNode.setProperty(PROP_ENABLED_GROUPS, cleaned.toArray(new String[0]));
        session.save();
        logger.info("WebAuthn site settings saved for {}: enabled={}, enforced={}, graceDays={}, groups={}",
                siteKey, settings.isEnabled(), settings.isEnforced(), settings.getGraceDays(), cleaned);
    }
}
