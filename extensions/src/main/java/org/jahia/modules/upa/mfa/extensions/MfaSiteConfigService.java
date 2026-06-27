package org.jahia.modules.upa.mfa.extensions;

import org.osgi.service.cm.ManagedServiceFactory;
import org.osgi.service.component.annotations.Component;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardCopyOption;
import java.util.ArrayList;
import java.util.Dictionary;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.TreeMap;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.UnaryOperator;
import java.util.regex.Pattern;

/**
 * The single source of per-site MFA configuration, backed by file OSGi <b>factory</b>
 * configuration: one {@code <karaf.etc>/org.jahia.modules.mfa.extensions.site-<siteKey>.cfg} file
 * per site, delivered by Felix FileInstall to {@link #updated(String, Dictionary)} and held as an
 * immutable {@link MfaSiteConfig} snapshot per site key. This replaces the per-factor JCR
 * {@code *:siteSettings} mixins so operators can see and manage the config as files (and have the
 * cluster propagate {@code karaf/etc} the same way it does every other module config).
 * <p>
 * Each file holds the factor-agnostic {@code loginUrl}/{@code logoutUrl} plus, per factor,
 * {@code <factorType>.enabled} and {@code <factorType>.enabledGroups} (a comma-separated string —
 * an OSGi {@code String[]} can't be expressed reliably in a {@code .cfg}, so we own the split, as
 * {@link MfaGlobalPolicy#parseEnforcedFactors(Object)} does for the global list).
 * <p>
 * <b>Writes</b> ({@link #save}) go straight to the file (atomic temp + {@code ATOMIC_MOVE}) and
 * update the in-memory map synchronously, so a read-after-write on the same node is immediate; the
 * subsequent FileInstall callback is an idempotent refresh. We never use
 * {@code ConfigurationAdmin.createFactoryConfiguration} — API-created factory configs are
 * bundle-scoped and get orphaned on reinstall.
 * <p>
 * <b>Authorization</b> for writes lives in the GraphQL layer ({@link MfaAdminAccess}); this service
 * only validates the {@code siteKey} as a safe single path segment before building a filename.
 * <p>
 * <b>Cluster note:</b> the in-memory map is per node; other nodes converge once {@code karaf/etc}
 * is propagated and their own FileInstall fires.
 */
@Component(service = {MfaSiteConfigService.class, ManagedServiceFactory.class},
        immediate = true,
        property = "service.pid=" + MfaSiteConfigService.FACTORY_PID)
public class MfaSiteConfigService implements ManagedServiceFactory {

    /** Factory PID; each instance is the file {@code <FACTORY_PID>-<siteKey>.cfg}. */
    public static final String FACTORY_PID = "org.jahia.modules.mfa.extensions.site";

    static final String PROP_SITE_KEY = "siteKey";
    static final String PROP_LOGIN_URL = "loginUrl";
    static final String PROP_LOGOUT_URL = "logoutUrl";
    static final String SUFFIX_ENABLED = ".enabled";
    static final String SUFFIX_ENABLED_GROUPS = ".enabledGroups";

    private static final Logger logger = LoggerFactory.getLogger(MfaSiteConfigService.class);

    /** A site key must be a safe single path segment (it becomes part of a filename). */
    private static final Pattern SITE_KEY_PATTERN = Pattern.compile("[A-Za-z0-9_-]+");

    private final Map<String, MfaSiteConfig> configs = new ConcurrentHashMap<>();
    private final Map<String, String> pidToSiteKey = new ConcurrentHashMap<>();
    private final AtomicReference<Path> etcDir = new AtomicReference<>();
    private final Object writeLock = new Object();

    @Override
    public String getName() {
        return "MFA per-site configuration";
    }

    @Override
    public void updated(String pid, Dictionary<String, ?> properties) {
        String siteKey = string(properties, PROP_SITE_KEY);
        if (!isValidSiteKey(siteKey)) {
            logger.warn("Ignoring MFA per-site config {} - missing or invalid '{}' property",
                    pid, PROP_SITE_KEY);
            return;
        }
        MfaSiteConfig config = parse(properties);
        configs.put(siteKey, config);
        pidToSiteKey.put(pid, siteKey);
        logger.info("Loaded MFA per-site config for site '{}' (loginUrl={}, factors={})",
                siteKey, config.getLoginUrl(), config.factors().keySet());
    }

    @Override
    public void deleted(String pid) {
        String siteKey = pidToSiteKey.remove(pid);
        if (siteKey != null) {
            configs.remove(siteKey);
            logger.info("Removed MFA per-site config for site '{}'", siteKey);
        }
    }

    /** The snapshot for a site, or {@link MfaSiteConfig#EMPTY} when nothing is configured. */
    public MfaSiteConfig getConfig(String siteKey) {
        if (siteKey == null) {
            return MfaSiteConfig.EMPTY;
        }
        return configs.getOrDefault(siteKey, MfaSiteConfig.EMPTY);
    }

    /** Whether at least one site currently has the given factor enabled (in-memory scan). */
    public boolean anySiteEnabled(String factorType) {
        return configs.values().stream().anyMatch(config -> config.isEnabled(factorType));
    }

    /**
     * Apply {@code merge} to the site's current config (read-modify-write, serialized so two
     * factors never clobber each other's keys in the shared file), then persist: write the file
     * atomically, or delete it when the merged config is all-default. The in-memory map is updated
     * synchronously for immediate read-after-write.
     *
     * @throws IOException when the {@code .cfg} file cannot be written or removed
     */
    public void save(String siteKey, UnaryOperator<MfaSiteConfig> merge) throws IOException {
        if (!isValidSiteKey(siteKey)) {
            throw new IllegalArgumentException("Invalid siteKey (must be a single path segment): " + siteKey);
        }
        synchronized (writeLock) {
            MfaSiteConfig current = configs.getOrDefault(siteKey, MfaSiteConfig.EMPTY);
            MfaSiteConfig merged = merge.apply(current);
            if (merged.isAllDefault()) {
                configs.remove(siteKey);
                deleteFile(siteKey);
                logger.info("Cleared MFA per-site config for site '{}' (now all-default)", siteKey);
            } else {
                configs.put(siteKey, merged);
                writeFile(siteKey, merged);
                logger.info("Saved MFA per-site config for site '{}'", siteKey);
            }
        }
    }

    private MfaSiteConfig parse(Dictionary<String, ?> props) {
        Map<String, MfaSiteConfig.FactorSiteState> factors = new HashMap<>();
        Enumeration<String> keys = props.keys();
        while (keys.hasMoreElements()) {
            String key = keys.nextElement();
            if (key.endsWith(SUFFIX_ENABLED)) {
                String factorType = key.substring(0, key.length() - SUFFIX_ENABLED.length());
                boolean enabled = Boolean.parseBoolean(string(props, key));
                List<String> groups = parseGroups(string(props, factorType + SUFFIX_ENABLED_GROUPS));
                factors.put(factorType, new MfaSiteConfig.FactorSiteState(enabled, groups));
            }
        }
        return new MfaSiteConfig(string(props, PROP_LOGIN_URL), string(props, PROP_LOGOUT_URL), factors);
    }

    private String serialize(String siteKey, MfaSiteConfig config) {
        StringBuilder sb = new StringBuilder();
        sb.append("# MFA per-site configuration - managed by the MFA Community admin UI.\n");
        sb.append(PROP_SITE_KEY).append('=').append(siteKey).append('\n');
        sb.append(PROP_LOGIN_URL).append('=').append(nullToEmpty(config.getLoginUrl())).append('\n');
        sb.append(PROP_LOGOUT_URL).append('=').append(nullToEmpty(config.getLogoutUrl())).append('\n');
        // TreeMap → deterministic key order so the file is stable across writes.
        for (Map.Entry<String, MfaSiteConfig.FactorSiteState> entry
                : new TreeMap<>(config.factors()).entrySet()) {
            MfaSiteConfig.FactorSiteState state = entry.getValue();
            sb.append(entry.getKey()).append(SUFFIX_ENABLED).append('=').append(state.isEnabled()).append('\n');
            sb.append(entry.getKey()).append(SUFFIX_ENABLED_GROUPS).append('=')
                    .append(String.join(",", state.getGroups())).append('\n');
        }
        return sb.toString();
    }

    private void writeFile(String siteKey, MfaSiteConfig config) throws IOException {
        Path dir = etcDirectory();
        Path target = dir.resolve(fileName(siteKey));
        // Temp file in the SAME directory so ATOMIC_MOVE stays on one filesystem.
        Path tmp = Files.createTempFile(dir, FACTORY_PID + "-" + siteKey + "-", ".tmp");
        try {
            Files.write(tmp, serialize(siteKey, config).getBytes(StandardCharsets.UTF_8));
            try {
                Files.move(tmp, target, StandardCopyOption.ATOMIC_MOVE);
            } catch (AtomicMoveNotSupportedException e) {
                logger.debug("ATOMIC_MOVE unsupported, falling back to REPLACE_EXISTING for {}", target);
                Files.move(tmp, target, StandardCopyOption.REPLACE_EXISTING);
            }
        } finally {
            Files.deleteIfExists(tmp);
        }
    }

    private void deleteFile(String siteKey) throws IOException {
        Files.deleteIfExists(etcDirectory().resolve(fileName(siteKey)));
    }

    private static String fileName(String siteKey) {
        return FACTORY_PID + "-" + siteKey + ".cfg";
    }

    /** Resolve and cache {@code karaf.etc}; fail fast (only reached on a write, never on a read). */
    private Path etcDirectory() throws IOException {
        Path dir = etcDir.get();
        if (dir != null) {
            return dir;
        }
        String etc = System.getProperty("karaf.etc");
        if (etc == null) {
            String base = System.getProperty("karaf.base");
            if (base != null) {
                etc = base + "/etc";
            }
        }
        if (etc == null) {
            throw new IOException("Cannot resolve karaf.etc to write MFA per-site configuration");
        }
        Path resolved = Paths.get(etc);
        if (!Files.isDirectory(resolved)) {
            throw new IOException("karaf.etc is not a directory: " + resolved);
        }
        etcDir.set(resolved);
        return resolved;
    }

    private static boolean isValidSiteKey(String siteKey) {
        return siteKey != null && SITE_KEY_PATTERN.matcher(siteKey).matches();
    }

    private static List<String> parseGroups(String raw) {
        List<String> groups = new ArrayList<>();
        if (raw != null) {
            for (String part : raw.split(",")) {
                String group = part.trim();
                if (!group.isEmpty()) {
                    groups.add(group);
                }
            }
        }
        return groups;
    }

    private static String string(Dictionary<String, ?> props, String key) {
        Object value = props == null ? null : props.get(key);
        return value == null ? null : value.toString();
    }

    private static String nullToEmpty(String value) {
        return value == null ? "" : value;
    }
}
