package org.jahia.modules.upa.mfa.extensions.internal;

import org.apache.commons.lang3.StringUtils;
import org.jahia.modules.upa.mfa.extensions.MfaGlobalPolicy;
import org.jahia.modules.upa.mfa.extensions.MfaSiteConfigService;
import org.jahia.modules.upa.mfa.extensions.MfaSiteProvider;
import org.osgi.service.component.annotations.Activate;
import org.osgi.service.component.annotations.Component;
import org.osgi.service.component.annotations.Modified;
import org.osgi.service.component.annotations.Reference;
import org.osgi.service.component.annotations.ReferenceCardinality;
import org.osgi.service.component.annotations.ReferencePolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicReference;
import java.util.regex.Pattern;

/**
 * The shared, request-time decision logic that gates Jahia's legacy login endpoint
 * ({@code /cms/login}) while ANY MFA factor enforces enrollment. It is consulted by BOTH access
 * points that protect that endpoint:
 * <ul>
 *   <li>{@link MfaLoginGateAuthValve} - a Jahia authentication valve inserted BEFORE the
 *       password-login valve, which is the only place that can block a {@code /cms/login}
 *       <b>POST</b> before a session is established (the servlet filter runs too late for POST -
 *       see that class);</li>
 *   <li>{@link MfaLoginGateFilter} - the servlet filter that remains as defense-in-depth, mainly
 *       effective for GET requests with no credentials to authenticate.</li>
 * </ul>
 * <p>
 * The MFA challenge runs in UPA's GraphQL {@code initiate} flow (used by the factor login UI) -
 * but {@code /cms/login} authenticates through Jahia's classic username/password valve and never
 * consults MFA factors. On a site that <i>enforces</i> enrollment, that endpoint is therefore a
 * complete second-factor bypass. The gating contract:
 * <ul>
 *   <li>nothing is gated while the global enforcement policy ({@link MfaGlobalPolicy}) lists no
 *       factors;</li>
 *   <li>requests carrying a site context (the {@code site} request parameter or the
 *       {@code siteKey} request attribute) are gated when THAT site has one of the globally
 *       enforced factors {@code enabled};</li>
 *   <li>requests with no site context (the common case for {@code /cms/login}) are gated when
 *       ANY site has an enforced factor enabled - the endpoint authenticates globally, so a
 *       single such site is enough to make it a bypass vector;</li>
 *   <li>gated requests are exempt when the client IP matches the configured whitelist, so
 *       operators keep an emergency/back-office door (e.g. their VPN range).</li>
 * </ul>
 * <p>
 * This component is factor-agnostic: it discovers per-site activation through every registered
 * {@link MfaSiteProvider} (TOTP, WebAuthn, ...) and intersects it with the global policy. It
 * therefore has no compile-time dependency on any individual factor module.
 * <p>
 * The client IP is taken from the FIRST entry of the {@code X-Forwarded-For} header when present
 * (the original client, by convention), falling back to the socket address - but ONLY when
 * {@code loginGate.trustForwardedFor} is {@code true} (the default, for backward-compat).
 * <b>Trust caveat:</b> {@code X-Forwarded-For} is client-spoofable - only trust it behind a
 * reverse proxy that overwrites (or sanitizes) the header, otherwise an attacker can impersonate
 * a whitelisted IP with a single forged header. Set {@code loginGate.trustForwardedFor=false} to
 * always use the (spoof-proof) socket address {@code request.getRemoteAddr()} instead.
 * <p>
 * Configuration (PID {@code org.jahia.modules.mfa.extensions}, hot-reloaded via {@code @Modified}):
 * <ul>
 *   <li>{@code loginGate.enabled} - the explicit HARD gate switch (consumed by the servlet filter
 *       to choose between redirect-or-403 and the automatic mode), default {@code false}. Note the
 *       valve blocks a gated password login regardless of this switch: the POST bypass must always
 *       be closed when a site enforces MFA.</li>
 *   <li>{@code loginGate.ipWhitelist} - comma-separated IPv4/IPv6 addresses or CIDR blocks
 *       (e.g. {@code 203.0.113.7, 10.0.0.0/8, 2001:db8::/32}).</li>
 *   <li>{@code loginGate.trustForwardedFor} - whether to read the client IP from the
 *       {@code X-Forwarded-For} header, default {@code true} (backward-compat).</li>
 * </ul>
 * <p>
 * A provider that cannot answer (e.g. an unhealthy repository) throws, and the gate fails
 * <b>closed</b> (block): this is an access-control decision, and if the backend is unhealthy the
 * login could not complete anyway.
 */
@Component(service = MfaLoginGateDecision.class, immediate = true,
        configurationPid = "org.jahia.modules.mfa.extensions")
public class MfaLoginGateDecision {

    private static final Logger logger = LoggerFactory.getLogger(MfaLoginGateDecision.class);

    static final String CONFIG_GATE_ENABLED = "loginGate.enabled";
    static final String CONFIG_GATE_WHITELIST = "loginGate.ipWhitelist";
    static final String CONFIG_TRUST_FORWARDED_FOR = "loginGate.trustForwardedFor";

    private static final String HEADER_X_FORWARDED_FOR = "X-Forwarded-For";
    private static final String PARAM_SITE = "site";
    private static final String ATTR_SITE_KEY = "siteKey";

    /** Valid Jahia site keys - also prevents JCR path traversal via the user-supplied parameter. */
    private static final Pattern SITE_KEY_PATTERN = Pattern.compile("[A-Za-z0-9_-]+");
    private static final Pattern IPV4_PATTERN = Pattern.compile("\\d{1,3}(\\.\\d{1,3}){3}");
    /** IPv6 literal (possibly v4-mapped). The ':' requirement rules out hostnames - labels cannot contain it. */
    private static final Pattern IPV6_PATTERN = Pattern.compile("[0-9a-fA-F:.]*:[0-9a-fA-F:.]*");

    /** How long the "is any site enforcing?" answer is reused before re-querying the providers. */
    private static final long ENFORCING_CACHE_MILLIS = 60_000L;

    private final AtomicBoolean gateEnabled = new AtomicBoolean(false);
    /** Trust the {@code X-Forwarded-For} header for the client IP; default {@code true} (back-compat). */
    private final AtomicBoolean trustForwardedFor = new AtomicBoolean(true);
    private final AtomicReference<List<String>> whitelist = new AtomicReference<>(Collections.emptyList());
    private final AtomicReference<EnforcingCache> enforcingCache = new AtomicReference<>();

    /** Every registered factor's per-site activation view. Read-heavy on the request path -> copy-on-write. */
    private final List<MfaSiteProvider> siteProviders = new CopyOnWriteArrayList<>();

    /** The global enforcement policy (same bundle, same configuration PID). */
    private MfaGlobalPolicy globalPolicy;

    /** Resolves the configured login URL (per-site -> global). */
    private MfaLoginLogoutProvider loginLogoutProvider;

    /**
     * The per-site config service; consulted ONLY for its {@link MfaSiteConfigService#isReady()}
     * readiness flag so BOTH gating paths (resolved-site and no-site) can fail CLOSED during the
     * startup window before FileInstall/the eager scan has populated the map. May be {@code null}
     * in a unit test that does not exercise the readiness path (treated as ready).
     */
    private MfaSiteConfigService siteConfigService;

    @Reference
    public void setGlobalPolicy(MfaGlobalPolicy globalPolicy) {
        this.globalPolicy = globalPolicy;
    }

    @Reference
    public void setLoginLogoutProvider(MfaLoginLogoutProvider loginLogoutProvider) {
        this.loginLogoutProvider = loginLogoutProvider;
    }

    @Reference
    public void setSiteConfigService(MfaSiteConfigService siteConfigService) {
        this.siteConfigService = siteConfigService;
    }

    @Reference(service = MfaSiteProvider.class,
            cardinality = ReferenceCardinality.MULTIPLE,
            policy = ReferencePolicy.DYNAMIC)
    public void bindSiteProvider(MfaSiteProvider provider) {
        siteProviders.add(provider);
        enforcingCache.set(null); // a new factor may change the global enforcement answer
    }

    public void unbindSiteProvider(MfaSiteProvider provider) {
        siteProviders.remove(provider);
        enforcingCache.set(null);
    }

    @Activate
    @Modified
    public void activate(Map<String, Object> properties) {
        boolean enabled = properties != null
                && Boolean.parseBoolean(String.valueOf(properties.get(CONFIG_GATE_ENABLED)));
        List<String> entries = parseWhitelist(properties == null ? null : properties.get(CONFIG_GATE_WHITELIST));
        boolean trustXff = parseTrustForwardedFor(properties);
        gateEnabled.set(enabled);
        whitelist.set(entries);
        trustForwardedFor.set(trustXff);
        enforcingCache.set(null); // settings may have changed semantics; re-query on next hit
        logger.info("MFA /cms/login gate {} ({} whitelist entr{})",
                enabled ? "ENABLED" : "disabled", entries.size(), entries.size() == 1 ? "y" : "ies");
        if (!entries.isEmpty() && trustXff) {
            logger.info("MFA /cms/login gate: a whitelist is set and {} is true - the client IP is taken "
                    + "from X-Forwarded-For, which is client-spoofable. Only keep this enabled behind a "
                    + "reverse proxy that overwrites the header, or set {}=false.",
                    CONFIG_TRUST_FORWARDED_FOR, CONFIG_TRUST_FORWARDED_FOR);
        }
    }

    /** {@code loginGate.trustForwardedFor}; default {@code true} for backward-compatibility. */
    private static boolean parseTrustForwardedFor(Map<String, Object> properties) {
        if (properties == null) {
            return true;
        }
        Object raw = properties.get(CONFIG_TRUST_FORWARDED_FOR);
        return raw == null || Boolean.parseBoolean(String.valueOf(raw));
    }

    /**
     * Parse the comma-separated whitelist, dropping (and logging) syntactically invalid entries.
     * Public so the administration mutation can validate submitted values (the class itself is
     * internal/unexported).
     */
    public static List<String> parseWhitelist(Object raw) {
        if (raw == null || StringUtils.isBlank(raw.toString())) {
            return Collections.emptyList();
        }
        List<String> entries = new ArrayList<>();
        for (String part : raw.toString().split(",")) {
            String entry = part.trim();
            if (entry.isEmpty()) {
                continue;
            }
            if (isValidWhitelistEntry(entry)) {
                entries.add(entry);
            } else {
                logger.warn("Ignoring invalid {} entry: '{}' (expected an IPv4/IPv6 address or CIDR block)",
                        CONFIG_GATE_WHITELIST, entry);
            }
        }
        return Collections.unmodifiableList(entries);
    }

    /** Whether the explicit HARD gate switch ({@code loginGate.enabled}) is on. */
    public boolean isHardGateEnabled() {
        return gateEnabled.get();
    }

    /**
     * Whether this request must be gated: global enforcement is active AND the request's site
     * (when identifiable) has one of the enforced factors enabled, or - with no site context -
     * any site does. Fails CLOSED when a provider cannot answer (throws).
     */
    public boolean isGated(HttpServletRequest request) {
        if (!globalPolicy.isEnforcementActive()) {
            return false;
        }
        // During the startup window the per-site config map may not be populated yet (FileInstall is
        // async) and the eager scan may not have run, so BOTH the resolved-site and the no-site
        // branches below could report "not enforcing" off an empty map and let /cms/login through
        // password-only - a fail-OPEN bypass. Enforcement is active here, so fail CLOSED until the
        // config service is ready, regardless of whether the request carries a site context.
        if (siteConfigService != null && !siteConfigService.isReady()) {
            logger.debug("MFA /cms/login gate: per-site config not ready yet (startup), failing CLOSED "
                    + "while enforcement is active");
            return true;
        }
        String siteKey = resolveSiteKey(request);
        if (siteKey != null) {
            return anyEnforcesForSite(siteKey);
        }
        // No resolvable site: the "any site enforcing?" decision over every site.
        return isAnySiteEnforcingCached();
    }

    /** Whether the request's client IP matches the configured whitelist (the emergency door). */
    public boolean isClientWhitelisted(HttpServletRequest request) {
        String clientIp = resolveClientIp(request, trustForwardedFor.get());
        return isWhitelisted(clientIp, whitelist.get());
    }

    /**
     * The configured MFA login URL to redirect a blocked request to (per-site -> global, resolved by
     * {@link MfaLoginLogoutProvider} with the {@code redirect=} return-to-target already appended),
     * or {@code null} when none is configured or when the configured URL is {@code /cms/login}
     * itself - in which case redirecting there would loop and the caller should fall back to a 403.
     */
    public String resolveDistinctLoginUrl(HttpServletRequest request) {
        String configuredLogin = loginLogoutProvider.getLoginUrl(request);
        if (configuredLogin == null || isCmsLogin(configuredLogin, request.getContextPath())) {
            return null;
        }
        return configuredLogin;
    }

    /**
     * Whether the operator deliberately configured {@code /cms/login} itself as the (per-site or
     * global) login URL. The automatic mode uses this to tell "keep the default screen" apart from
     * "no login URL configured at all" - {@link #resolveDistinctLoginUrl} returns {@code null} for
     * both, but only the former should pass through to the password-only screen.
     */
    public boolean isCmsLoginConfigured(HttpServletRequest request) {
        String configuredLogin = loginLogoutProvider.getLoginUrl(request);
        return isCmsLogin(configuredLogin, request.getContextPath());
    }

    /**
     * Gated if any globally-enforced factor is enabled for {@code siteKey}; a throwing provider
     * fails CLOSED. Package-visible for tests.
     */
    boolean anyEnforcesForSite(String siteKey) {
        for (MfaSiteProvider provider : siteProviders) {
            try {
                if (globalPolicy.isEnforced(provider.getFactorType()) && provider.isEnabledForSite(siteKey)) {
                    return true;
                }
            } catch (RuntimeException e) {
                logger.error("MFA /cms/login gate: provider {} failed for site '{}' (failing CLOSED, request "
                        + "blocked). Cause: {}", provider.getClass().getName(), siteKey, e.getMessage());
                return true;
            }
        }
        return false;
    }

    /** The {@code site} parameter (validated) or the {@code siteKey} attribute, else {@code null}. */
    private static String resolveSiteKey(HttpServletRequest request) {
        String param = StringUtils.trimToNull(request.getParameter(PARAM_SITE));
        if (param != null && SITE_KEY_PATTERN.matcher(param).matches()) {
            return param;
        }
        Object attr = request.getAttribute(ATTR_SITE_KEY);
        if (attr instanceof String && StringUtils.isNotBlank((String) attr)) {
            return (String) attr;
        }
        return null;
    }

    private boolean isAnySiteEnforcingCached() {
        long now = System.currentTimeMillis();
        EnforcingCache cached = enforcingCache.get();
        if (cached != null && (now - cached.timestamp) < ENFORCING_CACHE_MILLIS) {
            return cached.enforcing;
        }
        // The gate sits on an unauthenticated endpoint: cache the answer briefly so a login
        // brute-force cannot be amplified into a query flood. A fail-closed result is cached too -
        // brief over-blocking during a backend outage is the safe direction for an access gate.
        boolean enforcing = computeAnySiteEnforcing();
        enforcingCache.set(new EnforcingCache(now, enforcing));
        return enforcing;
    }

    /**
     * True if any globally-enforced factor is enabled on at least one site; a throwing provider
     * fails CLOSED. Package-visible for tests.
     */
    boolean computeAnySiteEnforcing() {
        for (MfaSiteProvider provider : siteProviders) {
            try {
                if (globalPolicy.isEnforced(provider.getFactorType()) && provider.isAnySiteEnabled()) {
                    return true;
                }
            } catch (RuntimeException e) {
                logger.error("MFA /cms/login gate: provider {} failed the global enforcement check (failing "
                        + "CLOSED, request blocked). Cause: {}", provider.getClass().getName(), e.getMessage());
                return true;
            }
        }
        return false;
    }

    /**
     * The client IP for whitelist matching. When {@code trustForwardedFor} is {@code true} (the
     * default), the FIRST {@code X-Forwarded-For} entry is used when the header is present (the
     * original client, by convention - later entries are proxies), otherwise the socket address.
     * When {@code false}, the (spoof-proof) socket address {@link HttpServletRequest#getRemoteAddr}
     * is ALWAYS used, ignoring the header - for deployments not behind a header-overwriting proxy.
     */
    static String resolveClientIp(HttpServletRequest request, boolean trustForwardedFor) {
        if (trustForwardedFor) {
            String forwarded = request.getHeader(HEADER_X_FORWARDED_FOR);
            if (StringUtils.isNotBlank(forwarded)) {
                return forwarded.split(",")[0].trim();
            }
        }
        return request.getRemoteAddr();
    }

    /** Whether the client IP matches any whitelist entry (exact address or CIDR block). */
    static boolean isWhitelisted(String clientIp, List<String> entries) {
        if (entries.isEmpty() || !isIpLiteral(clientIp)) {
            // Never DNS-resolve the (attacker-controlled) header value: a hostname-looking
            // X-Forwarded-For must simply not match.
            return false;
        }
        byte[] client = parseAddress(clientIp);
        if (client == null) {
            return false;
        }
        for (String entry : entries) {
            if (entryMatches(client, entry)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isValidWhitelistEntry(String entry) {
        String address = entry;
        int slash = entry.indexOf('/');
        if (slash >= 0) {
            address = entry.substring(0, slash);
            String prefix = entry.substring(slash + 1);
            byte[] raw = isIpLiteral(address) ? parseAddress(address) : null;
            if (raw == null) {
                return false;
            }
            try {
                int bits = Integer.parseInt(prefix);
                return bits >= 0 && bits <= raw.length * 8;
            } catch (NumberFormatException e) {
                return false;
            }
        }
        return isIpLiteral(address) && parseAddress(address) != null;
    }

    private static boolean entryMatches(byte[] client, String entry) {
        int slash = entry.indexOf('/');
        String address = slash >= 0 ? entry.substring(0, slash) : entry;
        byte[] base = parseAddress(address);
        if (base == null || base.length != client.length) {
            return false; // mixed v4/v6 never match
        }
        int prefixBits = slash >= 0 ? Integer.parseInt(entry.substring(slash + 1)) : base.length * 8;
        return prefixMatches(client, base, prefixBits);
    }

    private static boolean prefixMatches(byte[] client, byte[] base, int prefixBits) {
        int fullBytes = prefixBits / 8;
        for (int i = 0; i < fullBytes; i++) {
            if (client[i] != base[i]) {
                return false;
            }
        }
        int remainder = prefixBits % 8;
        if (remainder == 0) {
            return true;
        }
        int mask = 0xFF << (8 - remainder);
        return (client[fullBytes] & mask) == (base[fullBytes] & mask);
    }

    /**
     * True only for strings that are syntactically IP literals - {@link InetAddress#getByName}
     * would DNS-resolve a hostname, which must never happen for attacker-controlled input.
     * IPv4 octets are range-checked too: {@code 192.168.1.256} is NOT a literal and would
     * otherwise fall through to a DNS lookup. Strings containing {@code ':'} can never be
     * hostnames (the character is illegal in DNS labels), so the IPv6 branch is safe as-is.
     */
    static boolean isIpLiteral(String value) {
        if (StringUtils.isBlank(value)) {
            return false;
        }
        if (IPV4_PATTERN.matcher(value).matches()) {
            for (String octet : value.split("\\.")) {
                if (Integer.parseInt(octet) > 255) {
                    return false;
                }
            }
            return true;
        }
        return IPV6_PATTERN.matcher(value).matches();
    }

    /** Parse an IP literal to raw bytes, or {@code null} when malformed. */
    private static byte[] parseAddress(String literal) {
        try {
            return InetAddress.getByName(literal).getAddress();
        } catch (UnknownHostException | IllegalArgumentException e) {
            return null;
        }
    }

    /** Whether the configured login URL is {@code /cms/login} itself - the operator's explicit choice. */
    static boolean isCmsLogin(String url, String contextPath) {
        if (url == null) {
            return false;
        }
        String path = StringUtils.substringBefore(url, "?");
        if (StringUtils.isNotEmpty(contextPath) && path.startsWith(contextPath)) {
            path = path.substring(contextPath.length());
        }
        return path.equals("/cms/login");
    }

    /** Immutable timestamped snapshot of the "any site enforcing?" answer. */
    private static final class EnforcingCache {
        private final long timestamp;
        private final boolean enforcing;

        private EnforcingCache(long timestamp, boolean enforcing) {
            this.timestamp = timestamp;
            this.enforcing = enforcing;
        }
    }
}
