package org.jahia.modules.upa.mfa.webauthn;

import org.junit.Test;

import java.util.Arrays;
import java.util.HashMap;
import java.util.LinkedHashSet;
import java.util.Map;

import static org.junit.Assert.assertEquals;

/**
 * Origin/RP parsing for the WebAuthn factor configuration. The high-stakes rule: when no
 * origins are configured, BOTH https:// and http:// forms of the RP ID must be derived —
 * the yubico library's own default is https-only, which silently breaks every ceremony on
 * plain-http localhost deployments with a server-side "incorrect origin" at finish time.
 * Origins are also self-parsed (comma list + indexed keys) because OSGi String[] properties
 * cannot be expressed reliably in a .cfg file.
 */
public class WebAuthnConfigTest {

    private static WebAuthnConfig activated(Map<String, Object> props) {
        WebAuthnConfig config = new WebAuthnConfig();
        config.activate(props);
        return config;
    }

    @Test
    public void defaultsDeriveHttpAndHttpsLocalhostOrigins() {
        WebAuthnConfig config = activated(new HashMap<>());
        assertEquals("localhost", config.getRpId());
        assertEquals("Jahia", config.getRpName());
        assertEquals(new LinkedHashSet<>(Arrays.asList("https://localhost", "http://localhost")),
                config.getOrigins());
    }

    @Test
    public void derivedOriginsFollowTheConfiguredRpId() {
        Map<String, Object> props = new HashMap<>();
        props.put("rpId", "example.com");
        WebAuthnConfig config = activated(props);
        assertEquals(new LinkedHashSet<>(Arrays.asList("https://example.com", "http://example.com")),
                config.getOrigins());
    }

    @Test
    public void commaSeparatedOriginsOverrideDerivation() {
        Map<String, Object> props = new HashMap<>();
        props.put("origins", " https://example.com , https://www.example.com ");
        WebAuthnConfig config = activated(props);
        assertEquals(new LinkedHashSet<>(Arrays.asList("https://example.com", "https://www.example.com")),
                config.getOrigins());
    }

    @Test
    public void indexedOriginKeysAreCollectedInOrder() {
        Map<String, Object> props = new HashMap<>();
        props.put("origins.0", "https://example.com");
        props.put("origins.1", "http://localhost:8080");
        WebAuthnConfig config = activated(props);
        assertEquals(new LinkedHashSet<>(Arrays.asList("https://example.com", "http://localhost:8080")),
                config.getOrigins());
    }

    @Test
    public void blankOriginsValueStillDerivesFromRpId() {
        Map<String, Object> props = new HashMap<>();
        props.put("origins", "   ");
        WebAuthnConfig config = activated(props);
        assertEquals(new LinkedHashSet<>(Arrays.asList("https://localhost", "http://localhost")),
                config.getOrigins());
    }

    @Test
    public void nullPropertiesKeepDefaults() {
        WebAuthnConfig config = activated(null);
        assertEquals("localhost", config.getRpId());
        assertEquals(new LinkedHashSet<>(Arrays.asList("https://localhost", "http://localhost")),
                config.getOrigins());
    }
}
