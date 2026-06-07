# MFA factors

Third-party Jahia modules adding extra second factors to the
[User Password Authentication (UPA)](https://github.com/Jahia/user-password-authentication)
Multi-Factor Authentication framework. The reactor builds a family of `mfa-factors-*` modules
that share one sign-in UI:

| Module | artifactId | What it adds |
| --- | --- | --- |
| `extensions/` | `mfa-factors-extensions` | Shared, factor-agnostic infrastructure: the `/cms/login` gate, the login/logout URL provider, the backup-code generator, and the `MfaSiteProvider` SPI each factor implements. Has no UI. |
| `totp/` | `mfa-factors-totp` | TOTP (RFC 6238) factor: authenticator-app codes + one-shot backup codes; per-site policy. |
| `webauthn/` | `mfa-factors-webauthn` | WebAuthn / FIDO2 factor: passkeys, security keys, platform authenticators (fingerprint/face). Phishing-resistant, origin-bound. Built on `com.yubico:webauthn-server-core` (embedded). |
| `login-ui/` | `mfa-factors-login-ui` | Shared JS-SDK sign-in UI: username/password → factor chooser → TOTP / WebAuthn / email verification. |

The reactor root is `mfa-community-parent`. The two factor modules (`totp`, `webauthn`) depend on
`mfa-factors-extensions` (`jahia-depends`), which therefore starts first.

Each factor ships its own self-service dashboard panel. Site administration groups everything
under one **MFA Community** entry:

- **Extensions** — the per-site login/logout routing consumed by the shared login provider;
- **Two-factor authentication** — TOTP policy (enable / group scoping, user reset; enforcement
  is global — see `enforcedFactors`);
- **Security and passkeys** — WebAuthn policy (same shape);
- **Audit & reporting** — every installed factor's audit log and enrollment/registration report
  on a single page (each factor contributes its section; the page shows whatever is installed).

## Requirements

- Jahia 8.2.3+
- `user-password-authentication-api` 0.3.0+ (the UPA module must be installed and started)
- `graphql-dxm-provider` 3.4+
- Java 11+

## Installation

1. Build the project (`mvn clean install` at the repo root builds all modules):
   - `extensions/target/mfa-factors-extensions-<version>.jar` &mdash; the shared infrastructure
     bundle (the `/cms/login` gate, login/logout URL provider, backup-code generator). Required
     by both factor bundles; deploy it too.
   - `totp/target/mfa-factors-totp-<version>.jar` &mdash; the TOTP OSGi factor bundle.
   - `webauthn/target/mfa-factors-webauthn-<version>.jar` &mdash; the WebAuthn OSGi factor
     bundle (a ~6&nbsp;MB fat bundle; it embeds the yubico WebAuthn library).
   - `login-ui/target/mfa-factors-login-ui-<version>.tgz` &mdash; the sign-in UI (optional;
     install only if you want the bundled login template). The `.tgz` is an npm/JS-SDK
     package and must be installed via the Jahia provisioning API or the Modules UI &mdash;
     it is **not** picked up by the `digital-factory-data/modules/` hot-deploy folder.
2. Drop the bundle JAR(s) into Jahia's `digital-factory-data/modules/` directory, or upload them
   from the Jahia administration UI (*Server settings* &rarr; *Modules*). Install only the
   factors you want.
3. Make sure the `user-password-authentication` module is started first; these modules
   declare it as a hard dependency (`jahia-depends`).
4. Enable the factors you installed in `org.jahia.modules.upa` → `mfaEnabledFactors`
   (e.g. `totp`, `webauthn`), then enable them per site from each factor's administration page.

## Configuration

The **shared infrastructure** is configured under PID `org.jahia.modules.mfa.extensions`
(shipped by the extensions bundle). It can be edited from the UI — *Administration → Server →
Configuration → MFA Community* (server administrators) — or directly in the Karaf file:

- `extensions/src/main/resources/META-INF/configurations/org.jahia.modules.mfa.extensions.cfg`

| Key | Default | Effect |
| --- | --- | --- |
| `loginUrl` | _(empty)_ | **Global default** login URL. When resolved, `MfaLoginLogoutProvider` makes Jahia redirect unauthenticated users to this page instead of `/cms/login` — point it at the page that renders the `totpui:authentication` login UI (e.g. `/sites/mySite/login.html`). |
| `logoutUrl` | _(empty)_ | **Global default** custom sign-out page. |
| `loginGate.enabled` | `false` | Master switch for the `/cms/login` gate (see below). |
| `loginGate.ipWhitelist` | _(empty)_ | Comma-separated IPv4/IPv6 addresses or CIDR blocks allowed through the gate (e.g. `203.0.113.7, 10.0.0.0/8, 2001:db8::/32`). |

Each **factor** keeps its own PID for factor-specific keys. TOTP (`org.jahia.modules.totp`,
shipped by `totp/src/main/resources/META-INF/configurations/org.jahia.modules.totp.cfg`):

| Key | Default | Effect |
| --- | --- | --- |
| `secret.encryption.key` | _(empty)_ | Base64 256-bit AES key for encrypting TOTP secrets at rest. Empty = a key is auto-generated and persisted under `<jahiaVarDir>/mfa-factors/secret.key`. |

> **Migration note:** the `loginUrl` / `logoutUrl` and `loginGate.*` keys moved from
> `org.jahia.modules.totp` to `org.jahia.modules.mfa.extensions`. Existing deployments must
> copy any customized values to the new PID.

Each module also ships an OSGi authorization configuration granting its GraphQL types to all
callers (the actual authentication / rate limiting happens at the resolver level), e.g.
`totp/src/main/resources/META-INF/configurations/org.jahia.bundles.api.authorization-mfa-factors-totp.yml`.

`MfaLoginLogoutProvider` (in the extensions bundle) implements Jahia's `LoginUrlProvider` /
`LogoutUrlProvider` SPI. URLs are resolved **per request** with this precedence: a **per-site**
`loginUrl` / `logoutUrl` reported by any factor through the `MfaSiteProvider` SPI (TOTP surfaces
the values set from the site's *MFA Community → Extensions* administration page, stored on the
`upaTotp:siteSettings` mixin) → the **global** `.cfg` value above → Jahia's default. When nothing
is configured for a site the provider returns nothing, so deploying the module never hijacks
login on its own. Global `.cfg` edits are applied live (no restart); per-site values take effect
immediately on save.

**Return-to-target (`redirect=`):** the provider appends a `redirect=` parameter to the
login/logout URL it serves, carrying the page the user was actually after — the URL whose 401
triggered the redirect (read from the servlet ERROR/FORWARD dispatch attributes) or an explicit
`redirect=` parameter already present on a `/cms/login` / `/cms/logout` link. After a successful
sign-in the login UI sends the user there instead of the site root. The parameter is validated
on BOTH sides against open redirects (server: the same `MfaUrls` chokepoint; client: same-origin
check in `services/redirect.tsx`); an operator-hardcoded `redirect=` in the configured URL is
left untouched.

**Open-redirect guard:** per-site URLs must be server-relative paths starting with `/`
(e.g. `/sites/mySite/login.html`). Absolute (`https://…`), protocol-relative (`//host`,
`/\host`) and scheme-carrying (`javascript:`) values are rejected at save time, and any
pre-existing unsafe value is ignored at resolve time — a site administrator can never point
the login redirect off-site. The global `.cfg` values are operator-controlled (filesystem
trust level) and are not restricted, so an external SSO portal remains possible globally.

### Global enforcement (`enforcedFactors` / `graceDays`)

Enforcement is **platform-wide**: `enforcedFactors` (PID `org.jahia.modules.mfa.extensions`)
lists the factor types a user must satisfy — a user needs **at least one** of them configured
and verifies **one** of them at sign-in (the chooser lets them pick; the others skip). The
chooser only offers the factors the user actually **configured** (read post-password via the
`mfaSessionFactors` GraphQL query, scoped to the session's own user) — with a single configured
factor the chooser is skipped entirely; a skipped (drained) factor never satisfies pick-one for
its siblings, so a real challenge always happens for users who own one. A user
with **none** configured may still sign in during the global `graceDays` window (0–365, clamped;
tracked per user from their first enforced sign-in attempt); after that, the login page walks
them through **inline enrollment** (TOTP QR + code, or passkey registration) and signs them in
in the same flow. Empty `enforcedFactors` (the default) = no enforcement.

> **Migration note:** the per-site *Enforce enrollment* checkbox and *grace period* were removed
> from both factor administration pages. Existing per-site `upaTotp:enforced` /
> `upaWebauthn:enforced` / `…graceDays` values become inert after upgrade (the CND retains the
> properties; nothing reads them). Operators opt in by setting `enforcedFactors` globally —
> per-site `enabled` + group scoping still applies.

> **UPA prerequisite for several factors:** UPA's `mfaEnabledFactors` (PID
> `org.jahia.modules.upa`) is an OSGi `String[]` and CANNOT hold several values in a plain
> `.cfg` file — `mfaEnabledFactors=totp,webauthn` becomes ONE bogus element and silently
> disables MFA, and indexed keys (`mfaEnabledFactors.0=…`) fall back to the `email_code`
> default. Use a Felix **typed `.config` file** instead (replacing the `.cfg`, same PID):
> `<karaf>/etc/org.jahia.modules.upa.config` containing
> `mfaEnabledFactors=["totp","webauthn"]` — verified to yield both factors. A single factor
> works fine in the `.cfg` (`mfaEnabledFactors=totp`).

> **Every enforced factor MUST also be listed in `mfaEnabledFactors`.** UPA only challenges
> the factors it requires. If a factor is in `enforcedFactors` but not in `mfaEnabledFactors`,
> a user who configured **only that factor** satisfies pick-one (the required factors skip)
> while the factor itself is never verified — the sign-in completes on password alone. The
> factor providers log a `WARN` (*"…is not in UPA's mfaEnabledFactors — this sign-in completes
> WITHOUT a second-factor challenge"*) when this happens.

### UPA's built-in email factor (`email_code`)

UPA ships an email one-time-code factor of its own (`email_code`: a 6-digit code sent to the
user's `j:email` profile property — no enrollment concept). It can be offered as a **pick-one
alternative** next to TOTP and WebAuthn by listing it in **both** places:

```
# <karaf>/etc/org.jahia.modules.upa.config        (typed .config — see the note above)
mfaEnabledFactors=["totp","webauthn","email_code"]

# PID org.jahia.modules.mfa.extensions
enforcedFactors = totp,webauthn,email_code
```

The login chooser then offers *Email code* to every user whose profile carries an email
address, and verifying **any one** factor completes the sign-in. Two pieces in the extensions
bundle make this work — UPA's provider lives in an unexported package and knows nothing about
the pick-one protocol:

- **`EmailCodeFactorAdapter`** (an `MfaSiteProvider`) makes the factor visible to the shared
  infrastructure: the chooser filter counts a non-blank `j:email` as "configured", the factor
  appears in the administration UI's enforcement options, and owning an email address counts
  as "owning an enforced factor" (which also closes pre-auth inline enrollment for those
  users — correct, since they can sign in with the email challenge and enroll a stronger
  factor from their dashboard). It is **not inline-enrollable**: the sign-in flow cannot add
  an email address to a profile.
- **`MfaForeignFactorDrain`** wraps the TOTP/WebAuthn verify mutations: after a **genuine**
  verification of an enforced factor it marks the still-required `email_code` verified (with
  the usual skip marker, so it never satisfies pick-one for anyone else) and finishes the
  authentication. Without it UPA would keep requiring the email challenge **in addition** to
  the factor the user picked — UPA requires *every* factor in `mfaEnabledFactors` and its
  email provider never skips itself. The reverse direction needs no help: after a genuine
  email verification the native factors skip themselves. Choosing TOTP/WebAuthn therefore
  sends **no email at all**.

Prerequisites: Jahia's **mail service** must be configured (Administration → Server →
Notifications) — a user picking *Email code* with a broken SMTP setup sees a clear
`sending_validation_code_failed` error. Users without an email address are simply not offered
the option. With `email_code` enabled in UPA but **not** listed in `enforcedFactors`, UPA's
vanilla semantics stand: every login requires the email challenge on top of everything else
(the drain only spans the enforced set).

### The `/cms/login` gate

Jahia's legacy `/cms/login` endpoint authenticates with username/password only — it never
consults MFA factors. While enforcement is active it is therefore a complete second-factor
bypass. `MfaLoginGateFilter` (in the extensions bundle; a Jahia `AbstractServletFilter` running
before the authentication valve, so blocked requests never get a session) closes it. It is
factor-agnostic — it intersects the global policy with every factor's `MfaSiteProvider`:

- nothing is gated while `enforcedFactors` is empty;
- requests carrying a site context (`?site=<key>` parameter or the `siteKey` request
  attribute) are gated when **that site** has one of the **enforced** factors **enabled**;
- requests with no site context — the common case — are gated when **any** site has an
  enforced factor enabled (`/cms/login` authenticates globally, so one such site is enough);
- a client IP matching `loginGate.ipWhitelist` always passes (emergency/back-office door,
  e.g. your VPN range) — in both modes below.

Gated, non-whitelisted requests are handled in one of two modes:

- **automatic** (always on while enforcement is active): `/cms/login` stays reachable **only
  when the operator explicitly configured it as the login URL** (global or per-site). With a
  custom MFA login page configured, the request is **302-redirected** there (carrying the
  `redirect=` return-to-target); with **no** login URL configured at all it is rejected with
  **403** and a configuration-guidance warning — enforcement with the default password-only
  screen reachable would silently void the second factor;
- **explicit hard gate** (`loginGate.enabled=true`): always **HTTP 403**, regardless of any
  configured login URL — the strictest, opt-in behavior.

The client IP is the **first `X-Forwarded-For` entry** when present, else the socket
address. **Security:** `X-Forwarded-For` is client-spoofable — only rely on the whitelist
behind a reverse proxy that overwrites the header. The hard gate is **off by default**:
enabling it with an empty whitelist locks everyone (including platform administrators) out of
`/cms/login` as soon as one site enforces enrollment — set the whitelist first, then flip
`loginGate.enabled=true`. JCR errors fail **closed** (request blocked).

Tunable security constants (`DRIFT_WINDOWS`, `TIME_STEP_SECONDS`, `DIGITS`, PBKDF2
iterations, ...) live in `TotpService` and `BackupCodes`. To change them, fork and rebuild.

## WebAuthn factor

The `mfa-factors-webauthn` bundle adds a phishing-resistant, origin-bound second factor:
passkeys, security keys (USB/NFC/BLE) and platform authenticators (Touch ID / Windows Hello).
Users register one or more authenticators from the dashboard (*Security keys & passkeys*);
at login the browser performs an assertion ceremony — the private key never leaves the device,
and the assertion is bound to the site's origin so it cannot be relayed by a phishing proxy.

It ships its own per-site administration page (*MFA Community → Security and passkeys*: enable /
groups, user reset; enforcement is global — see `enforcedFactors`) mirroring TOTP, contributes
its registration report to the shared *Audit & reporting* page, and credentials are stored as
`upaWebauthn:credential` child nodes on the user. Clone detection is enforced via the
authenticator signature counter, persisted atomically on each assertion.

Configuration (Karaf PID `org.jahia.modules.webauthn`):

| Key | Default | Effect |
| --- | --- | --- |
| `rpId` | `localhost` | The WebAuthn **Relying Party ID** — a registrable suffix of the browsing origin's host (host only, no scheme/port), e.g. `example.com`. Credentials are scoped to it. |
| `rpName` | `Jahia` | Human-readable site name shown by the authenticator during registration. |
| `origins` | _(derived)_ | Comma-separated full allowed origins (`scheme://host[:port]`); indexed `origins.N=…` keys are accepted too. Any port is tolerated. Leave unset to derive **both** `https://<rpId>` and `http://<rpId>` (the http form only ever matters on localhost-style hosts — the one place browsers allow WebAuthn without TLS). |

> **WebAuthn requires a secure context.** Ceremonies run only over **HTTPS**, except on
> `http://localhost`. Set `rpId`/`origins` to match the host users actually browse (e.g.
> `rpId=example.com`, `origins=https://example.com`); a mismatch makes the browser refuse the
> ceremony with a `SecurityError` (the login UI shows *"Could not register your authenticator"*).
> Behind a reverse proxy, Tomcat must also see the real scheme/host (configure
> `RemoteIpValve`) so the server-side origin check agrees with the browser.

## GraphQL API

All mutations are exposed under `Mutation.upa.mfa.factors.totp`:

| Mutation | Arguments | Returns |
| --- | --- | --- |
| `enroll` | `force: Boolean`, `currentCode: String` | `MfaTotpEnrollResult` (`secretBase32`, `otpauthUri`, `issuer`, `accountName`) |
| `confirmEnroll` | `code: String!` | `MfaTotpConfirmEnrollResult` (`backupCodes: [String]`) |
| `prepare` | &mdash; | `MfaTotpPreparation` |
| `verify` | `code: String!` | `Result` |
| `regenerateBackupCodes` | `code: String!` | `MfaTotpBackupCodesResult` (`backupCodes: [String]`) |
| `disable` | `code: String!` | `Result` |

Example &mdash; enroll an authenticated user:

```graphql
mutation {
  upa {
    mfa {
      factors {
        totp {
          enroll {
            secretBase32
            otpauthUri
            issuer
            accountName
          }
        }
      }
    }
  }
}
```

Example &mdash; confirm enrollment with the first 6-digit code from the app:

```graphql
mutation {
  upa { mfa { factors { totp {
    confirmEnroll(code: "123456") { backupCodes }
  } } } }
}
```

`enroll(force: true)` is gated: a non-root user must supply `currentCode`, a currently
valid TOTP for the existing secret, before the secret can be rotated.

## User flow

### Enrollment

1. Authenticated user calls `enroll`. The server generates a fresh 160-bit secret and
   returns it once, together with an `otpauth://` URI suitable for QR code rendering.
2. The UI renders the QR code **client-side** (no server round-trip carries the secret
   after this response). The user scans it with their authenticator app.
3. The user types the 6-digit code shown in the app. The UI calls `confirmEnroll(code)`.
4. The server verifies the code, persists the secret and a fresh set of hashed backup
   codes, and returns the plaintext backup codes **once**.

### Login

1. After password authentication succeeds, UPA asks for an additional factor.
2. The UI calls `prepare`, then `verify(code)` with the current TOTP code &mdash; or a
   backup code if the user has lost their device.
3. UPA's rate limiting and lockout apply on `verify`.

## Security properties

- HMAC-SHA1, 30-second step, 6 digits (RFC 6238).
- Verification accepts the current window and &plusmn;1 step (clock drift tolerance).
- Replay protection: the matched counter is persisted in JCR; a code cannot be reused,
  even within its own validity window.
- Backup codes: 10 single-use codes, generated with `SecureRandom`, shown once, stored as
  PBKDF2-HMAC-SHA256 hashes (120 000 iterations, per-code salt).
- All code comparisons use constant-time helpers (`MessageDigest.isEqual` /
  `TotpService.constantTimeEquals`).
- Secrets are generated with `SecureRandom`, never re-disclosed after `confirmEnroll`,
  and never logged.

## Backup codes

`confirmEnroll` and `regenerateBackupCodes` return ten one-shot codes. They are the only
recovery path if the user loses their authenticator device. The user must store them
securely; the server keeps only PBKDF2 hashes and cannot recover them. Consumption is
atomic (verify-and-remove in a single JCR transaction), so a backup code can never be
spent twice — not even by two simultaneous login attempts.

## Lockout & recovery

A user who has lost **both** their authenticator device and their backup codes cannot sign
in on an enforcing site. The recovery path is administrative:

1. A **site administrator** opens the site's *MFA Community → Two-factor authentication*
   administration page and uses **"Reset a user's MFA"** (GraphQL: `resetUserMfa(userId, siteKey)`).
   A confirmation step guards the action; it clears the user's secret, backup codes,
   grace tracking and any management lockout.
2. The reset is recorded in the audit log (`reset` event, with the acting admin in the
   detail field) and visible under *MFA Community → Audit & reporting*.
3. At next login the user enrolls again from scratch (new secret, new backup codes).

If codes from a healthy authenticator are rejected, check the device clock: the server
accepts ±1 time step (30 s) of drift around the current 30-second window.

## Accessibility (WCAG 2.2 AAA)

Every screen shipped by these modules (the sign-in flow, the dashboard pages and the
administration pages) targets WCAG 2.2 **AAA**:

- **Contrast (1.4.6, ≥7:1 normal / ≥4.5:1 large text)** — the shared palette is verified by
  computation: errors `#a00000` (8.42:1), success `#006600` (7.24:1), help text `#555`
  (7.46:1), actions/links `#00538b` (8.05:1, also the focus-ring color), base text `#131c21`
  (17.27:1). Input borders use `#767676` (4.54:1 — non-text boundaries, 1.4.11). Explicit
  `::placeholder` color avoids the under-contrast UA default.
- **Host-template independence** — the login UI renders as an island inside arbitrary site
  templates (some paint near-black backgrounds and force white headings). The flow owns its
  own white card surface (background, text color, heading/link overrides), so the ratios
  above hold regardless of the page hosting it.
- **Status messages (4.1.3)** — errors carry `role="alert"`, successes and loading states
  `role="status"`/`aria-live="polite"`, on every screen including the modals and the admin
  reset sections.
- **Labels & relationships** — every input has a programmatic name (`<label for>` or
  `aria-label`) and help text is attached via `aria-describedby`. The enrollment QR code has
  a `role="img"` text alternative plus the secret displayed as selectable text.
- **Keyboard & focus (2.1.3 / 2.4.7 / 2.4.13)** — everything operates with the keyboard
  alone; focus is visible everywhere (2px outline, 2px offset, 8:1 against the surface) and
  moved to the active field between steps. `prefers-reduced-motion` is honored (2.3.3).
- **Target size (2.5.5)** — buttons, standalone links and inputs reserve at least 44 CSS px.
- **Headings (2.4.10)** — every step of the sign-in flow opens with a heading.
- **Timing (2.2.3)** — the 30-second TOTP window, the emailed-code lifetime and the
  brute-force lockouts are *essential* security timings and rely on the corresponding WCAG
  exception; nothing else in the UI is timed and no content auto-updates or moves.

## Building

```bash
mvn clean install
```

Requires the `user-password-authentication-api` artifact in the local Maven repo (build
the parent UPA project first, or rely on the Jahia public Nexus snapshot).

## Running the tests

Unit tests:

```bash
mvn test
```

End-to-end Cypress tests:

```bash
cd tests
./ci.build.sh
./ci.startup.sh
docker cp "cypress:/home/jahians/results" .
```

## License

Apache License 2.0 &mdash; see [LICENSE](LICENSE).
