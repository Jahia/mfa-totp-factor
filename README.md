# UPA - TOTP factor

Third-party Jahia module adding a TOTP (RFC 6238 / Google Authenticator) factor to the
[User Password Authentication (UPA)](https://github.com/Jahia/user-password-authentication)
Multi-Factor Authentication framework. Once installed, end users can enroll an authenticator
app, log in with a 6-digit time-based code, and fall back to one-shot backup codes.

Compatible with Google Authenticator, Authy, 1Password, FreeOTP and any other RFC 6238
compliant authenticator.

## Requirements

- Jahia 8.2.3+
- `user-password-authentication-api` 0.3.0+ (the UPA module must be installed and started)
- `graphql-dxm-provider` 3.4+
- Java 11+

## Installation

1. Build the project (`mvn clean install` at the repo root builds both modules):
   - `factor/target/mfa-totp-factor-<version>.jar` &mdash; the OSGi factor bundle.
   - `login-ui/target/mfa-totp-factor-login-ui-<version>.tgz` &mdash; the sign-in UI (optional;
     install only if you want the bundled login template). The `.tgz` is an npm/JS-SDK
     package and must be installed via the Jahia provisioning API or the Modules UI &mdash;
     it is **not** picked up by the `digital-factory-data/modules/` hot-deploy folder.
2. Drop the bundle JAR into Jahia's `digital-factory-data/modules/` directory, or upload it
   from the Jahia administration UI (*Server settings* &rarr; *Modules*).
3. Make sure the `user-password-authentication` module is started first; this module
   declares it as a hard dependency (`jahia-depends`).

## Configuration

The module ships a single OSGi authorization configuration that grants the GraphQL types
to all callers (the actual authentication / rate limiting happens at the resolver level):

- `factor/src/main/resources/META-INF/configurations/org.jahia.bundles.api.authorization-mfa-totp-factor.yml`

It also ships an editable Karaf configuration (PID `org.jahia.modules.totp`):

- `factor/src/main/resources/META-INF/configurations/org.jahia.modules.totp.cfg`

| Key | Default | Effect |
| --- | --- | --- |
| `loginUrl` | _(empty)_ | **Global default** login URL. When resolved, `MfaTotpLoginLogoutProvider` makes Jahia redirect unauthenticated users to this page instead of `/cms/login` — point it at the page that renders the `totpui:authentication` login UI (e.g. `/sites/mySite/login.html`). |
| `logoutUrl` | _(empty)_ | **Global default** custom sign-out page. |
| `loginGate.enabled` | `false` | Master switch for the `/cms/login` gate (see below). |
| `loginGate.ipWhitelist` | _(empty)_ | Comma-separated IPv4/IPv6 addresses or CIDR blocks allowed through the gate (e.g. `203.0.113.7, 10.0.0.0/8, 2001:db8::/32`). |
| `secret.encryption.key` | _(empty)_ | Base64 256-bit AES key for encrypting TOTP secrets at rest. Empty = a key is auto-generated and persisted under `<jahiaVarDir>/mfa-totp-factor/secret.key`. |

`MfaTotpLoginLogoutProvider` implements Jahia's `LoginUrlProvider` / `LogoutUrlProvider` SPI.
URLs are resolved **per request** with this precedence: a **per-site** `loginUrl` / `logoutUrl`
(set from the site's *Two-factor authentication* administration page, stored on the
`upaTotp:siteSettings` mixin) → the **global** `.cfg` value above → Jahia's default. When nothing
is configured for a site the provider returns nothing, so deploying the module never hijacks
login on its own. Global `.cfg` edits are applied live (no restart); per-site values take effect
immediately on save.

**Open-redirect guard:** per-site URLs must be server-relative paths starting with `/`
(e.g. `/sites/mySite/login.html`). Absolute (`https://…`), protocol-relative (`//host`,
`/\host`) and scheme-carrying (`javascript:`) values are rejected at save time, and any
pre-existing unsafe value is ignored at resolve time — a site administrator can never point
the login redirect off-site. The global `.cfg` values are operator-controlled (filesystem
trust level) and are not restricted, so an external SSO portal remains possible globally.

The enrollment **grace period** is bounded to **0–365 days** (an unbounded value would
silently disable enforcement forever).

### The `/cms/login` gate

Jahia's legacy `/cms/login` endpoint authenticates with username/password only — it never
consults MFA factors. On a site that **enforces** TOTP enrollment it is therefore a complete
second-factor bypass. `TotpLoginGateFilter` (a Jahia `AbstractServletFilter` running before
the authentication valve, so blocked requests never get a session) closes it:

- requests carrying a site context (`?site=<key>` parameter or the `siteKey` request
  attribute) are gated when **that site** has TOTP enabled + enforced;
- requests with no site context — the common case — are gated when **any** site enforces
  enrollment (`/cms/login` authenticates globally, so one enforcing site is enough);
- gated requests get **HTTP 403** unless the client IP matches `loginGate.ipWhitelist`,
  keeping an emergency/back-office door (e.g. your VPN range).

The client IP is the **first `X-Forwarded-For` entry** when present, else the socket
address. **Security:** `X-Forwarded-For` is client-spoofable — only enable the gate behind a
reverse proxy that overwrites the header. The gate is **off by default**: enabling it with an
empty whitelist locks everyone (including platform administrators) out of `/cms/login` as
soon as one site enforces enrollment — set the whitelist first, then flip
`loginGate.enabled=true`. JCR errors fail **closed** (request blocked).

Tunable security constants (`DRIFT_WINDOWS`, `TIME_STEP_SECONDS`, `DIGITS`, PBKDF2
iterations, ...) live in `TotpService` and `BackupCodes`. To change them, fork and rebuild.

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

1. A **site administrator** opens the site's *Two-factor authentication* administration
   page and uses **"Reset a user's MFA"** (GraphQL: `resetUserMfa(userId, siteKey)`).
   A confirmation step guards the action; it clears the user's secret, backup codes,
   grace tracking and any management lockout.
2. The reset is recorded in the audit log (`reset` event, with the acting admin in the
   detail field) and visible under *Audit & reporting* on the same page.
3. At next login the user enrolls again from scratch (new secret, new backup codes).

If codes from a healthy authenticator are rejected, check the device clock: the server
accepts ±1 time step (30 s) of drift around the current 30-second window.

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
