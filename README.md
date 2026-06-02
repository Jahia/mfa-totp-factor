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
| `loginUrl` | _(empty)_ | When set, `MfaTotpLoginLogoutProvider` makes Jahia redirect unauthenticated users to this page instead of `/cms/login` — point it at the page that renders the `totpui:authentication` login UI (e.g. `/sites/mySite/login.html`). Empty = default Jahia login. |
| `logoutUrl` | _(empty)_ | Optional custom sign-out page. Empty = default Jahia logout. |
| `secret.encryption.key` | _(empty)_ | Base64 256-bit AES key for encrypting TOTP secrets at rest. Empty = a key is auto-generated and persisted under `<jahiaVarDir>/mfa-totp-factor/secret.key`. |

`MfaTotpLoginLogoutProvider` implements Jahia's `LoginUrlProvider` / `LogoutUrlProvider` SPI
and stays inert until `loginUrl` / `logoutUrl` are set, so deploying the module never hijacks
login on its own. Edits to the `.cfg` are applied live (no restart).

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
securely; the server keeps only PBKDF2 hashes and cannot recover them.

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
