# AGENTS.md

Notes for AI coding agents (Claude Code, Cursor, etc.) working on this repository.
Keep edits minimal and consistent with the conventions below.

## Project type

Third-party Jahia 8.2 **multi-module Maven project** (root `pom.xml` is a `packaging=pom`
aggregator, mirroring UPA's layout). It has two modules:

- **`totp/`** &mdash; the OSGi bundle (`packaging=bundle`, artifactId `mfa-factors-totp`).
  Implements the `MfaFactorProvider` SPI exposed by the
  [User Password Authentication (UPA)](https://github.com/Jahia/user-password-authentication)
  module, contributes a TOTP factor to UPA's MFA pipeline, and bundles the self-service
  dashboard + per-site admin React UIs (webpack/Module Federation).
- **`login-ui/`** &mdash; a Jahia JS-SDK module (`packaging=pom`, produces a `.tgz` via Vite)
  providing the sign-in template (`totpui:authentication`) with a factor chooser.

Published under groupId `org.jahia.community` (required by Jahia EE's license check
&mdash; do not change it).

The functional spec lives **outside this repository** at
`../SPEC-TOTP.md` (i.e. `SUPPORT/SUPPORT-591/SPEC-TOTP.md`). Keep the implementation in
sync with that document; do not duplicate its contents inside the module.

## Repo layout

```
pom.xml                            Root aggregator (packaging=pom): <modules>factor, login-ui</modules>.
totp/                            OSGi bundle module (artifactId mfa-factors-totp).
  pom.xml
  src/main/java/org/jahia/modules/upa/mfa/totp/
    TotpService.java                 RFC 6238 primitive: HOTP/TOTP generation + verification, Base32, otpauth:// URI.
    TotpFactorProvider.java          UPA MfaFactorProvider SPI impl (verify at login; consults per-site settings).
    TotpUserStore.java               JCR persistence of per-user settings (secret, hashed backup codes, lastUsedCounter).
    TotpSiteSettingsStore.java       JCR persistence of per-site settings (enabled / enforced) on the site node.
    TotpEnrollmentState.java         Transient (in-session) secret + TTL while the user is enrolling.
    TotpPreparationResult.java       MFA "preparation" DTO (carries the per-session "skipped" flag).
    TotpManagementRateLimiter.java   In-memory throttle for management mutations.
    BackupCodes.java                 Generates, PBKDF2-hashes, and constant-time-verifies backup codes.
    gql/
      TotpFactorMutation.java        Mutations: enroll/confirmEnroll/prepare/verify/regenerateBackupCodes/disable/setSiteSettings.
      TotpFactorQuery.java           Queries: status (per-user) + siteSettings (per-site).
      TotpFactorMutationExtension / TotpFactorQueryExtension   @GraphQLTypeExtension graft points.
      ExtensionsAutoDiscovery.java   Registers the extensions with graphql-dxm-provider.
      Totp*Result.java               Result DTOs.
  src/main/javascript/               Dashboard (self-service) + per-site admin React (webpack/Module Federation).
  src/main/resources/META-INF/
    definitions.cnd                  JCR node types: upaTotp:userSettings (per-user) + upaTotp:siteSettings (per-site).
    configurations/...authorization-mfa-factors-totp.yml  Grants GraphQL types.
  src/test/java/...                  JUnit 4 tests.
login-ui/                          JS-SDK module (Vite → .tgz): totpui:authentication sign-in template + factor chooser.
tests/                             Cypress / docker-compose E2E harness (isolated Compose project; mirrors UPA's tests/).
```

## Build

```bash
mvn clean install        # at the repo root: builds BOTH modules (factor JAR + login-ui .tgz)
```

The root reactor builds `factor` then `login-ui`. Build a single module with
`mvn -pl factor` (or `-pl login-ui`), optionally `-am`. Requires
`user-password-authentication-api` (UPA's `api` module) in the local Maven repo or Jahia's
public Nexus; UPA must be built first when working from a snapshot.

## Tests

- Unit: `mvn test` (JUnit 4).
- E2E: `cd tests && ./ci.build.sh && ./ci.startup.sh`, then
  `docker cp "cypress:/home/jahians/results" .`.

## Key invariants &mdash; do not bypass

- **Replay protection chokepoint:** `TotpUserStore.verifyAndConsumeTotp` is the single
  function that re-reads `lastUsedCounter`, verifies the code, and persists the consumed
  counter in the **same JCR transaction**. Every management mutation that consumes a TOTP
  code routes through this method via `TotpFactorMutation.verifyTotpAndConsume`. Do not
  add a sibling code path that verifies without consuming.
- **Backup codes are PBKDF2-hashed at rest** (`BackupCodes.hash`); never persist or
  compare raw codes. Verification uses `MessageDigest.isEqual` (constant time).
- **Secrets are write-once towards the client:** the Base32 secret and `otpauth://` URI
  leave the server only on the `enroll` response. After `confirmEnroll`, the secret is
  never returned by any API and never logged. Preserve this when adding fields.
- **Constant-time comparisons** for all code/hash comparisons.
- **GroupId `org.jahia.community`** in `pom.xml` is required by Jahia EE license checks.
  Do not move the bundle under `org.jahia.modules`.

## GraphQL wiring

The mutation tree is grafted onto UPA's `FactorsMutation` via the
`@GraphQLTypeExtension` annotation in `TotpFactorMutationExtension`. Discovery happens
through `gql/ExtensionsAutoDiscovery`, registered as an OSGi `@Component` that exposes a
`DXGraphQLExtensionsProvider`. If you add new GraphQL types or mutations, register them
in the same file and grant them in `org.jahia.bundles.api.authorization-mfa-factors-totp.yml`.

## Common pitfalls

- Do **not** override the parent `maven-bundle-plugin` instructions wholesale. The
  bundle's `Import-Package` list must include `${jahia.plugin.projectPackageImport}` and
  the UPA SPI packages (`org.jahia.modules.upa.mfa[.gql]`); extend, do not replace.
- Do **not** add new third-party runtime dependencies without checking they are already
  on the Jahia classpath. Cryptography uses only `java.security` / `javax.crypto`;
  Base32 comes from `commons-codec` which Jahia ships.
- The Cypress suite runs in the **browser context**: do not introduce Node-only APIs
  (e.g. `Buffer.writeBigUInt64BE`) in test helpers. Use `Uint8Array` and `BigInt` math.
- The `enroll(force: true)` path is sensitive (it rotates the second factor). Keep its
  guards: admin OR a valid `currentCode` consumed through the chokepoint.

## Security review

To re-run a security review pass, prompt a fresh agent with something like:

> Review every file under `totp/src/main/java/org/jahia/modules/upa/mfa/totp/` for: replay,
> timing-attack, brute force, secret disclosure, JCR transaction races, logging of
> secrets/codes, and OWASP ASVS controls relevant to MFA. Cross-check against
> `../SECURITY-REVIEW.md`. Output findings as severity/title/file/lines/fix.

See `../SECURITY-REVIEW.md` and `../SECURITY-FIXES.md` for the previous pass.
