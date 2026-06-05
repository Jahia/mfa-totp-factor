# TOTP factor — Cypress test suite

End-to-end tests for the UPA TOTP MFA factor (`user-password-authentication-mfa-factors-totp`).
The suite is fully self-contained and runs against a Jahia instance booted from a Docker
image with both the UPA bundles and the TOTP module pre-installed.

## Prerequisites

1. Docker (with `docker compose`) installed and running.
2. The UPA module has been built locally:
   ```
   cd ../../user-password-authentication && mvn -DskipTests package
   ```
   Produces:
   - `user-password-authentication/api/target/user-password-authentication-api-*.jar`
   - `user-password-authentication/ui/target/user-password-authentication-ui-*.tgz`
3. The TOTP module has been built locally:
   ```
   cd ../ && mvn -DskipTests package
   ```
   Produces `mfa-factors-totp/target/user-password-authentication-mfa-factors-totp-*.jar`.

## How to run

```sh
./ci.build.sh        # stages JARs/tgz into artifacts/jars/ for the Jahia container
./ci.startup.sh      # brings up Jahia + smtp + cypress, runs the suite
docker cp "cypress:/home/jahians/results" .   # pull the results
```

`ci.startup.sh` exits with the Cypress suite's exit code, so it can be wired
straight into a CI pipeline.

## Layout

- `ci.build.sh` — stages bundles into `artifacts/jars/`.
- `ci.startup.sh` — orchestrates `docker compose`, runs Cypress, exits with the suite's code.
- `docker-compose.yml` — Jahia + Cypress + Mailpit services. The `artifacts/jars/` host
  directory is bind-mounted into the Jahia container's auto-deploy directory
  (`/var/jahia/modules`) so the staged bundles install on boot.
- `cypress/e2e/` — TOTP spec files.
- `cypress/e2e/utils/totp.ts` — pure-JS RFC 6238 generator (HMAC-SHA1, 30s step, 6 digits)
  used inside specs to compute valid codes.
- `assets/setup-smtp-server.groovy` — wires Mailpit into Jahia's mail settings.

## Specs

- `graphQL.totp.enroll.cy.ts` — enrollment happy-path + re-enroll refusal.
- `graphQL.totp.verify.cy.ts` — login with TOTP code; replay rejection.
- `graphQL.totp.errors.cy.ts` — confirmEnroll without enroll, wrong code, already-enrolled.
- `graphQL.totp.backupCodes.cy.ts` — backup-code single-use + regenerateBackupCodes gating.
