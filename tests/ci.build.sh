#!/bin/bash
#
# Stage all module JARs that Jahia needs to boot with TOTP support into
# ./artifacts/jars/. The docker-compose volume mount of that dir into the
# Jahia container's auto-deploy directory makes them available at startup.
#
# Bundles staged:
#   - UPA api JAR              (from ../../user-password-authentication/api/target/)
#   - UPA UI JS module (.tgz)  (from ../../user-password-authentication/ui/target/)
#   - UPA template-set test    (from ../../user-password-authentication/test-modules/template-set/target/)
#                              — needed because the login-flow specs build a site with this templateSet
#   - TOTP factor JAR          (from ../target/)
#   - TOTP login-ui tgz        (from ../login-ui/target/)
set -e

source ./set-env.sh

cd "$(dirname "$0")"
ARTIFACTS_DIR="$(pwd)/artifacts/jars"
mkdir -p "${ARTIFACTS_DIR}"
rm -f "${ARTIFACTS_DIR}"/*.jar "${ARTIFACTS_DIR}"/*.tgz

UPA_API_DIR="../../user-password-authentication/api/target"
UPA_UI_DIR="../../user-password-authentication/ui/target"
UPA_TEMPLATE_SET_DIR="../../user-password-authentication/test-modules/template-set/target"
TOTP_TARGET_DIR="../totp/target"
TOTP_LOGIN_UI_DIR="../login-ui/target"

echo "== Staging UPA api JAR =="
UPA_API_JAR=$(ls -1 "${UPA_API_DIR}"/user-password-authentication-api-*.jar 2>/dev/null | grep -v sources | grep -v javadoc | head -n1 || true)
if [[ -z "${UPA_API_JAR}" ]]; then
  echo "ERROR: Could not find UPA api JAR under ${UPA_API_DIR}. Build UPA first (mvn package)."
  exit 1
fi
cp "${UPA_API_JAR}" "${ARTIFACTS_DIR}/"
echo "  staged: $(basename "${UPA_API_JAR}")"

echo "== Staging UPA UI tgz =="
UPA_UI_TGZ=$(ls -1 "${UPA_UI_DIR}"/user-password-authentication-ui-*.tgz 2>/dev/null | head -n1 || true)
if [[ -z "${UPA_UI_TGZ}" ]]; then
  echo "ERROR: Could not find UPA UI tgz under ${UPA_UI_DIR}. Build UPA UI first."
  exit 1
fi
cp "${UPA_UI_TGZ}" "${ARTIFACTS_DIR}/"
echo "  staged: $(basename "${UPA_UI_TGZ}")"

echo "== Staging TOTP factor JAR =="
TOTP_JAR=$(ls -1 "${TOTP_TARGET_DIR}"/mfa-factors-totp-*.jar 2>/dev/null | grep -v sources | grep -v javadoc | head -n1 || true)
if [[ -z "${TOTP_JAR}" ]]; then
  echo "ERROR: Could not find TOTP factor JAR under ${TOTP_TARGET_DIR}. Run 'mvn package' on mfa-factors-totp first."
  exit 1
fi
cp "${TOTP_JAR}" "${ARTIFACTS_DIR}/"
echo "  staged: $(basename "${TOTP_JAR}")"

echo "== Staging UPA template-set test module JAR =="
UPA_TEMPLATE_SET_JAR=$(ls -1 "${UPA_TEMPLATE_SET_DIR}"/user-password-authentication-template-set-test-module-*.jar 2>/dev/null | grep -v sources | grep -v javadoc | head -n1 || true)
if [[ -z "${UPA_TEMPLATE_SET_JAR}" ]]; then
  echo "ERROR: Could not find UPA template-set test JAR under ${UPA_TEMPLATE_SET_DIR}."
  echo "       Build it via: mvn -f ${UPA_TEMPLATE_SET_DIR}/../pom.xml package"
  exit 1
fi
cp "${UPA_TEMPLATE_SET_JAR}" "${ARTIFACTS_DIR}/"
echo "  staged: $(basename "${UPA_TEMPLATE_SET_JAR}")"

echo "== Staging TOTP login-ui tgz =="
TOTP_LOGIN_UI_TGZ=$(ls -1 "${TOTP_LOGIN_UI_DIR}"/mfa-factors-login-ui-*.tgz 2>/dev/null | head -n1 || true)
if [[ -z "${TOTP_LOGIN_UI_TGZ}" ]]; then
  echo "ERROR: Could not find TOTP login-ui tgz under ${TOTP_LOGIN_UI_DIR}."
  echo "       Build it via: mvn -f ../login-ui/pom.xml package"
  exit 1
fi
cp "${TOTP_LOGIN_UI_TGZ}" "${ARTIFACTS_DIR}/"
echo "  staged: $(basename "${TOTP_LOGIN_UI_TGZ}")"

echo "== Building Cypress test image =="
# We do NOT build a custom image; we use the official cypress/included one. Pull it now
# so docker-compose up doesn't wait on first run.
docker pull "${TESTS_IMAGE}" || true

echo "== Done. Staged artifacts:"
ls -la "${ARTIFACTS_DIR}"
