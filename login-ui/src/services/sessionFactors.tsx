/**
 * The factor types the user of the ACTIVE MFA session has configured (post-password,
 * pre-second-factor). Drives the factor chooser filter: offering an unconfigured factor is a
 * dead end — its pick-one row defers to a configured sibling, and the user lands on a different
 * factor than the one they picked.
 *
 * Returns null on ANY failure — callers fall back to the unfiltered factor list. That fallback
 * is safe: the chooser is cosmetic, verification stays enforced server-side either way.
 */
export default async function sessionFactors(apiRoot: string): Promise<Array<string> | null> {
  try {
    const response = await fetch(apiRoot, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        query: /* GraphQL */ `
          query sessionFactors {
            mfaSessionFactors {
              configuredFactors
            }
          }
        `,
      }),
    });
    const result = await response.json();
    const factors = result?.data?.mfaSessionFactors?.configuredFactors;
    return Array.isArray(factors) ? factors : null;
  } catch {
    return null;
  }
}
