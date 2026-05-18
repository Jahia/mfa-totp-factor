import { type BaseError, type BaseSuccess, createError } from "./common";

type InitiateResultSuccess = BaseSuccess;
type InitiateResultError = BaseError;
export type InitiateResult = InitiateResultSuccess | InitiateResultError;

export default async function initiate(
  apiRoot: string,
  username: string,
  password: string,
  rememberMe = false,
  site?: string,
): Promise<InitiateResult> {
  const response = await fetch(apiRoot, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      query: /* GraphQL */ `
        mutation initiate(
          $username: String!
          $password: String!
          $rememberMe: Boolean!
          $site: String
        ) {
          upa {
            mfaInitiate(
              username: $username
              password: $password
              rememberMe: $rememberMe
              site: $site
            ) {
              session {
                initiated
                remainingFactors
                error {
                  code
                  arguments {
                    name
                    value
                  }
                }
              }
            }
          }
        }
      `,
      variables: { username, password, rememberMe, site },
    }),
  });
  const result = await response.json();
  const session = result?.data?.upa?.mfaInitiate?.session;
  const success = session?.initiated;
  if (success) {
    return {
      success: true,
      remainingFactors: session.remainingFactors,
    };
  } else {
    return createError(session?.error);
  }
}
