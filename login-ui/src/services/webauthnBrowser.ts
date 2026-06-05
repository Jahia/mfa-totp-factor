/**
 * Browser-side WebAuthn assertion glue for the login flow.
 *
 * The server emits the assertion options as W3C "…JSON" (base64url), but
 * navigator.credentials.get() needs ArrayBuffers, and the resulting PublicKeyCredential must be
 * re-serialized to the base64url JSON the server parses. No external dependency.
 */

function b64uToBuf(b64u: string): ArrayBuffer {
  const pad = "=".repeat((4 - (b64u.length % 4)) % 4);
  const b64 = (b64u + pad).replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) {
    bytes[i] = bin.charCodeAt(i);
  }

  return bytes.buffer;
}

function bufToB64u(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let bin = "";
  for (let i = 0; i < bytes.length; i++) {
    bin += String.fromCharCode(bytes[i]);
  }

  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

/** Whether the browser exposes the WebAuthn API. */
export function isWebauthnSupported(): boolean {
  return (
    typeof window !== "undefined" &&
    typeof window.PublicKeyCredential !== "undefined" &&
    Boolean(navigator.credentials && navigator.credentials.get)
  );
}

/**
 * Run an assertion ceremony from the server's request-options JSON and return the response JSON
 * string for the verify mutation. Throws (NotAllowedError) if the user cancels or it times out.
 */
export async function getAssertion(requestOptionsJson: string): Promise<string> {
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  const options: any = JSON.parse(requestOptionsJson).publicKey;
  options.challenge = b64uToBuf(options.challenge);
  if (options.allowCredentials) {
    // eslint-disable-next-line @typescript-eslint/no-explicit-any
    options.allowCredentials = options.allowCredentials.map((c: any) => ({
      ...c,
      id: b64uToBuf(c.id),
    }));
  }

  const cred = (await navigator.credentials.get({ publicKey: options })) as PublicKeyCredential;
  const response = cred.response as AuthenticatorAssertionResponse;
  return JSON.stringify({
    id: cred.id,
    rawId: bufToB64u(cred.rawId),
    type: cred.type,
    response: {
      authenticatorData: bufToB64u(response.authenticatorData),
      clientDataJSON: bufToB64u(response.clientDataJSON),
      signature: bufToB64u(response.signature),
      userHandle: response.userHandle ? bufToB64u(response.userHandle) : null,
    },
    clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {},
  });
}
