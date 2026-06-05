/**
 * Browser-side WebAuthn ceremony glue.
 *
 * The yubico server emits ceremony options as W3C "…JSON" (base64url-encoded), but
 * navigator.credentials.create()/get() need ArrayBuffers, and the PublicKeyCredential result
 * must be re-serialized back to the base64url JSON shape the server parses. This module does
 * those conversions with no external dependency.
 */

function b64uToBuf(b64u) {
    const pad = '='.repeat((4 - (b64u.length % 4)) % 4);
    const b64 = (b64u + pad).replace(/-/g, '+').replace(/_/g, '/');
    const bin = atob(b64);
    const bytes = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) {
        bytes[i] = bin.charCodeAt(i);
    }

    return bytes.buffer;
}

function bufToB64u(buf) {
    const bytes = new Uint8Array(buf);
    let bin = '';
    for (let i = 0; i < bytes.length; i++) {
        bin += String.fromCharCode(bytes[i]);
    }

    return btoa(bin).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

/** Whether the browser exposes the WebAuthn API at all. */
export function isWebauthnSupported() {
    return typeof window !== 'undefined' &&
        typeof window.PublicKeyCredential !== 'undefined' &&
        Boolean(navigator.credentials && navigator.credentials.create);
}

/**
 * Run a registration ceremony: convert the server's create-options JSON, call
 * navigator.credentials.create(), and return the response JSON string for finishRegistration.
 */
export async function createCredential(creationOptionsJson) {
    const options = JSON.parse(creationOptionsJson).publicKey;
    options.challenge = b64uToBuf(options.challenge);
    options.user.id = b64uToBuf(options.user.id);
    if (options.excludeCredentials) {
        options.excludeCredentials = options.excludeCredentials.map(c => ({...c, id: b64uToBuf(c.id)}));
    }

    const cred = await navigator.credentials.create({publicKey: options});
    return JSON.stringify({
        id: cred.id,
        rawId: bufToB64u(cred.rawId),
        type: cred.type,
        response: {
            attestationObject: bufToB64u(cred.response.attestationObject),
            clientDataJSON: bufToB64u(cred.response.clientDataJSON),
            transports: cred.response.getTransports ? cred.response.getTransports() : []
        },
        clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
    });
}

/**
 * Run an assertion ceremony: convert the server's request-options JSON, call
 * navigator.credentials.get(), and return the response JSON string for verify.
 */
export async function getCredential(requestOptionsJson) {
    const options = JSON.parse(requestOptionsJson).publicKey;
    options.challenge = b64uToBuf(options.challenge);
    if (options.allowCredentials) {
        options.allowCredentials = options.allowCredentials.map(c => ({...c, id: b64uToBuf(c.id)}));
    }

    const cred = await navigator.credentials.get({publicKey: options});
    return JSON.stringify({
        id: cred.id,
        rawId: bufToB64u(cred.rawId),
        type: cred.type,
        response: {
            authenticatorData: bufToB64u(cred.response.authenticatorData),
            clientDataJSON: bufToB64u(cred.response.clientDataJSON),
            signature: bufToB64u(cred.response.signature),
            userHandle: cred.response.userHandle ? bufToB64u(cred.response.userHandle) : null
        },
        clientExtensionResults: cred.getClientExtensionResults ? cred.getClientExtensionResults() : {}
    });
}
