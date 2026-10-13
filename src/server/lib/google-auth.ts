/**
 * Access tokens for Vertex AI from a service account's JSON key, for the
 * deployed Worker, where `gcloud` isn't there to hand out tokens. Signs a JWT
 * with the key and trades it at Google's token endpoint, as Google's own
 * client libraries do, then reuses the token until shortly before it expires.
 */

const SCOPE = "https://www.googleapis.com/auth/cloud-platform";

/** Renew this long before Google's expiry, so a token never lapses mid-call. */
const MARGIN_SECONDS = 300;

/** The fields we use from the key file `gcloud iam service-accounts keys create` writes. */
export interface ServiceAccountKey {
  client_email: string;
  private_key: string;
  token_uri?: string;
}

export function parseKey(json: string): ServiceAccountKey {
  const key = JSON.parse(json);
  if (typeof key?.client_email !== "string" || typeof key?.private_key !== "string") {
    throw new Error("GOOGLE_SERVICE_ACCOUNT_KEY isn't a service account's JSON key");
  }
  return key;
}

/** The claims Google asks for in a service account's token request. */
export function jwtClaims(key: ServiceAccountKey, now: number) {
  return {
    iss: key.client_email,
    scope: SCOPE,
    aud: key.token_uri ?? "https://oauth2.googleapis.com/token",
    iat: now,
    exp: now + 3600,
  };
}

function base64url(data: string | ArrayBuffer): string {
  const binary =
    typeof data === "string"
      ? String.fromCharCode(...new TextEncoder().encode(data))
      : String.fromCharCode(...new Uint8Array(data));
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function pemToDer(pem: string): ArrayBuffer {
  const body = pem.replace(/-----[^-]+-----/g, "").replace(/\s/g, "");
  return Uint8Array.from(atob(body), (c) => c.charCodeAt(0)).buffer;
}

/** An RS256 JWT, signed with the key. */
export async function signJwt(key: ServiceAccountKey, now: number): Promise<string> {
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const claims = base64url(JSON.stringify(jwtClaims(key, now)));
  const signingKey = await crypto.subtle.importKey(
    "pkcs8",
    pemToDer(key.private_key),
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign(
    "RSASSA-PKCS1-v1_5",
    signingKey,
    new TextEncoder().encode(`${header}.${claims}`),
  );
  return `${header}.${claims}.${base64url(signature)}`;
}

async function fetchToken(key: ServiceAccountKey) {
  const now = Math.floor(Date.now() / 1000);
  const resp = await fetch(jwtClaims(key, now).aud, {
    method: "POST",
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
    body: new URLSearchParams({
      grant_type: "urn:ietf:params:oauth:grant-type:jwt-bearer",
      assertion: await signJwt(key, now),
    }),
  });
  if (!resp.ok) {
    throw new Error(`Google token exchange failed (${resp.status}): ${await resp.text()}`);
  }
  const { access_token, expires_in } = (await resp.json()) as {
    access_token: string;
    expires_in: number;
  };
  return { token: access_token, renewAt: now + expires_in - MARGIN_SECONDS };
}

/** Per key, for this isolate: the last token, and the request for the next. */
const tokens = new Map<string, { token: string; renewAt: number }>();
const pending = new Map<string, Promise<string>>();

/**
 * A Vertex access token from the service account's JSON key, reused until
 * near expiry. Calls at the same time share one request; a failed one isn't
 * kept, so the next call tries again.
 */
export async function serviceAccountToken(keyJson: string): Promise<string> {
  const cached = tokens.get(keyJson);
  if (cached && cached.renewAt > Date.now() / 1000) return cached.token;
  let request = pending.get(keyJson);
  if (!request) {
    request = fetchToken(parseKey(keyJson))
      .then((t) => {
        tokens.set(keyJson, t);
        return t.token;
      })
      .finally(() => pending.delete(keyJson));
    pending.set(keyJson, request);
  }
  return request;
}
