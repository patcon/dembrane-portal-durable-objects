import { afterEach, beforeAll, describe, expect, it, vi } from "vitest";
import { jwtClaims, parseKey, serviceAccountToken, signJwt } from "./google-auth";

const ALGORITHM = { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" } as const;

/** A throwaway key pair, its private half shaped like a key file's `private_key`. */
let publicKey: CryptoKey;
let privatePem: string;

beforeAll(async () => {
  const pair = (await crypto.subtle.generateKey(
    { ...ALGORITHM, modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]) },
    true,
    ["sign", "verify"],
  )) as CryptoKeyPair;
  publicKey = pair.publicKey;
  const der = Buffer.from(await crypto.subtle.exportKey("pkcs8", pair.privateKey));
  privatePem = `-----BEGIN PRIVATE KEY-----\n${der.toString("base64").replace(/.{64}/g, "$&\n")}\n-----END PRIVATE KEY-----\n`;
});

function keyJson(email = "sa@p.iam.gserviceaccount.com") {
  return JSON.stringify({ type: "service_account", client_email: email, private_key: privatePem });
}

function fromBase64url(part: string) {
  return Buffer.from(part, "base64url");
}

/** Stubs Google's token endpoint, handing out `token-1`, `token-2`, … */
function tokenEndpoint(expiresIn = 3599) {
  let n = 0;
  const stub = vi.fn(
    async (_url: string, _init: RequestInit) =>
      new Response(JSON.stringify({ access_token: `token-${++n}`, expires_in: expiresIn })),
  );
  vi.stubGlobal("fetch", stub);
  return stub;
}

afterEach(() => {
  vi.unstubAllGlobals();
  vi.useRealTimers();
});

describe("parseKey", () => {
  it("rejects JSON that isn't a service account key", () => {
    expect(() => parseKey('{"api_key":"x"}')).toThrow(/service account/);
  });
});

describe("signJwt", () => {
  it("signs Google's claims with the key, verifiably", async () => {
    const key = parseKey(keyJson());
    const jwt = await signJwt(key, 1_000);
    const [header, claims, signature] = jwt.split(".");
    expect(JSON.parse(fromBase64url(header).toString())).toEqual({ alg: "RS256", typ: "JWT" });
    expect(JSON.parse(fromBase64url(claims).toString())).toEqual(jwtClaims(key, 1_000));
    const ok = await crypto.subtle.verify(
      ALGORITHM,
      publicKey,
      fromBase64url(signature),
      new TextEncoder().encode(`${header}.${claims}`),
    );
    expect(ok).toBe(true);
  });
});

describe("serviceAccountToken", () => {
  it("trades a signed JWT for a token at Google's endpoint", async () => {
    const stub = tokenEndpoint();
    expect(await serviceAccountToken(keyJson("trade@p"))).toBe("token-1");
    const [url, init] = stub.mock.calls[0];
    expect(url).toBe("https://oauth2.googleapis.com/token");
    const body = new URLSearchParams(init.body as string);
    expect(body.get("grant_type")).toBe("urn:ietf:params:oauth:grant-type:jwt-bearer");
    expect(body.get("assertion")?.split(".")).toHaveLength(3);
  });

  it("reuses the token, and one request serves calls made together", async () => {
    const stub = tokenEndpoint();
    const json = keyJson("reuse@p");
    expect(await Promise.all([serviceAccountToken(json), serviceAccountToken(json)])).toEqual([
      "token-1",
      "token-1",
    ]);
    expect(await serviceAccountToken(json)).toBe("token-1");
    expect(stub).toHaveBeenCalledTimes(1);
  });

  it("fetches a new token near expiry", async () => {
    vi.useFakeTimers({ now: 0 });
    const stub = tokenEndpoint(3600);
    const json = keyJson("renew@p");
    expect(await serviceAccountToken(json)).toBe("token-1");
    vi.setSystemTime(3000 * 1000);
    expect(await serviceAccountToken(json)).toBe("token-1");
    vi.setSystemTime(3400 * 1000);
    expect(await serviceAccountToken(json)).toBe("token-2");
    expect(stub).toHaveBeenCalledTimes(2);
  });

  it("says why the exchange failed, and tries again next time", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response('{"error":"invalid_grant"}', { status: 400 })),
    );
    const json = keyJson("fail@p");
    await expect(serviceAccountToken(json)).rejects.toThrow(/\(400\).*invalid_grant/);
    tokenEndpoint();
    expect(await serviceAccountToken(json)).toBe("token-1");
  });
});
