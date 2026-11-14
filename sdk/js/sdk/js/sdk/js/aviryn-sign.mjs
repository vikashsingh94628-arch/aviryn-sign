// Aviryn Sign - single-file JavaScript SDK (agent side). Zero dependencies.
// Works in Node 18+ and modern browsers (Web Crypto API).
//
// Non-custodial by design: createIdentity() generates the Ed25519 keypair
// locally and signAction() signs locally. The private key is never sent
// anywhere. mint() and verify() talk to a deployed worker over HTTPS.

const ED25519 = { name: "Ed25519" };
export const ISSUER = "aviryn-sign-v0.2";

export function b64urlEncode(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function b64urlDecode(s) {
  if (!/^[A-Za-z0-9_-]+$/.test(s)) throw new Error("invalid base64url");
  const pad = s.length % 4 === 0 ? "" : "=".repeat(4 - (s.length % 4));
  const bin = atob(s.replace(/-/g, "+").replace(/_/g, "/") + pad);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

const utf8 = (s) => new TextEncoder().encode(s);

// Canonical JSON, JCS-inspired subset (sorted keys, no whitespace, safe
// integers only) - byte-identical to the worker and the Python SDK.
export function canonicalize(value) {
  if (value === null) return "null";
  const t = typeof value;
  if (t === "boolean" || t === "string") return JSON.stringify(value);
  if (t === "number") {
    if (!Number.isSafeInteger(value)) throw new Error("non-safe-integer numbers are outside the canonical subset");
    return String(value);
  }
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  if (t === "object") {
    const keys = Object.keys(value).filter((k) => value[k] !== undefined).sort();
    return "{" + keys.map((k) => JSON.stringify(k) + ":" + canonicalize(value[k])).join(",") + "}";
  }
  throw new Error("uncanonicalizable type: " + t);
}

async function sha256B64url(data) {
  return b64urlEncode(new Uint8Array(await crypto.subtle.digest("SHA-256", data)));
}

export async function actionHash(action) {
  return sha256B64url(utf8(canonicalize(action)));
}

async function signingPayloadBytes(actionHashB64, token, timestamp, nonce) {
  const tokenHash = await sha256B64url(utf8(token));
  return utf8(canonicalize({ action_hash: actionHashB64, nonce, timestamp, token_hash: tokenHash }));
}

export async function createIdentity() {
  const kp = await crypto.subtle.generateKey(ED25519, true, ["sign", "verify"]);
  const spki = new Uint8Array(await crypto.subtle.exportKey("spki", kp.publicKey));
  const jwk = await crypto.subtle.exportKey("jwk", kp.privateKey);
  return {
    publicKey: b64urlEncode(spki), // safe to share with /v1/policy/mint
    privateKeyJwk: { kty: jwk.kty, crv: jwk.crv, d: jwk.d, x: jwk.x }, // keep secret
  };
}

export async function signAction(privateKeyJwk, token, action, timestamp, nonce) {
  const ts = timestamp ?? Math.floor(Date.now() / 1000);
  const n = nonce ?? b64urlEncode(crypto.getRandomValues(new Uint8Array(16)));
  const key = await crypto.subtle.importKey("jwk", privateKeyJwk, ED25519, true, ["sign"]);
  const hash = await actionHash(action);
  const payload = await signingPayloadBytes(hash, token, ts, n);
  const sig = new Uint8Array(await crypto.subtle.sign(ED25519, key, payload));
  return { action_hash: hash, signature: b64urlEncode(sig), timestamp: ts, nonce: n };
}

export class AvirynSign {
  constructor(baseUrl, adminKey = null) {
    this.baseUrl = baseUrl.replace(/\/+$/, "");
    this.adminKey = adminKey;
  }

  async #post(path, body, admin = false) {
    const headers = { "content-type": "application/json" };
    if (admin) {
      if (!this.adminKey) throw new Error("adminKey required for mint");
      headers["authorization"] = "Bearer " + this.adminKey;
    }
    const res = await fetch(this.baseUrl + path, { method: "POST", headers, body: JSON.stringify(body) });
    return { status: res.status, body: await res.json() };
  }

  // Owner-side: requires the admin key. Prefer passing the agent's own publicKey.
  mint(agentId, publicKey, policy, ttlSeconds = 3600) {
    return this.#post("/v1/policy/mint", { agent_id: agentId, public_key: publicKey, policy, ttl_seconds: ttlSeconds }, true);
  }

  verify(token, action, receipt) {
    return this.#post("/v1/action/verify", { token, action, receipt });
  }
}
