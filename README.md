# Aviryn Sign - Public Beta

Cryptographic receipt and intent verifier for AI agents. An agent signs each
action with its own Ed25519 key; your service verifies the receipt against
the live Sign API BEFORE it executes anything. Tampered, replayed or
out-of-permission requests are rejected and change nothing.

Status: PUBLIC BETA / limited pilot. Honest limits below. Not
enterprise-certified: no independent security audit has been performed yet.

- Live API: https://aviryn-sign.qalir.workers.dev
- Interactive playground (EN/Hindi): https://aviryn-sign.qalir.workers.dev/
- API info JSON: https://aviryn-sign.qalir.workers.dev/v1/info
- Service version: 0.5.13 (demo receiver example: 1.3.0)

## Package contents

- `sdk/js/aviryn-sign.mjs` - single-file JS SDK (Node 18+ / browsers), zero
  dependencies. Class `AvirynSign` plus `createIdentity`, `signAction`.
- `sdk/python/aviryn_sign.py` - single-file Python SDK (needs
  `pip install cryptography`). Class `Client` plus `create_identity`,
  `sign_action`.
- `examples/receiver-worker.mjs` - a running example of the receiver-side
  pattern (a Cloudflare Worker that verifies first and applies its own
  effect only on a valid verdict, classifying every rejection honestly).

Both SDKs are non-custodial: private keys are generated and used locally;
only signatures and public keys cross the wire.

## Try it in two minutes (no account, no admin key)

The live service exposes a public demo token endpoint scoped to a harmless
demo action, so you can exercise the full sign-then-verify flow right away.

Exact steps (everything runs from the package root - the folder that
contains this README and the `sdk/` directory):

JavaScript (Node 18+): save the snippet below as `try-js.mjs` in the
package root, then run:

    node try-js.mjs

The import path `./sdk/js/aviryn-sign.mjs` resolves from the package root;
there is no install step and no hidden harness.

Python (3.9+): one dependency, then save the snippet below as `try-py.py`
in the package root and run it from there:

    pip install cryptography
    python3 try-py.py

The snippet adds `sdk/python` to `sys.path` itself, so it runs from the
package root with no install and no environment variables.

JavaScript:

```js
import { AvirynSign, createIdentity, signAction } from "./sdk/js/aviryn-sign.mjs";

const BASE = "https://aviryn-sign.qalir.workers.dev";
const id = await createIdentity();                       // keypair stays local

// demo-scoped token (public endpoint; only your public key crosses the wire)
const mint = await fetch(BASE + "/v1/demo/mint", {
  method: "POST",
  headers: { "content-type": "application/json" },
  body: JSON.stringify({ agent_id: "my-first-agent", public_key: id.publicKey }),
}).then((r) => r.json());
const token = mint.token;

const action = {
  type: "demo.action",
  target: "https://demo.playground.aviryn/board",
  op: "board.add",
  title: "Pay the milk bill",
};
const now = Math.floor(Date.now() / 1000);
const receipt = await signAction(id.privateKeyJwk, token, action, now, crypto.randomUUID());

const aviryn = new AvirynSign(BASE);
const { status, body } = await aviryn.verify(token, action, receipt);
console.log(status, body.valid, body.checks);
// 200 true [ 'token_signature', 'token_expiry', 'action_integrity',
//   'agent_signature', 'timestamp_freshness', 'capability_scope', 'replay_claim' ]
```

Python:

```python
import sys, time, secrets
sys.path.insert(0, "sdk/python")  # run from the package root
from aviryn_sign import Client, create_identity, sign_action
import json, urllib.request

BASE = "https://aviryn-sign.qalir.workers.dev"
ident = create_identity()                                # keypair stays local

req = urllib.request.Request(
    BASE + "/v1/demo/mint",
    data=json.dumps({"agent_id": "my-first-agent", "public_key": ident["public_key"]}).encode(),
    headers={"content-type": "application/json", "user-agent": "aviryn-sign-python-sdk/0.4"},
    method="POST",
)
token = json.loads(urllib.request.urlopen(req).read())["token"]

action = {
    "type": "demo.action",
    "target": "https://demo.playground.aviryn/board",
    "op": "board.add",
    "title": "Pay the milk bill",
}
receipt = sign_action(ident["private_key_jwk"], token, action,
                      timestamp=int(time.time()), nonce=secrets.token_urlsafe(16))

aviryn = Client(BASE)
body = aviryn.verify(token, action, receipt)
print(body.get("valid"), body.get("checks"))
```

Note: the edge blocks generic HTTP-client user agents (error 1010). The
Python SDK sends its own UA; do the same in hand-rolled clients.

## The contract your receiver must implement

Verify FIRST, execute SECOND. Inside your own action endpoint:

```js
let status = 0, body = {};
try {
  ({ status, body } = await aviryn.verify(token, action, receipt));
} catch {
  status = 0; // network failure: treat as no verdict, NOT as success
}
if (status !== 200 || !body.valid) {
  // Do NOT execute. Classify the rejection before deciding to retry:
}
```

Rejection classes, grounded in the verify pipeline's check order
(rate limits -> token/action-hash/signature/freshness/scope -> nonce claim
LAST):

- 429 and every 403 reason: provably rejected BEFORE the nonce claim. The
  receipt was not consumed. 403 is final for the receipt as-is; 429 is safe
  to retry with the same receipt.
- 503 rate_limiter_not_configured / rate_limiter_unavailable /
  issuer_not_configured / replay_store_not_configured: also pre-claim; not
  consumed; retryable.
- 503 replay_store_unavailable, 500, or no answer at all: UNKNOWN. The
  request may have been processed with the response lost. Retrying the SAME
  receipt still cannot double-apply (a consumed nonce rejects with 409),
  but the retry cannot tell you what the first attempt did.
- 409 REPLAY_DETECTED: the nonce was consumed by an EARLIER verification.
  That proves an earlier verify happened, NOT that anyone's effect was
  applied.

`/v1/action/verify` proves a receipt and consumes its nonce. That is ALL it
does; your effect is a separate step with a failure gap between them. If you
need exactly-once, durably record nonce -> effect-result on your side. The
atomic demo endpoint `/v1/demo/verify-execute` shows the pattern: claim,
effect record and effect commit in one Durable Object transaction, and its
409 answers from evidence:

- `prior_effect_outcome: "applied"`, `effect_record_present: true`,
  `outcome_record_present: true`: a durable record proves this receipt's
  effect committed (the recorded effect is included).
- `prior_effect_outcome: "never_applied"`, `effect_record_present: false`,
  `outcome_record_present: true`: a durable NEGATIVE record proves the
  nonce was spent by a verify-only call and no effect was ever committed.
- `prior_effect_outcome: "unknown"`, both records absent: no retained
  record proves the historical outcome (evicted by the 20-item demo board
  cap, expired, or predates effect records). The API never reports a false
  historical negative.

Field definitions: `effect_record_present` means a retained EFFECT entry
exists (only in the applied case). `outcome_record_present` means ANY
retained durable outcome record exists (applied and never_applied).

No-double-apply is bounded by retention, not forever: the same receipt
cannot double-apply while its nonce claim is retained (300s replay window,
which fully covers the receipt's 120s freshness lifetime).

## Honest limits (Public Beta)

- Tokens are bearer credentials until `exp`: no per-token revocation list.
  Revocation = issuer key rotation (operational procedure, owner-run).
- Receipts expire after a 120s freshness window; nonces are single-use.
- Per-IP rate limits apply on every endpoint (429 with retry_after).
- The demo board keeps at most 20 items and auto-deletes after 24 hours.
- The receiver example keeps its task list in memory (ephemeral, per
  isolate). It demonstrates the contract; it is not a durable integration.
- Recovery across a lost network response is solved only for the atomic
  demo path. For your own external effects, exactly-once needs the durable
  nonce -> effect-result record described above; that part is on the
  integrator.
- No independent security audit yet. Treat this as a strong engineering
  build suitable for evaluation and limited pilots, not as a certified
  security product.
- Known playground quirk: right after the page loads, the server list can
  render empty until you click "Refresh the list" (a load-time display
  race). The data itself persists correctly on the server.

## Production use

`POST /v1/policy/mint` (owner admin key) mints full policy tokens with your
own action types, targets, ops and TTLs. The playground's demo tokens are
intentionally narrow. For pilot access and policy design, start from the
playground page's developer section.
