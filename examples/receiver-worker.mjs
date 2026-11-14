// aviryn-sign-demo-receiver: an independently deployed, owner-controlled
// RECEIVER for Aviryn Sign. It exists to prove the receiver-side pattern end
// to end: this service verifies the receipt against the live Sign service
// FIRST and applies its own effect (adding a task to ITS OWN list) only when
// Sign says valid. Every non-valid outcome - 403, 409 replay, 429, 503,
// network error - is no-effect.
//
// Owner-controlled demo, NOT a customer integration: the "effect" is an
// in-memory, per-isolate, ephemeral list. No storage, no accounts, no data.

const SIGN_BASE = "https://aviryn-sign.qalir.workers.dev";
const MAX_BODY = 65536;
const CAP = 20;

const tasks = []; // in-memory, per-isolate, ephemeral - see note in every response
const NOTE = "Owner-controlled demo receiver. List is in-memory, per-isolate and ephemeral (resets anytime). Proves the verify-then-effect boundary against the live Sign service; not a customer integration.";

function json(data, status = 200) {
  return new Response(JSON.stringify(data, null, 2), { status, headers: { "content-type": "application/json" } });
}

async function handleAdd(request, env) {
  const len = parseInt(request.headers.get("content-length") ?? "0", 10);
  if (len > MAX_BODY) return json({ error: "body_too_large", applied: false }, 413);
  let body;
  try {
    body = await request.json();
  } catch {
    return json({ error: "invalid_json", applied: false }, 400);
  }
  if (!body || typeof body !== "object" || typeof body.token !== "string" || !body.action || typeof body.action !== "object" || !body.receipt || typeof body.receipt !== "object") {
    return json({ error: "token_action_receipt_required", applied: false }, 400);
  }

  // 1. VERIFY FIRST against the live Sign service. Any failure = no effect.
  let status = 0, verdict = {};
  try {
    // Service binding to the Sign worker on this same account (Cloudflare
    // blocks worker-to-worker fetches over public workers.dev routes on one
    // account - error 1042). Same verification, direct internal channel.
    const res = await env.SIGN.fetch(new Request("https://aviryn-sign.internal/v1/action/verify", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ token: body.token, action: body.action, receipt: body.receipt }),
    }));
    status = res.status;
    verdict = await res.json();
  } catch {
    status = 0; // network failure: also a rejection
  }
  if (status !== 200 || !verdict.valid) {
    // Outcome honesty, classified by what Sign's pipeline PROVABLY did.
    // Verified source order in Sign's verify pipeline: rate limit checks,
    // then token/hash/signature/freshness/scope checks, and the nonce claim
    // LAST. So:
    // - 429 (rate_limited): provably BEFORE any verification step - the
    //   nonce was not consumed. Safe to retry with the same receipt.
    // - 403 (any reason): all 403 checks precede the claim in the pipeline -
    //   the nonce was not consumed. Final for this receipt as-is.
    // - 503 with rate_limiter_not_configured / rate_limiter_unavailable /
    //   issuer_not_configured / replay_store_not_configured: these fail
    //   before the claim - the nonce was not consumed. Retryable.
    // - 503 replay_store_unavailable, 500 internal_error, 0 (network):
    //   UNKNOWN. The claim may have committed Durable-Object-side with the
    //   response lost on the way back. Retrying the SAME receipt still
    //   cannot double-apply (a consumed nonce rejects), but this answer
    //   cannot confirm what happened.
    // - 409 REPLAY_DETECTED: the nonce was consumed by an EARLIER
    //   verification. That proves an earlier verify happened; it does NOT
    //   prove any receiver effect was applied - a failure between verify
    //   and effect, or a lost response, leaves the earlier outcome unknown.
    //   This demo receiver keeps no durable effect record (ephemeral list),
    //   so certainty requires inspecting GET /tasks.
    const PRE_CLAIM_5XX = ["rate_limiter_not_configured", "rate_limiter_unavailable", "issuer_not_configured", "replay_store_not_configured"];
    let retryable, prior;
    const reason = verdict.reason ?? verdict.error ?? "sign_unreachable";
    if (status === 409 || reason === "REPLAY_DETECTED") {
      retryable = false;
      prior = "unknown - nonce consumed by an earlier verification; no durable effect record here, check GET /tasks (ephemeral)";
    } else if (status === 429 || status === 403 || (status === 503 && PRE_CLAIM_5XX.includes(verdict.error))) {
      retryable = status === 429 || status === 503;
      prior = "not consumed - rejected before the nonce claim (" + reason + ")";
    } else if (status === 0 || status >= 500) {
      retryable = true;
      prior = "unknown - Sign may have processed the request before this answer was lost; same-receipt retry cannot double-apply";
    } else {
      retryable = false;
      prior = "this attempt applied nothing";
    }
    return json({
      applied: false,
      sign_status: status,
      reason,
      retryable,
      prior_outcome: prior,
      effect: "nothing changed",
    }, 403);
  }

  // 2. Only now apply OUR effect.
  const title = typeof body.action.title === "string" ? body.action.title.slice(0, 200) : "(untitled)";
  tasks.push({ title, at: new Date().toISOString(), agent: verdict.agent_id ?? null });
  if (tasks.length > CAP) tasks.shift();
  return json({ applied: true, effect: "task added to this receiver's own list", task: tasks[tasks.length - 1], tasks_count: tasks.length, note: NOTE });
}

export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    if (request.method === "GET" && url.pathname === "/") {
      return json({
        service: "aviryn-sign-demo-receiver",
        version: "1.3.0",
        verifies_against: SIGN_BASE + "/v1/action/verify",
        endpoints: ["POST /tasks {token, action, receipt}", "GET /tasks"],
        note: NOTE,
      });
    }
    if (request.method === "GET" && url.pathname === "/tasks") {
      return json({ tasks, count: tasks.length, note: NOTE });
    }
    if (request.method === "POST" && url.pathname === "/tasks") {
      return handleAdd(request, env);
    }
    return json({ error: "not_found" }, 404);
  },
};
