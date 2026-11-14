"""Aviryn Sign - single-file Python SDK (agent side).

Non-custodial by design: the private key is generated and held locally and is
never sent anywhere. This SDK can mint policy tokens (with your admin key) and
sign actions locally; verification can be done locally or via a deployed
worker's /v1/action/verify.

Dependency: the `cryptography` package (pip install cryptography). Everything
else is the Python standard library.

Canonicalization matches the worker's JCS-inspired subset: sorted object keys,
no whitespace, safe integers only (floats are rejected), UTF-8.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
import time
import urllib.request

from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)
from cryptography.hazmat.primitives.serialization import (
    Encoding,
    PrivateFormat,
    PublicFormat,
    NoEncryption,
    load_der_private_key,
    load_der_public_key,
)

ISSUER = "aviryn-sign-v0.2"


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def canonicalize(value) -> str:
    """Deterministic canonical JSON matching src/crypto.ts (ASCII-key safe)."""
    return json.dumps(
        value,
        separators=(",", ":"),
        sort_keys=True,
        ensure_ascii=False,
        allow_nan=False,
        check_circular=True,
    )


def _reject_floats(value):
    if isinstance(value, float):
        raise ValueError("non-integer numbers are outside the canonical subset")
    if isinstance(value, dict):
        for v in value.values():
            _reject_floats(v)
    elif isinstance(value, (list, tuple)):
        for v in value:
            _reject_floats(v)


def action_hash(action: dict) -> str:
    _reject_floats(action)
    return _b64url(hashlib.sha256(canonicalize(action).encode("utf-8")).digest())


def _signing_payload(action_hash_b64: str, token: str, timestamp: int, nonce: str) -> bytes:
    token_hash = _b64url(hashlib.sha256(token.encode("utf-8")).digest())
    return canonicalize(
        {
            "action_hash": action_hash_b64,
            "nonce": nonce,
            "timestamp": timestamp,
            "token_hash": token_hash,
        }
    ).encode("utf-8")


def create_identity() -> dict:
    """Generate an Ed25519 keypair. Returns dict with public_key (base64url
    SPKI, safe to share) and private_key_jwk (keep secret, never transmit)."""
    priv = Ed25519PrivateKey.generate()
    pub = priv.public_key()
    spki = pub.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    raw_priv = priv.private_bytes(Encoding.Raw, PrivateFormat.Raw, NoEncryption())
    raw_pub = pub.public_bytes(Encoding.Raw, PublicFormat.Raw)
    return {
        "public_key": _b64url(spki),
        "private_key_jwk": {"kty": "OKP", "crv": "Ed25519", "d": _b64url(raw_priv), "x": _b64url(raw_pub)},
    }


def _load_private(jwk: dict) -> Ed25519PrivateKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "d" not in jwk:
        raise ValueError("not an Ed25519 private JWK")
    return Ed25519PrivateKey.from_private_bytes(_b64url_decode(jwk["d"]))


def load_public(public_key_b64: str) -> Ed25519PublicKey:
    return load_der_public_key(_b64url_decode(public_key_b64))


def sign_action(private_key_jwk: dict, token: str, action: dict, timestamp: int | None = None, nonce: str | None = None) -> dict:
    """Sign an action locally. Returns the receipt to present for verification."""
    ts = int(timestamp if timestamp is not None else time.time())
    n = nonce or _b64url(secrets.token_bytes(16))
    h = action_hash(action)
    priv = _load_private(private_key_jwk)
    sig = priv.sign(_signing_payload(h, token, ts, n))
    return {"action_hash": h, "signature": _b64url(sig), "timestamp": ts, "nonce": n}


def verify_local(token: str, action: dict, receipt: dict, issuer_public_key_b64: str, now: int | None = None) -> dict:
    """Verify without any network call. Raises ValueError with the worker's
    reason code on failure; returns the token payload on success."""
    now = int(now if now is not None else time.time())
    parts = token.split(".")
    if len(parts) != 3:
        raise ValueError("token_malformed")
    header = json.loads(_b64url_decode(parts[0]))
    if header.get("alg") != "EdDSA":
        raise ValueError("token_alg_rejected")
    issuer_pub = load_public(issuer_public_key_b64)
    try:
        issuer_pub.verify(_b64url_decode(parts[2]), (parts[0] + "." + parts[1]).encode("utf-8"))
    except Exception:
        raise ValueError("token_signature_invalid")
    payload = json.loads(_b64url_decode(parts[1]))
    if payload.get("iss") != ISSUER:
        raise ValueError("token_issuer_invalid")
    if now >= payload["exp"]:
        raise ValueError("token_expired")
    if action_hash(action) != receipt.get("action_hash"):
        raise ValueError("action_hash_mismatch")
    agent_pub = load_public(payload["agt_key"])
    try:
        agent_pub.verify(
            _b64url_decode(receipt["signature"]),
            _signing_payload(receipt["action_hash"], token, receipt["timestamp"], receipt["nonce"]),
        )
    except Exception:
        raise ValueError("signature_invalid")
    if abs(now - receipt["timestamp"]) > 120:
        raise ValueError("timestamp_stale")
    # Scope check
    policy = payload["policy"]
    if action.get("type") not in policy["actions"]:
        raise ValueError("scope_action_type_denied")
    if not _target_allowed(action.get("target", ""), policy["targets"]):
        raise ValueError("scope_target_denied")
    spend_actions = policy.get("spend_actions") or []
    spend = action.get("spend")
    if action["type"] in spend_actions:
        if not spend:
            raise ValueError("spend_required_missing")
        cap = policy["max_spend_per_action"]
        if spend["amount"] > cap["amount"]:
            raise ValueError("scope_spend_limit_exceeded")
        if spend["currency"] != cap["currency"]:
            raise ValueError("scope_currency_mismatch")
    elif spend:
        raise ValueError("scope_spend_not_permitted")
    # NOTE: local verify cannot do replay claims; use the worker endpoint for that.
    return payload


def _target_allowed(target: str, patterns: list) -> bool:
    from urllib.parse import urlparse

    for p in patterns:
        if p.endswith("*"):
            try:
                t = urlparse(target)
                b = urlparse(p[:-1])
            except Exception:
                continue
            if (t.scheme, t.hostname, t.port) != (b.scheme, b.hostname, b.port):
                continue
            if t.username or t.password or b.username or b.password:
                continue
            base_path = b.path if b.path.endswith("/") else b.path + "/"
            if t.path == b.path or t.path.startswith(base_path):
                return True
        elif target == p:
            return True
    return False


class Client:
    """HTTP client for a deployed Aviryn Sign worker."""

    def __init__(self, base_url: str, admin_key: str | None = None):
        self.base_url = base_url.rstrip("/")
        self.admin_key = admin_key

    def _post(self, path: str, body: dict, admin: bool = False) -> dict:
        req = urllib.request.Request(
            self.base_url + path,
            data=json.dumps(body).encode("utf-8"),
            headers={
                "content-type": "application/json",
                # Edge bot protection rejects urllib's default UA (error 1010);
                # identify the SDK explicitly instead.
                "user-agent": "aviryn-sign-python-sdk/0.4",
            },
            method="POST",
        )
        if admin:
            if not self.admin_key:
                raise ValueError("admin_key required for mint")
            req.add_header("authorization", "Bearer " + self.admin_key)
        try:
            with urllib.request.urlopen(req) as res:
                return json.loads(res.read())
        except urllib.error.HTTPError as e:
            return json.loads(e.read())

    def mint(self, agent_id: str, public_key: str, policy: dict, ttl_seconds: int = 3600) -> dict:
        return self._post(
            "/v1/policy/mint",
            {"agent_id": agent_id, "public_key": public_key, "policy": policy, "ttl_seconds": ttl_seconds},
            admin=True,
        )

    def verify(self, token: str, action: dict, receipt: dict) -> dict:
        return self._post("/v1/action/verify", {"token": token, "action": action, "receipt": receipt})
