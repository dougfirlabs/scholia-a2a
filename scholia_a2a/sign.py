"""Optional Ed25519 JWS (compact serialization) over the trace hash (spec section 4.4).

The JWS payload is `{"sha256": "<hash>", "kid": "<key id>"}`; the protected
header is `{"alg": "EdDSA", "typ": "JWT", "kid": "<key id>"}`. The public key
travels as an OKP JWK: a responder publishes it in its Agent Card extension
params (`public_key_jwk`) or in a JWK Set at `params.jwks_uri`; a requester
without an Agent Card ships it in the metadata `signer` field, which proves
integrity but not identity (self-asserted) unless bound out of band.
"""

from __future__ import annotations

import base64
import json
from dataclasses import dataclass
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519

ALG = "EdDSA"


def _b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64u_decode(text: str) -> bytes:
    pad = "=" * (-len(text) % 4)
    return base64.urlsafe_b64decode(text + pad)


def _canonical_json(obj: Any) -> bytes:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")


def generate_keypair() -> tuple[ed25519.Ed25519PrivateKey, ed25519.Ed25519PublicKey]:
    """Generate a fresh Ed25519 keypair."""
    private = ed25519.Ed25519PrivateKey.generate()
    return private, private.public_key()


def public_key_to_jwk(public: ed25519.Ed25519PublicKey, kid: str) -> dict[str, str]:
    raw = public.public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return {"kty": "OKP", "crv": "Ed25519", "x": _b64u(raw), "kid": kid, "alg": ALG}


def public_key_from_jwk(jwk: dict[str, Any]) -> ed25519.Ed25519PublicKey:
    if jwk.get("kty") != "OKP" or jwk.get("crv") != "Ed25519" or "x" not in jwk:
        raise ValueError("JWK is not an Ed25519 OKP key")
    return ed25519.Ed25519PublicKey.from_public_bytes(_b64u_decode(jwk["x"]))


def private_key_to_pem(private: ed25519.Ed25519PrivateKey) -> bytes:
    return private.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )


def private_key_from_pem(pem: bytes) -> ed25519.Ed25519PrivateKey:
    key = serialization.load_pem_private_key(pem, password=None)
    if not isinstance(key, ed25519.Ed25519PrivateKey):
        raise ValueError("PEM does not hold an Ed25519 private key")
    return key


@dataclass
class Ed25519Signer:
    """Signs a trace hash; pass as `signer=` to `build_provenance`."""

    private_key: ed25519.Ed25519PrivateKey
    kid: str = "default"

    @classmethod
    def generate(cls, kid: str = "default") -> "Ed25519Signer":
        private, _ = generate_keypair()
        return cls(private_key=private, kid=kid)

    @property
    def public_key(self) -> ed25519.Ed25519PublicKey:
        return self.private_key.public_key()

    def public_jwk(self) -> dict[str, str]:
        return public_key_to_jwk(self.public_key, self.kid)

    def sign(self, sha256: str) -> str:
        header = _b64u(_canonical_json({"alg": ALG, "typ": "JWT", "kid": self.kid}))
        payload = _b64u(_canonical_json({"sha256": sha256, "kid": self.kid}))
        signing_input = f"{header}.{payload}".encode("ascii")
        sig = self.private_key.sign(signing_input)
        return f"{header}.{payload}.{_b64u(sig)}"


@dataclass
class Ed25519Verifier:
    """Verifies a JWS produced by `Ed25519Signer`; pass as `verifier=` to `verify_provenance`."""

    public_key: ed25519.Ed25519PublicKey
    kid: str | None = None

    @classmethod
    def from_jwk(cls, jwk: dict[str, Any]) -> "Ed25519Verifier":
        return cls(public_key=public_key_from_jwk(jwk), kid=jwk.get("kid"))

    @classmethod
    def from_jwks(cls, jwks: dict[str, Any], kid: str | None = None) -> "Ed25519Verifier":
        """Pick the Ed25519 key with `kid` (or the only Ed25519 key) out of a JWK Set (`params.jwks_uri`)."""
        keys = [k for k in jwks.get("keys", []) if k.get("kty") == "OKP" and k.get("crv") == "Ed25519"]
        if kid is not None:
            keys = [k for k in keys if k.get("kid") == kid]
        if len(keys) != 1:
            raise ValueError(f"JWK Set has {len(keys)} matching Ed25519 keys for kid={kid!r}; need exactly one")
        return cls.from_jwk(keys[0])

    @classmethod
    def from_signer_field(cls, signer: dict[str, Any]) -> "Ed25519Verifier":
        """Verifier for a metadata `signer: {kid, jwk}` field. The result is self-asserted identity."""
        jwk = signer.get("jwk")
        if not isinstance(jwk, dict):
            raise ValueError("signer has no inline jwk (agent_card_url must be resolved by the caller)")
        if "d" in jwk:
            raise ValueError("signer.jwk carries a private key member; refusing")
        kid = signer.get("kid")
        if kid is not None and jwk.get("kid") not in (None, kid):
            raise ValueError(f"signer.kid {kid!r} does not match signer.jwk.kid {jwk.get('kid')!r}")
        v = cls.from_jwk(jwk)
        if kid is not None:
            v.kid = kid
        return v

    def verify(self, jws: str, expected_sha256: str) -> tuple[bool, str]:
        """Return (ok, reason). Never raises on malformed input."""
        try:
            header_b64, payload_b64, sig_b64 = jws.split(".")
            header = json.loads(_b64u_decode(header_b64))
            payload = json.loads(_b64u_decode(payload_b64))
            if header.get("alg") != ALG:
                return False, f"unsupported alg {header.get('alg')!r}"
            if self.kid is not None and header.get("kid") not in (None, self.kid):
                return False, f"kid mismatch: header {header.get('kid')!r} vs key {self.kid!r}"
            self.public_key.verify(_b64u_decode(sig_b64), f"{header_b64}.{payload_b64}".encode("ascii"))
        except InvalidSignature:
            return False, "signature does not verify against the public key"
        except (ValueError, TypeError, json.JSONDecodeError) as exc:
            return False, f"malformed JWS: {exc}"
        if payload.get("sha256") != expected_sha256:
            return False, "signed hash differs from the metadata sha256"
        return True, "ok"
