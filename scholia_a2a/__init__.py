"""Reference implementation of the Scholia Provenance Extension for A2A (draft 0.2)."""

from .ext import (
    EXTENSION_URI,
    GRAMMAR_VERSION,
    KEYS,
    VALIDATOR_VERSION,
    agent_extension,
    extract,
    has_provenance,
    has_provenance_keys,
    is_activated,
    is_signalled,
    key,
    provenance_from,
    read_extension_entry,
)
from .provenance import build_provenance, canonical_bytes, extract_claims, normalize_hash, run_validator, sha256_of
from .sign import Ed25519Signer, Ed25519Verifier, generate_keypair
from .verify import IDENTITY_CARD, IDENTITY_SELF, VerifyResult, verify_object, verify_provenance

__all__ = [
    "EXTENSION_URI", "GRAMMAR_VERSION", "VALIDATOR_VERSION", "KEYS",
    "agent_extension", "read_extension_entry", "extract", "has_provenance", "has_provenance_keys",
    "is_activated", "is_signalled", "key", "provenance_from",
    "build_provenance", "canonical_bytes", "extract_claims", "normalize_hash", "run_validator", "sha256_of",
    "Ed25519Signer", "Ed25519Verifier", "generate_keypair",
    "IDENTITY_CARD", "IDENTITY_SELF", "VerifyResult", "verify_object", "verify_provenance",
]
__version__ = "0.2.0"
