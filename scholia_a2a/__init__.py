"""Reference implementation of the Scholia Provenance Extension for A2A (draft 0.1)."""

from .ext import EXTENSION_URI, KEYS, agent_extension, extract, has_provenance, is_activated, key
from .provenance import build_provenance, extract_claims, run_validator, sha256_of
from .sign import Ed25519Signer, Ed25519Verifier, generate_keypair
from .verify import VerifyResult, verify_provenance

__all__ = [
    "EXTENSION_URI", "KEYS", "agent_extension", "extract", "has_provenance", "is_activated", "key",
    "build_provenance", "extract_claims", "run_validator", "sha256_of",
    "Ed25519Signer", "Ed25519Verifier", "generate_keypair",
    "VerifyResult", "verify_provenance",
]
__version__ = "0.1.0"
