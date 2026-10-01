"""Extension identity, metadata keys and Agent Card entry.

Implements section 3 ("Declaration and activation") and the key layout of
section 4 of the Scholia Provenance Extension for A2A, draft 0.1.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

EXTENSION_URI = "https://scholialang.org/ext/a2a/provenance/v1"
SCHOLIA_VERSION = "0.7"
MODES = ("inline", "reference")
SIGNING = ("none", "jws")
MAX_INLINE_BYTES = 65536

# Short key names from section 4 of the spec, in table order.
KEY_NAMES = ("trace", "sha256", "parent", "claims", "validator", "signature", "audit")
REQUIRED_KEYS = ("trace", "sha256")


def key(name: str) -> str:
    """Return the URI-prefixed metadata key for a short key name."""
    if name not in KEY_NAMES:
        raise KeyError(f"unknown provenance key {name!r}; expected one of {KEY_NAMES}")
    return f"{EXTENSION_URI}/{name}"


KEYS: dict[str, str] = {name: key(name) for name in KEY_NAMES}


def default_params(**overrides: Any) -> dict[str, Any]:
    """The `params` block of the Agent Card extension entry (spec section 3)."""
    params: dict[str, Any] = {
        "scholia_version": SCHOLIA_VERSION,
        "modes": list(MODES),
        "signing": list(SIGNING),
        "max_inline_bytes": MAX_INLINE_BYTES,
    }
    params.update(overrides)
    return params


def agent_extension(
    *,
    required: bool = False,
    description: str = "Scholialang reasoning provenance on messages and artifacts",
    **params: Any,
) -> dict[str, Any]:
    """Build the Agent Card `capabilities.extensions[]` entry as a JSON dict.

    Extra keyword arguments extend `params` (for example a signing public key
    as `public_key_jwk`). Pass the result to `AgentExtension(**entry)` from
    `a2a.types.a2a_pb2`, or splice the dict into a JSON Agent Card.
    """
    return {
        "uri": EXTENSION_URI,
        "description": description,
        "required": required,
        "params": default_params(**params),
    }


def is_activated(requested_extensions: Iterable[str]) -> bool:
    """True when the client's A2A-Extensions header named this extension."""
    return EXTENSION_URI in set(requested_extensions)


def has_provenance(metadata: Mapping[str, Any] | None) -> bool:
    """True when a metadata map carries both MUST keys of the extension."""
    if not metadata:
        return False
    return all(KEYS[k] in metadata for k in REQUIRED_KEYS)


def extract(metadata: Mapping[str, Any] | None) -> dict[str, Any]:
    """Pull the extension's fields out of a metadata map, keyed by short name.

    Unknown keys under the extension prefix are kept (additive keys are
    allowed within v1) so that verifiers can report them.
    """
    out: dict[str, Any] = {}
    if not metadata:
        return out
    prefix = EXTENSION_URI + "/"
    for k, v in metadata.items():
        if isinstance(k, str) and k.startswith(prefix):
            out[k[len(prefix):]] = v
    return out


def embed(fields: Mapping[str, Any], into: dict[str, Any] | None = None) -> dict[str, Any]:
    """Write short-keyed fields into a metadata map under URI-prefixed keys."""
    target = into if into is not None else {}
    for name, value in fields.items():
        target[key(name)] = value
    return target
