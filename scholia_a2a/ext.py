"""Extension identity, metadata keys, Agent Card entry and the in-band signal.

Implements section 3 ("Declaration and activation") and the key layout of
section 4 of the Scholia Provenance Extension for A2A, draft 0.2.
"""

from __future__ import annotations

from typing import Any, Iterable, Mapping

EXTENSION_URI = "https://scholialang.org/ext/a2a/provenance/v1"
GRAMMAR_VERSION = "0.6.2"  # Scholialang grammar the traces are written in
VALIDATOR_VERSION = "0.7.2"  # scholialang package / validator suite
MODES = ("inline", "reference")
SIGNING = ("none", "jws")
MAX_INLINE_BYTES = 65536
FORMAT = "srml"  # the only v1 trace format (section 4, "Formats")

# Short key names from section 4 of the spec, in table order.
KEY_NAMES = (
    "trace", "sha256", "parent", "claims", "validator", "signature", "signer", "redacted", "full_sha256", "audit",
)
REQUIRED_KEYS = ("trace", "sha256")
NUMERIC_PARAMS = ("max_inline_bytes",)


def key(name: str) -> str:
    """Return the URI-prefixed metadata key for a short key name."""
    if name not in KEY_NAMES:
        raise KeyError(f"unknown provenance key {name!r}; expected one of {KEY_NAMES}")
    return f"{EXTENSION_URI}/{name}"


KEYS: dict[str, str] = {name: key(name) for name in KEY_NAMES}


# ------------------------------------------------------------ Agent Card


def default_params(**overrides: Any) -> dict[str, Any]:
    """The `params` block of the Agent Card extension entry (section 3)."""
    params: dict[str, Any] = {
        "grammar_version": GRAMMAR_VERSION,
        "validator_version": VALIDATOR_VERSION,
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

    Extra keyword arguments extend `params`: a responder publishes its
    verification key as `public_key_jwk` (Ed25519 OKP JWK) or points at a
    JWK Set with `jwks_uri` (section 4.4). Pass the result to
    `AgentExtension(**entry)` from `a2a.types.a2a_pb2`, or splice the dict
    into a JSON Agent Card.
    """
    return {
        "uri": EXTENSION_URI,
        "description": description,
        "required": required,
        "params": default_params(**params),
    }


def read_extension_entry(entry: Mapping[str, Any] | None) -> dict[str, Any]:
    """Normalize a received Agent Card extension entry (section 3, serialization tolerance).

    - an absent `required` reads as false (proto3 JSON omits defaults);
    - numeric params may arrive as integral floats (`65536.0`) and are
      returned as ints; a non-integral float is a ValueError.
    Returns `{"uri", "required", "description", "params"}` with params copied.
    """
    entry = entry or {}
    params = dict(entry.get("params") or {})
    for name in NUMERIC_PARAMS:
        if name in params:
            params[name] = _integral(params[name], name)
    return {
        "uri": entry.get("uri"),
        "required": bool(entry.get("required", False)),
        "description": entry.get("description", ""),
        "params": params,
    }


def _integral(value: Any, name: str) -> int:
    if isinstance(value, bool):
        raise ValueError(f"{name} must be a number, got a boolean")
    if isinstance(value, int):
        return value
    if isinstance(value, float):
        if value.is_integer():
            return int(value)
        raise ValueError(f"{name} must be an integer, got {value!r}")
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value.strip())
    raise ValueError(f"{name} must be a number, got {type(value).__name__}")


# --------------------------------------------------------------- signals


def is_activated(requested_extensions: Iterable[str]) -> bool:
    """True when the client's A2A-Extensions header named this extension (activation request, MAY)."""
    return EXTENSION_URI in set(requested_extensions)


def is_signalled(extensions: Iterable[str] | None) -> bool:
    """True when a Message's or Artifact's own `extensions` field lists this URI (in-band signal, section 3)."""
    if extensions is None:
        return False
    return EXTENSION_URI in set(extensions)


def has_provenance_keys(metadata: Mapping[str, Any] | None) -> bool:
    """True when a metadata map carries both MUST keys of the extension."""
    if not metadata:
        return False
    return all(KEYS[k] in metadata for k in REQUIRED_KEYS)


def has_provenance(metadata: Mapping[str, Any] | None, extensions: Iterable[str] | None = None) -> bool:
    """Receiver's presence decision.

    With `extensions` (the Message's/Artifact's own `extensions` field) the
    decision is the in-band signal, as section 3 requires: the URI must be
    listed and the MUST keys must be present. Without `extensions` (caller
    only has a metadata map) the decision falls back to the keys alone, which
    is the draft-0.1 rule; `verify_provenance` reports that the signal was
    not checked.
    """
    if extensions is None:
        return has_provenance_keys(metadata)
    return is_signalled(extensions) and has_provenance_keys(metadata)


def provenance_from(obj: Any) -> tuple[dict[str, Any], list[str]]:
    """`(metadata, extensions)` from an A2A Message or Artifact, protobuf or JSON dict.

    Reads the object's *own* metadata map and extensions field (section 4,
    first paragraph), never a request-level metadata map.
    """
    if obj is None:
        return {}, []
    if isinstance(obj, Mapping):
        return dict(obj.get("metadata") or {}), list(obj.get("extensions") or [])
    from google.protobuf.json_format import MessageToDict

    meta = MessageToDict(obj.metadata) if obj.HasField("metadata") else {}
    return meta, list(obj.extensions)


# --------------------------------------------------------------- fields


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
