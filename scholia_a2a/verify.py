"""Receiver-side verification (spec section 5, audit level L1 of section 6).

`verify_provenance()` re-derives everything the sender declared and reports
every mismatch, in the spec's order: in-band signal, format, canonical hash,
signature, validator re-run, claims. Trace content is treated as untrusted
data: nothing here interprets it, and `VerifyResult.safe_summary()` exposes
structure only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Mapping, Protocol

from . import ext
from .provenance import (
    EVIDENCE_KINDS,
    FORMATS,
    canonical_bytes,
    cited_evidence,
    extract_claims,
    normalize_hash,
    parse_trace,
    run_validator,
    sha256_of,
    walk_atoms,
)

Fetcher = Callable[[str], Any]

IDENTITY_CARD = "agent-card"  # key came from the responder's Agent Card (params.public_key_jwk / jwks_uri)
IDENTITY_SELF = "self-asserted"  # key came from the metadata `signer` field; integrity only


class Verifier(Protocol):
    def verify(self, jws: str, expected_sha256: str) -> tuple[bool, str]: ...


@dataclass
class VerifyResult:
    """Outcome of one verification. `ok` is the L1 structural verdict."""

    present: bool = False  # the MUST keys are in the metadata map
    signalled: bool | None = None  # extension URI listed in the object's `extensions` field; None: not checked
    sha256: str | None = None
    mode: str | None = None
    format: str | None = None
    format_ok: bool = False
    hash_ok: bool = False
    signature_present: bool = False
    signature_ok: bool | None = None  # None: no signature, or no key available
    identity: str | None = None  # IDENTITY_CARD | IDENTITY_SELF | None
    validator_ok: bool = False
    validator_declared_ok: bool | None = None
    validator_version: str | None = None
    grammar_version: str | None = None
    claims_ok: bool = False
    claims_declared: list[dict[str, Any]] = field(default_factory=list)
    claims_derived: list[dict[str, Any]] = field(default_factory=list)
    parents: list[str] = field(default_factory=list)
    redacted: bool = False
    full_sha256: str | None = None
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    atom_summary: dict[str, Any] = field(default_factory=dict)
    size_bytes: int = 0

    @property
    def ok(self) -> bool:
        return (
            self.present
            and self.signalled is not False
            and self.format_ok
            and self.hash_ok
            and self.signature_ok is not False
            and self.validator_ok
            and self.claims_ok
        )

    @property
    def signature(self) -> str:
        """`verified` | `failed` | `unverified` | `none`, the signature state as a word."""
        if self.signature_ok:
            return "verified"
        if self.signature_ok is False:
            return "failed"
        return "unverified" if self.signature_present else "none"

    @property
    def signature_statement(self) -> str:
        """Honest one-line statement of what a passing signature proves (section 4.4)."""
        if self.signature_ok and self.identity == IDENTITY_SELF:
            return "integrity verified, identity self-asserted"
        if self.signature_ok and self.identity == IDENTITY_CARD:
            return "integrity verified, key from Agent Card"
        if self.signature_ok:
            return "integrity verified"
        return self.signature

    def to_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items()}
        d["ok"] = self.ok
        d["signature"] = self.signature
        return d

    def safe_summary(self) -> dict[str, Any]:
        """Structure-only view for logs or an LLM context. Never includes trace text.

        Atom ids and kinds are data about the graph shape; content, prose,
        attribute values other than polarity/status enums are withheld.
        """
        return {
            "ok": self.ok,
            "sha256": self.sha256,
            "mode": self.mode,
            "format": self.format,
            "signalled": self.signalled,
            "hash_ok": self.hash_ok,
            "signature": self.signature,
            "identity": self.identity,
            "signature_statement": self.signature_statement,
            "validator_ok": self.validator_ok,
            "validator_version": self.validator_version,
            "grammar_version": self.grammar_version,
            "claims_ok": self.claims_ok,
            "claims": [{"finding": c["finding"], "depends_on": list(c["depends_on"])} for c in self.claims_declared],
            "parents": list(self.parents),
            "redacted": self.redacted,
            "atoms": dict(self.atom_summary),
            "error_count": len(self.errors),
            "errors": [e[:200] for e in self.errors],
            "warnings": [w[:200] for w in self.warnings],
        }


def _atom_summary(steps: Any) -> dict[str, Any]:
    kinds: dict[str, int] = {}
    polarity: dict[str, int] = {}
    status: dict[str, int] = {}
    ids: list[str] = []
    for a in walk_atoms(steps):
        kinds[a.kind] = kinds.get(a.kind, 0) + 1
        if a.id:
            ids.append(a.id)
        p = getattr(a, "polarity", None)
        if a.kind == "Evidence" and p:
            polarity[p] = polarity.get(p, 0) + 1
        s = getattr(a, "status", None)
        if a.kind in ("Finding", "Concluding") and s:
            status[s] = status.get(s, 0) + 1
    return {"kinds": kinds, "ids": ids, "evidence_polarity": polarity, "finding_status": status}


def _check_claims(declared: Any, steps: Any, result: VerifyResult) -> bool:
    """Section 4.2: declared depends_on MUST be a subset of the cited set; strict subset is a warning."""
    if declared is None:
        result.warnings.append("no claims declared (SHOULD)")
        return True
    if not isinstance(declared, list):
        result.errors.append("claims is not a list")
        return False
    atoms = {a.id: a for a in walk_atoms(steps) if a.id}
    cited = cited_evidence(steps)
    ok = True
    seen: set[str] = set()
    for c in declared:
        if not isinstance(c, dict) or "finding" not in c or not isinstance(c.get("depends_on"), list):
            result.errors.append(f"malformed claim {c!r}")
            ok = False
            continue
        fid = str(c["finding"])
        f = atoms.get(fid)
        if f is None or f.kind != "Finding":
            result.errors.append(f"claim names {fid!r}, which is not a Finding in the trace")
            ok = False
            continue
        seen.add(fid)
        deps = {str(d) for d in c["depends_on"]}
        for d in sorted(deps):
            t = atoms.get(d)
            if t is None or t.kind not in EVIDENCE_KINDS:
                result.errors.append(f"claim {fid} depends on {d!r}, which is not Evidence in the trace")
                ok = False
        extra = deps - cited.get(fid, set())
        if extra:
            result.errors.append(f"claim {fid} declares dependencies the trace does not cite (superset): {sorted(extra)}")
            ok = False
        missing = cited.get(fid, set()) - deps
        if missing:
            result.warnings.append(f"claim {fid} is a strict subset of the cited set; omits {sorted(missing)}")
    for fid, deps in sorted(cited.items()):
        if deps and fid not in seen:
            result.warnings.append(f"no claim declared for Finding {fid}, which cites {sorted(deps)}")
    return ok


def verify_provenance(
    metadata: Mapping[str, Any] | None,
    fetch: Fetcher | None = None,
    verifier: Verifier | None = None,
    *,
    extensions: Iterable[str] | None = None,
    max_inline_bytes: int = ext.MAX_INLINE_BYTES,
    allow_self_asserted: bool = True,
) -> VerifyResult:
    """Verify the extension fields found in an A2A Message's or Artifact's own `metadata` map.

    Args:
        metadata: the Message/Artifact metadata map (URI-prefixed keys).
        fetch: callable(uri) -> body, used in reference mode. Without it a
               reference-mode trace cannot be checked and the result fails.
        verifier: checks the JWS `signature` with a key the caller trusts
               (normally from the sender's Agent Card). When None and the
               metadata carries `signer: {kid, jwk}`, that key is used and the
               result is marked `identity = "self-asserted"`.
        extensions: the object's own `extensions` field. When given, the
               in-band signal is checked (section 3); keys without the URI
               listed are a failure. When None the signal is reported as
               unchecked (a warning), for callers that only have the map.
        max_inline_bytes: limit on the canonical body (from the card params).
        allow_self_asserted: set False to refuse the `signer` fallback.
    """
    r = VerifyResult()
    fields = ext.extract(metadata)
    keys_present = ext.has_provenance_keys(metadata)
    if extensions is not None:
        r.signalled = ext.is_signalled(extensions)
        if r.signalled and not keys_present:
            r.errors.append("extensions[] lists the extension URI but the MUST keys (trace, sha256) are absent")
            return r
        if keys_present and not r.signalled:
            r.errors.append("provenance keys present but the extension URI is not listed in the object's extensions[] (MUST, section 3)")
    else:
        if keys_present:
            r.warnings.append("in-band signal not checked: caller did not supply the object's extensions[] field")
    if not keys_present:
        r.errors.append("no provenance block (missing trace or sha256)")
        return r
    r.present = True

    trace = fields.get("trace")
    if not isinstance(trace, dict):
        r.errors.append("trace is not an object")
        return r
    r.mode = trace.get("mode")
    r.format = trace.get("format")
    try:
        r.sha256 = normalize_hash(str(fields.get("sha256")))
    except ValueError as exc:
        r.errors.append(str(exc))
        return r

    # Parents are reported even when the rest fails, so a graph can still be stitched.
    for p in fields.get("parent") or []:
        try:
            r.parents.append(normalize_hash(str(p)))
        except ValueError as exc:
            r.errors.append(f"bad parent hash: {exc}")

    # Redaction flags (4.3): reported, and full_sha256 is checked for form only (it cannot be recomputed).
    r.redacted = fields.get("redacted") is True
    if fields.get("full_sha256") is not None:
        try:
            r.full_sha256 = normalize_hash(str(fields["full_sha256"]))
        except ValueError as exc:
            r.errors.append(f"bad full_sha256: {exc}")
        if not r.redacted:
            r.warnings.append("full_sha256 present without redacted: true")

    # 1. Format: v1 defines srml only; never guess.
    if r.format not in FORMATS:
        r.errors.append(f"unknown trace format {r.format!r}; v1 defines only 'srml' (rejected, not guessed)")
        return r
    r.format_ok = True

    # 2. Obtain the body.
    if r.mode == "inline":
        if "body" not in trace:
            r.errors.append("inline trace has no body")
            return r
        body = trace["body"]
    elif r.mode == "reference":
        uri = trace.get("uri")
        if not uri:
            r.errors.append("reference trace has no uri")
            return r
        if fetch is None:
            r.errors.append(f"reference mode: no fetcher supplied to resolve {uri}")
            return r
        try:
            body = fetch(uri)
        except Exception as exc:
            r.errors.append(f"reference mode: fetch failed for {uri}: {type(exc).__name__}: {exc}")
            return r
    else:
        r.errors.append(f"unknown trace mode {r.mode!r}")
        return r

    # 3. Canonical hash (4.1); max_inline_bytes is measured on the canonical bytes.
    try:
        r.size_bytes = len(canonical_bytes(body))
        actual = sha256_of(body)
    except (TypeError, ValueError) as exc:
        r.errors.append(f"cannot canonicalize body: {exc}")
        return r
    r.hash_ok = actual == r.sha256
    if not r.hash_ok:
        r.errors.append(f"sha256 mismatch: metadata {r.sha256} vs computed {actual}")
    if r.mode == "inline" and r.size_bytes > max_inline_bytes:
        r.warnings.append(f"inline body is {r.size_bytes} canonical bytes, over max_inline_bytes={max_inline_bytes}")

    # 4. Signature (binds the declared hash to a key; checked even if the hash failed, for the report).
    sig = fields.get("signature")
    signer_field = fields.get("signer")
    if sig:
        r.signature_present = True
        if verifier is None and isinstance(signer_field, dict) and allow_self_asserted:
            if "jwk" in signer_field:
                from .sign import Ed25519Verifier

                try:
                    verifier = Ed25519Verifier.from_signer_field(signer_field)
                    r.identity = IDENTITY_SELF
                except ValueError as exc:
                    r.errors.append(f"signer: {exc}")
                    r.signature_ok = False
            elif signer_field.get("agent_card_url"):
                r.warnings.append(
                    f"signature unverified: signer.agent_card_url={signer_field['agent_card_url']!r}; resolve the card and pass verifier="
                )
        elif verifier is not None:
            r.identity = IDENTITY_CARD
        if verifier is None:
            if r.signature_ok is None:
                r.warnings.append("signature present but no key available; unverified")
        else:
            ok, reason = verifier.verify(str(sig), r.sha256)
            r.signature_ok = ok
            if not ok:
                r.errors.append(f"signature: {reason}")
    elif isinstance(signer_field, dict):
        r.warnings.append("signer present without a signature")

    # 5. Validator, re-run locally (the sender's record is advisory).
    local = run_validator(body)
    r.validator_ok = local["ok"]
    r.validator_version = local["validator_version"]
    r.grammar_version = local["grammar_version"]
    if not local["ok"]:
        r.errors.append("validator: " + "; ".join(f"{e['rule']}({e['atom_id']}): {e['message']}" for e in local["errors"]))
    declared = fields.get("validator")
    if isinstance(declared, dict):
        r.validator_declared_ok = declared.get("ok")
        if declared.get("ok") != local["ok"]:
            r.errors.append(f"validator record disagrees with local run (declared ok={declared.get('ok')}, local ok={local['ok']})")
            r.validator_ok = False
        declared_vv = declared.get("validator_version", declared.get("version"))  # `version` was the 0.1 name
        if "validator_version" not in declared:
            r.warnings.append("validator record uses draft-0.1 keys (no validator_version/grammar_version)")
        if declared_vv != local["validator_version"]:
            r.warnings.append(f"validator version differs: declared {declared_vv}, local {local['validator_version']}")
        if declared.get("grammar_version") not in (None, local["grammar_version"]):
            r.warnings.append(f"grammar version differs: declared {declared.get('grammar_version')}, local {local['grammar_version']}")
    else:
        r.warnings.append("no validator record (SHOULD)")

    # 6. Claims against the trace (4.2).
    try:
        steps = parse_trace(body)
    except Exception:  # already reported by the validator step
        r.claims_ok = False
        return r
    r.atom_summary = _atom_summary(steps)
    r.claims_derived = extract_claims(steps)
    r.claims_declared = list(fields.get("claims") or [])
    r.claims_ok = _check_claims(fields.get("claims"), steps, r)
    return r


def verify_object(obj: Any, **kwargs: Any) -> VerifyResult:
    """Verify an A2A Message or Artifact (protobuf or JSON dict) using its own metadata and extensions."""
    metadata, extensions = ext.provenance_from(obj)
    return verify_provenance(metadata, extensions=extensions, **kwargs)
