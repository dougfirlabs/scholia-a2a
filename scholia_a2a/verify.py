"""Receiver-side verification (spec section 5, audit level L1 of section 6).

`verify_provenance()` re-derives everything the sender declared and reports
every mismatch. Trace content is treated as untrusted data: nothing here
interprets it, and `VerifyResult.safe_summary()` exposes structure only.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol

from scholialang.parser import ScholiaParseError

from . import ext
from .provenance import (
    EVIDENCE_KINDS,
    canonical_bytes,
    extract_claims,
    normalize_hash,
    parse_trace,
    run_validator,
    sha256_of,
    walk_atoms,
)

Fetcher = Callable[[str], Any]


class Verifier(Protocol):
    def verify(self, jws: str, expected_sha256: str) -> tuple[bool, str]: ...


@dataclass
class VerifyResult:
    """Outcome of one verification. `ok` is the L1 structural verdict."""

    present: bool = False
    sha256: str | None = None
    mode: str | None = None
    format: str | None = None
    hash_ok: bool = False
    signature_present: bool = False
    signature_ok: bool | None = None  # None: no signature, or no verifier supplied
    validator_ok: bool = False
    validator_declared_ok: bool | None = None
    validator_version: str | None = None
    claims_ok: bool = False
    claims_declared: list[dict[str, Any]] = field(default_factory=list)
    claims_derived: list[dict[str, Any]] = field(default_factory=list)
    parents: list[str] = field(default_factory=list)
    errors: list[str] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    atom_summary: dict[str, Any] = field(default_factory=dict)
    size_bytes: int = 0

    @property
    def ok(self) -> bool:
        return (
            self.present
            and self.hash_ok
            and self.signature_ok is not False
            and self.validator_ok
            and self.claims_ok
        )

    def to_dict(self) -> dict[str, Any]:
        d = {k: v for k, v in self.__dict__.items()}
        d["ok"] = self.ok
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
            "hash_ok": self.hash_ok,
            "signature": "verified" if self.signature_ok else ("failed" if self.signature_ok is False else ("unverified" if self.signature_present else "none")),
            "validator_ok": self.validator_ok,
            "validator_version": self.validator_version,
            "claims_ok": self.claims_ok,
            "claims": [{"finding": c["finding"], "depends_on": list(c["depends_on"])} for c in self.claims_declared],
            "parents": list(self.parents),
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


def _check_claims(declared: Any, derived: list[dict[str, Any]], steps: Any, result: VerifyResult) -> bool:
    """Declared claims must be a consistent subset of what the trace actually says."""
    if declared is None:
        result.warnings.append("no claims declared (SHOULD)")
        return True
    if not isinstance(declared, list):
        result.errors.append("claims is not a list")
        return False
    atoms = {a.id: a for a in walk_atoms(steps) if a.id}
    derived_map = {c["finding"]: set(c["depends_on"]) for c in derived}
    ok = True
    for c in declared:
        if not isinstance(c, dict) or "finding" not in c or "depends_on" not in c:
            result.errors.append(f"malformed claim {c!r}")
            ok = False
            continue
        fid = c["finding"]
        f = atoms.get(fid)
        if f is None or f.kind != "Finding":
            result.errors.append(f"claim names {fid!r}, which is not a Finding in the trace")
            ok = False
            continue
        deps = set(c["depends_on"])
        for d in deps:
            t = atoms.get(d)
            if t is None or t.kind not in EVIDENCE_KINDS:
                result.errors.append(f"claim {fid} depends on {d!r}, which is not Evidence/Observation in the trace")
                ok = False
        extra = deps - derived_map.get(fid, set())
        if extra:
            result.errors.append(f"claim {fid} declares dependencies the trace does not cite: {sorted(extra)}")
            ok = False
        missing = derived_map.get(fid, set()) - deps
        if missing:
            result.warnings.append(f"claim {fid} omits cited evidence {sorted(missing)}")
    return ok


def verify_provenance(
    metadata: Mapping[str, Any] | None,
    fetch: Fetcher | None = None,
    verifier: Verifier | None = None,
    *,
    max_inline_bytes: int = ext.MAX_INLINE_BYTES,
) -> VerifyResult:
    """Verify the extension fields found in an A2A `metadata` map.

    Args:
        metadata: the Message/Artifact metadata map (URI-prefixed keys).
        fetch: callable(uri) -> body, used in reference mode. Without it a
               reference-mode trace cannot be checked and the result fails.
        verifier: checks the JWS `signature` if present. Without it a present
               signature is reported as unverified (signature_ok=None).
    """
    r = VerifyResult()
    fields = ext.extract(metadata)
    if not ext.has_provenance(metadata):
        r.errors.append("no provenance block (missing trace or sha256)")
        return r
    r.present = True

    trace = fields.get("trace")
    if not isinstance(trace, dict):
        r.errors.append("trace is not an object")
        return r
    r.mode = trace.get("mode")
    r.format = trace.get("format", "srml")
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

    # 1. Obtain the body.
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
    if r.format not in ("srml", "json"):
        r.errors.append(f"unknown trace format {r.format!r}")
        return r

    # 2. Hash.
    try:
        r.size_bytes = len(canonical_bytes(body, r.format))
        actual = sha256_of(body, r.format)
    except (TypeError, ValueError) as exc:
        r.errors.append(f"cannot canonicalize body: {exc}")
        return r
    r.hash_ok = actual == r.sha256
    if not r.hash_ok:
        r.errors.append(f"sha256 mismatch: metadata {r.sha256} vs computed {actual}")
    if r.mode == "inline" and r.size_bytes > max_inline_bytes:
        r.warnings.append(f"inline body is {r.size_bytes} bytes, over max_inline_bytes={max_inline_bytes}")

    # 3. Signature (binds the declared hash to a key; checked even if hash failed, for the report).
    sig = fields.get("signature")
    if sig:
        r.signature_present = True
        if verifier is None:
            r.warnings.append("signature present but no verifier supplied; unverified")
        else:
            ok, reason = verifier.verify(str(sig), r.sha256)
            r.signature_ok = ok
            if not ok:
                r.errors.append(f"signature: {reason}")

    # 4. Validator, re-run locally (the sender's record is advisory).
    local = run_validator(body, r.format)
    r.validator_ok = local["ok"]
    r.validator_version = local["version"]
    if not local["ok"]:
        r.errors.append("validator: " + "; ".join(f"{e['rule']}({e['atom_id']}): {e['message']}" for e in local["errors"]))
    declared = fields.get("validator")
    if isinstance(declared, dict):
        r.validator_declared_ok = declared.get("ok")
        if declared.get("ok") != local["ok"]:
            r.errors.append(f"validator record disagrees with local run (declared ok={declared.get('ok')}, local ok={local['ok']})")
            r.validator_ok = False
        if declared.get("version") != local["version"]:
            r.warnings.append(f"validator version differs: declared {declared.get('version')}, local {local['version']}")
    else:
        r.warnings.append("no validator record (SHOULD)")

    # 5. Claims against the trace.
    try:
        steps = parse_trace(body, r.format)
    except Exception:  # already reported by the validator step
        r.claims_ok = False
        return r
    r.atom_summary = _atom_summary(steps)
    r.claims_derived = extract_claims(steps)
    r.claims_declared = list(fields.get("claims") or [])
    r.claims_ok = _check_claims(fields.get("claims"), r.claims_derived, steps, r)
    return r
