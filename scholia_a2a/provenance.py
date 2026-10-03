"""Build the provenance metadata block (spec section 4).

`build_provenance()` turns a Scholialang trace into the metadata fields of
the extension: canonical hash (4.1), declared claims (4.2), optional
redaction (4.3), validator record, optional signature and signer (4.4), in
inline or reference mode. SRML is the only v1 format; the draft-0.1 json
mapping was removed in 0.2 (section 4, "Formats"; open question 9.3).
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from typing import Any, Iterable, Iterator, Protocol

import scholialang
from scholialang.atoms import Atom, Step
from scholialang.parser import ScholiaParseError

from . import ext

HASH_PREFIX = "sha256:"
FORMATS = (ext.FORMAT,)

# Atom kinds a Finding may depend on. Section 4.2 defines the cited set in
# terms of Evidence atoms only (inline REFER to an Evidence id, or Evidence
# `for` = Finding `for_hyp`).
EVIDENCE_KINDS = ("Evidence",)

_REFER_RE = re.compile(r"\bREFER:([A-Za-z0-9_:.\-]+)")


class Signer(Protocol):
    kid: str

    def sign(self, sha256: str) -> str: ...


# ---------------------------------------------------------- canonical (4.1)


def canonical_bytes(body: str, fmt: str = ext.FORMAT) -> bytes:
    """Canonical byte form of an SRML body, the input to sha256 (section 4.1).

    (1) CRLF and CR -> LF; (2) trailing whitespace stripped from every line;
    (3) leading and trailing blank lines dropped; (4) exactly one final LF;
    (5) UTF-8.
    """
    check_format(fmt)
    if not isinstance(body, str):
        raise TypeError("srml body must be a str")
    lines = [ln.rstrip() for ln in body.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
    while lines and lines[0] == "":
        lines.pop(0)
    while lines and lines[-1] == "":
        lines.pop()
    return ("\n".join(lines) + "\n").encode("utf-8")


def sha256_of(body: str, fmt: str = ext.FORMAT) -> str:
    """`sha256:<64 lowercase hex>` of the canonical body (the only emitted form)."""
    return HASH_PREFIX + hashlib.sha256(canonical_bytes(body, fmt)).hexdigest()


def normalize_hash(value: str) -> str:
    """Accept `sha256:`-prefixed hex (0.2) or bare hex (0.1 senders); return the prefixed form."""
    v = str(value).strip().lower()
    if v.startswith(HASH_PREFIX):
        v = v[len(HASH_PREFIX):]
    if not re.fullmatch(r"[0-9a-f]{64}", v):
        raise ValueError(f"not a sha256 hash: {value!r}")
    return HASH_PREFIX + v


def check_format(fmt: Any) -> str:
    """Return `fmt` if it is the v1 format; raise ValueError otherwise (never guess)."""
    if fmt not in FORMATS:
        raise ValueError(f"unknown trace format {fmt!r}; v1 defines only {ext.FORMAT!r}")
    return fmt


# ------------------------------------------------------------- trace access


def walk_atoms(steps: Iterable[Step]) -> Iterator[Atom]:
    """Depth-first over every atom in a parsed trace, including children."""
    for step in steps:
        stack = list(step.atoms)
        while stack:
            atom = stack.pop(0)
            yield atom
            stack[:0] = list(atom.children)


def parse_trace(body: str, fmt: str = ext.FORMAT) -> list[Step]:
    """Parse an SRML body with scholialang; raises ScholiaParseError."""
    check_format(fmt)
    return scholialang.parse(body)


def redact_srml(body: str) -> str:
    """Redaction profile (section 4.3): keep atom kinds, ids, attributes and edges; drop prose.

    Inline `REFER:`/`IMPLIES:` tokens are kept (they are edges); everything
    else in the element text is removed. Applied before hashing, so the
    redacted body is what gets hashed and shipped.
    """
    import xml.etree.ElementTree as ET

    root = ET.fromstring(f"<__root__>{body}</__root__>")
    keep = re.compile(r"\b(?:REFER|IMPLIES):[A-Za-z0-9_:.\-]+")

    def scrub(el: ET.Element) -> None:
        if el.text:
            tokens = keep.findall(el.text)
            el.text = (" ".join(tokens) + " ") if tokens else None
        if el.tail:
            el.tail = "\n"
        for child in el:
            scrub(child)

    for child in root:
        scrub(child)
    text = "".join(ET.tostring(c, encoding="unicode") for c in root)
    return text.strip() + "\n"


# ------------------------------------------------------------- claims (4.2)


def cited_evidence(steps: Iterable[Step]) -> dict[str, set[str]]:
    """Finding id -> the cited set: inline REFER to Evidence ids, union Evidence sharing the Finding's hypothesis."""
    atoms = list(walk_atoms(steps))
    by_id = {a.id: a for a in atoms if a.id}
    evidence_for_hyp: dict[str, set[str]] = {}
    for a in atoms:
        if a.kind == "Evidence" and a.id and getattr(a, "for_ref", None):
            evidence_for_hyp.setdefault(a.for_ref, set()).add(a.id)
    cited: dict[str, set[str]] = {}
    for a in atoms:
        if a.kind != "Finding" or not a.id:
            continue
        deps: set[str] = set()
        refs = list(a.operators or [])
        refs += _REFER_RE.findall(a.content or "")
        for token in refs:
            target = token.split(":", 1)[1] if token.startswith("REFER:") else token
            t = by_id.get(target)
            if t is not None and t.kind in EVIDENCE_KINDS:
                deps.add(target)
        hyp = getattr(a, "for_hyp", None)
        if hyp:
            deps.update(evidence_for_hyp.get(hyp, set()))
        cited[a.id] = deps
    return cited


def extract_claims(steps: Iterable[Step]) -> list[dict[str, Any]]:
    """Declared claims derived from the trace: one entry per Finding with a non-empty cited set, sorted."""
    return [
        {"finding": fid, "depends_on": sorted(deps)}
        for fid, deps in sorted(cited_evidence(steps).items())
        if deps
    ]


# --------------------------------------------------------------- validator


def run_validator(body: str, fmt: str = ext.FORMAT) -> dict[str, Any]:
    """`{validator_version, grammar_version, ok, errors[]}`: the spec's `validator` object."""
    base = {"validator_version": scholialang.SCHOLIA_VALIDATOR_VERSION, "grammar_version": ext.GRAMMAR_VERSION}
    try:
        steps = parse_trace(body, fmt)
    except (ScholiaParseError, ValueError, KeyError, TypeError) as exc:
        return {**base, "ok": False, "errors": [{"rule": "parse", "atom_id": "", "message": str(exc)}]}
    except Exception as exc:  # parser raised something unexpected; still a failure, never a crash
        return {**base, "ok": False, "errors": [{"rule": "parse", "atom_id": "", "message": f"{type(exc).__name__}: {exc}"}]}
    result = scholialang.validate(steps)
    return {
        **base,
        "validator_version": result.scholia_validator_version,
        "ok": bool(result.ok),
        "errors": [{"rule": e.rule, "atom_id": e.atom_id or "", "message": e.message} for e in result.errors],
    }


# ------------------------------------------------------------------- build


@dataclass
class Provenance:
    """The extension's fields, short-keyed. `metadata()` gives the wire form."""

    fields: dict[str, Any] = field(default_factory=dict)

    @property
    def sha256(self) -> str:
        return self.fields["sha256"]

    def metadata(self, into: dict[str, Any] | None = None) -> dict[str, Any]:
        return ext.embed(self.fields, into)


def build_provenance(
    trace_body: str,
    fmt: str = ext.FORMAT,
    parents: Iterable[str] = (),
    claims: list[dict[str, Any]] | None = None,
    mode: str = "inline",
    uri: str | None = None,
    signer: Signer | None = None,
    *,
    redact: bool = False,
    full_sha256: bool = True,
    signer_jwk: dict[str, Any] | None = None,
    agent_card_url: str | None = None,
    audit: dict[str, Any] | None = None,
    max_inline_bytes: int = ext.MAX_INLINE_BYTES,
) -> dict[str, Any]:
    """Return the metadata dict (URI-prefixed keys) for a trace.

    The caller MUST also list `EXTENSION_URI` in the Message's or Artifact's
    `extensions` field (section 3, in-band signal).

    Args:
        trace_body: SRML text.
        fmt: must be "srml" (the only v1 format).
        parents: upstream trace hashes (bare hex or `sha256:` form; emitted prefixed).
        claims: declared Finding dependencies; auto-extracted when None.
        mode: "inline" ships the body; "reference" ships `uri` only (sha256 is
              identical in both modes, by the spec).
        uri: required in reference mode.
        signer: optional JWS signer over the sha256.
        redact: apply the redaction profile before hashing; sets `redacted: true`
              and, with `full_sha256`, the unredacted body's hash (section 4.3).
        signer_jwk: for requesters without an Agent Card: ship `signer: {kid, jwk}`
              so the receiver can verify the signature (identity self-asserted).
        agent_card_url: alternative `signer: {agent_card_url}` (section 4.4).
        audit: optional `{level, by, attestation_uri}` block (section 6).
        max_inline_bytes: limit on the canonical body's byte length in inline mode.
    """
    check_format(fmt)
    if mode not in ext.MODES:
        raise ValueError(f"unknown mode {mode!r}; expected one of {ext.MODES}")
    if mode == "reference" and not uri:
        raise ValueError("reference mode requires a uri")
    if not isinstance(trace_body, str):
        raise TypeError("trace_body must be SRML text")

    body = trace_body
    fields: dict[str, Any] = {}
    if redact:
        body = redact_srml(trace_body)
        fields["redacted"] = True
        if full_sha256:
            fields["full_sha256"] = sha256_of(trace_body)

    digest = sha256_of(body)
    validator = run_validator(body)
    if claims is None:
        claims = extract_claims(parse_trace(body)) if validator["ok"] else []

    if mode == "inline":
        size = len(canonical_bytes(body))
        if size > max_inline_bytes:
            raise ValueError(
                f"inline trace is {size} canonical bytes, over max_inline_bytes={max_inline_bytes}; use reference mode"
            )
        trace: dict[str, Any] = {"mode": "inline", "format": ext.FORMAT, "body": body}
    else:
        trace = {"mode": "reference", "format": ext.FORMAT, "uri": uri}

    fields = {
        "trace": trace,
        "sha256": digest,
        "parent": [normalize_hash(p) for p in parents],
        "claims": claims,
        "validator": validator,
        **fields,
    }
    if signer is not None:
        fields["signature"] = signer.sign(digest)
        if signer_jwk is not None:
            if "d" in signer_jwk:
                raise ValueError("signer_jwk must be a public JWK (it has a private 'd' member)")
            fields["signer"] = {"kid": signer.kid, "jwk": dict(signer_jwk)}
        elif agent_card_url:
            fields["signer"] = {"kid": signer.kid, "agent_card_url": agent_card_url}
    elif signer_jwk is not None or agent_card_url:
        raise ValueError("signer_jwk / agent_card_url need a signer")
    if audit is not None:
        fields["audit"] = audit
    return Provenance(fields).metadata()
