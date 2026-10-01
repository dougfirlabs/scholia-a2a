"""Build the provenance metadata block (spec section 4).

`build_provenance()` turns a Scholialang trace into the metadata fields of
the extension: canonical hash, declared claims, validator record, optional
signature, in inline or reference mode.
"""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any, Callable, Iterable, Iterator, Protocol
from xml.sax.saxutils import escape, quoteattr

import scholialang
from scholialang.atoms import Atom, Step
from scholialang.parser import ScholiaParseError

from . import ext

HASH_PREFIX = "sha256:"
FORMATS = ("srml", "json")

# Atom kinds a Finding may legitimately depend on, per the spec's example
# (`{finding: "F_01", depends_on: ["E_01"]}`) and scholialang's own
# Concluding rule (REFER targets must be Finding/Observation/Evidence).
EVIDENCE_KINDS = ("Evidence", "Observation")

_REFER_RE = re.compile(r"\bREFER:([A-Za-z0-9_:.\-]+)")


class Signer(Protocol):
    kid: str

    def sign(self, sha256: str) -> str: ...


# ---------------------------------------------------------------- canonical


def canonical_bytes(body: Any, fmt: str = "srml") -> bytes:
    """Canonical byte form of a trace body, the input to sha256.

    srml: text; CRLF -> LF, trailing whitespace stripped per line, leading and
          trailing blank lines dropped, one final newline, UTF-8.
    json: JSON value; keys sorted, no insignificant whitespace, UTF-8.
    """
    if fmt == "srml":
        if not isinstance(body, str):
            raise TypeError("srml body must be a str")
        lines = [ln.rstrip() for ln in body.replace("\r\n", "\n").replace("\r", "\n").split("\n")]
        text = "\n".join(lines).strip("\n")
        return (text + "\n").encode("utf-8")
    if fmt == "json":
        if isinstance(body, str):
            body = json.loads(body)
        return json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    raise ValueError(f"unknown trace format {fmt!r}; expected one of {FORMATS}")


def sha256_of(body: Any, fmt: str = "srml") -> str:
    """`sha256:<hex>` of the canonical body."""
    return HASH_PREFIX + hashlib.sha256(canonical_bytes(body, fmt)).hexdigest()


def normalize_hash(value: str) -> str:
    """Accept bare hex or `sha256:`-prefixed hex; return the prefixed form."""
    v = value.strip().lower()
    if v.startswith(HASH_PREFIX):
        v = v[len(HASH_PREFIX):]
    if not re.fullmatch(r"[0-9a-f]{64}", v):
        raise ValueError(f"not a sha256 hash: {value!r}")
    return HASH_PREFIX + v


# ------------------------------------------------------------- trace access


def walk_atoms(steps: Iterable[Step]) -> Iterator[Atom]:
    """Depth-first over every atom in a parsed trace, including children."""
    for step in steps:
        stack = list(step.atoms)
        while stack:
            atom = stack.pop(0)
            yield atom
            stack[:0] = list(atom.children)


def json_to_srml(body: Any) -> str:
    """Render the json format (`{"steps":[{"id","atoms":[...]}]}`) as SRML.

    Each atom is `{"kind","id","attrs":{},"content":"","children":[]}`. This
    is the canonical mapping used both to validate json-format traces and to
    hash-check that both formats describe the same trace.
    """
    if isinstance(body, str):
        body = json.loads(body)

    def atom_xml(a: dict[str, Any], indent: str) -> str:
        kind = a["kind"]
        attrs = {"id": a.get("id")} if a.get("id") else {}
        attrs.update(a.get("attrs") or {})
        attr_text = "".join(f" {k}={quoteattr(str(v))}" for k, v in attrs.items() if v is not None)
        content = escape(str(a.get("content") or ""))
        children = a.get("children") or []
        if not children and not content:
            return f"{indent}<{kind}{attr_text}/>"
        inner = content
        if children:
            inner += "\n" + "\n".join(atom_xml(c, indent + "  ") for c in children) + "\n" + indent
        return f"{indent}<{kind}{attr_text}>{inner}</{kind}>"

    out: list[str] = []
    for step in body.get("steps", []):
        sid = f' id={quoteattr(step["id"])}' if step.get("id") else ""
        out.append(f"<Step{sid}>")
        out.extend(atom_xml(a, "  ") for a in step.get("atoms", []))
        out.append("</Step>")
    return "\n".join(out) + "\n"


def parse_trace(body: Any, fmt: str = "srml") -> list[Step]:
    """Parse either format with scholialang; raises ScholiaParseError."""
    text = body if fmt == "srml" else json_to_srml(body)
    return scholialang.parse(text)


def redact_srml(body: str) -> str:
    """Redaction profile: keep atom kinds, ids, attributes and edges; drop prose.

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
            el.tail = "\n" if el.tail.strip() == "" else "\n"
        for child in el:
            scrub(child)

    for child in root:
        scrub(child)
    text = "".join(ET.tostring(c, encoding="unicode") for c in root)
    return text.strip() + "\n"


# ------------------------------------------------------------------ claims


def extract_claims(steps: Iterable[Step]) -> list[dict[str, Any]]:
    """Declared Finding -> Evidence dependencies, derived from the trace.

    A Finding depends on: (a) each REFER target in its operators that resolves
    to an Evidence/Observation atom, and (b) each Evidence atom whose `for`
    names the hypothesis the Finding closes (`for_hyp`). Findings with no
    dependencies are omitted. Output is sorted and deterministic.
    """
    atoms = list(walk_atoms(steps))
    by_id = {a.id: a for a in atoms if a.id}
    evidence_for_hyp: dict[str, list[str]] = {}
    for a in atoms:
        if a.kind == "Evidence" and a.id and getattr(a, "for_ref", None):
            evidence_for_hyp.setdefault(a.for_ref, []).append(a.id)
    claims: list[dict[str, Any]] = []
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
            deps.update(evidence_for_hyp.get(hyp, []))
        if deps:
            claims.append({"finding": a.id, "depends_on": sorted(deps)})
    claims.sort(key=lambda c: c["finding"])
    return claims


# --------------------------------------------------------------- validator


def run_validator(body: Any, fmt: str = "srml") -> dict[str, Any]:
    """`{version, ok, errors[]}` as the spec's `validator` object."""
    try:
        steps = parse_trace(body, fmt)
    except (ScholiaParseError, ValueError, KeyError, TypeError) as exc:
        return {
            "version": scholialang.SCHOLIA_VALIDATOR_VERSION,
            "ok": False,
            "errors": [{"rule": "parse", "atom_id": "", "message": str(exc)}],
        }
    except Exception as exc:  # parser raised something unexpected; still a failure, never a crash
        return {
            "version": scholialang.SCHOLIA_VALIDATOR_VERSION,
            "ok": False,
            "errors": [{"rule": "parse", "atom_id": "", "message": f"{type(exc).__name__}: {exc}"}],
        }
    result = scholialang.validate(steps)
    return {
        "version": result.scholia_validator_version,
        "ok": bool(result.ok),
        "errors": [
            {"rule": e.rule, "atom_id": e.atom_id or "", "message": e.message} for e in result.errors
        ],
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
    trace_body: Any,
    fmt: str = "srml",
    parents: Iterable[str] = (),
    claims: list[dict[str, Any]] | None = None,
    mode: str = "inline",
    uri: str | None = None,
    signer: Signer | None = None,
    *,
    redact: bool = False,
    audit: dict[str, Any] | None = None,
    max_inline_bytes: int = ext.MAX_INLINE_BYTES,
) -> dict[str, Any]:
    """Return the metadata dict (URI-prefixed keys) for a trace.

    Args:
        trace_body: SRML text, or a json-format trace (dict or JSON text).
        fmt: "srml" | "json".
        parents: upstream trace hashes (bare hex or `sha256:` form).
        claims: declared Finding dependencies; auto-extracted when None.
        mode: "inline" ships the body; "reference" ships `uri` only (sha256 is
              identical in both modes, by the spec).
        uri: required in reference mode.
        signer: optional JWS signer over the sha256.
        redact: apply the redaction profile (srml only) before hashing.
        audit: optional `{level, by, attestation_uri}` block (section 6).
    """
    if fmt not in FORMATS:
        raise ValueError(f"unknown trace format {fmt!r}")
    if mode not in ext.MODES:
        raise ValueError(f"unknown mode {mode!r}; expected one of {ext.MODES}")
    if mode == "reference" and not uri:
        raise ValueError("reference mode requires a uri")

    body = trace_body
    if redact:
        if fmt != "srml":
            raise ValueError("redaction profile is defined for srml bodies only")
        body = redact_srml(body)
    if fmt == "json" and isinstance(body, str):
        body = json.loads(body)

    digest = sha256_of(body, fmt)
    validator = run_validator(body, fmt)
    if claims is None:
        claims = extract_claims(parse_trace(body, fmt)) if validator["ok"] else []

    if mode == "inline":
        size = len(canonical_bytes(body, fmt))
        if size > max_inline_bytes:
            raise ValueError(
                f"inline trace is {size} bytes, over max_inline_bytes={max_inline_bytes}; use reference mode"
            )
        trace: dict[str, Any] = {"mode": "inline", "format": fmt, "body": body}
    else:
        trace = {"mode": "reference", "format": fmt, "uri": uri}

    fields: dict[str, Any] = {
        "trace": trace,
        "sha256": digest,
        "parent": [normalize_hash(p) for p in parents],
        "claims": claims,
        "validator": validator,
    }
    if signer is not None:
        fields["signature"] = signer.sign(digest)
    if audit is not None:
        fields["audit"] = audit
    return Provenance(fields).metadata()
