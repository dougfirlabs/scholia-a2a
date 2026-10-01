# scholia-a2a

Reference implementation and live demo of the **Scholia Provenance Extension for A2A**, draft 0.1.

This is a *draft community extension*, not an official A2A extension. Extension URI (intended, not yet hosted):
`https://scholialang.org/ext/a2a/provenance/v1`. It is a profile extension (`required: false`): agents that ignore it
interoperate unchanged.

What it does: an A2A agent attaches typed, machine-validatable reasoning provenance, written as a
[Scholialang](https://scholialang.org) trace, to the `metadata` map of a Message or Artifact. A sha256 of the canonical
trace, an optional Ed25519 JWS over that hash, declared Finding → Evidence `claims`, and `parent` hash links let a
receiver verify the trace and stitch the traces of delegating and delegated agents into one provenance graph.

Built against `a2a-sdk==1.2.1` (A2A protocol 1.0, protobuf types) and `scholialang==0.7.2`.

## Quickstart

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
./demo/run_demo.sh          # starts analyst :9602 and planner :9601 on 127.0.0.1, runs the scenario, stops them
.venv/bin/python -m pytest  # 20 tests: unit + end-to-end on ephemeral ports
```

`run_demo.sh` prints a PASS/FAIL table (22 checks) and writes `demo-out/provenance-graph.html` (self-contained,
dark theme, inline SVG, phone-friendly) and `demo-out/transcript.json` (every message, artifact and verification result).

The scenario:

1. **planner → analyst, extension activated.** The planner writes a Goal / Constraint / Deciding trace, puts it in the
   message metadata, sends `A2A-Extensions: https://scholialang.org/ext/a2a/provenance/v1`. The analyst returns an
   Artifact whose metadata carries a Hypothesis / Evidence (supports, refutes, neutral) / Finding trace, validated by
   scholialang, signed with the key published in its Agent Card, with `parent` = the planner's trace hash. The planner
   verifies hash, signature, validator and claims, then runs three tamper tests on copies (flip a polarity → hash fails;
   flip and re-hash → signature fails; claim an uncited dependency → claims fail).
2. **plain client → analyst, extension not activated.** Same question, no header, no metadata: a normal answer with no
   provenance block (required=false compatibility).
3. **third party → planner agent over A2A.** The planner is itself an A2A agent; its artifact carries a closing trace whose
   parent is the analyst's hash, giving a three-node chain planner → analyst → planner.

`./demo/run_demo.sh --llm` lets the analyst rewrite its one-sentence prose summary with `claude -p`; the trace itself is
always generated deterministically and never by a model. Off by default.

## Package layout

| File | Purpose |
| --- | --- |
| `scholia_a2a/ext.py` | `EXTENSION_URI`, URI-prefixed key helpers (`key("sha256")`), `agent_extension()` builder for the Agent Card entry, `is_activated()`, `extract()` |
| `scholia_a2a/provenance.py` | `build_provenance(trace_body, fmt, parents, claims, mode, uri, signer, redact=...)` → metadata dict; canonicalization + sha256; claims auto-extraction; validator record; redaction profile; json ↔ srml mapping |
| `scholia_a2a/verify.py` | `verify_provenance(metadata, fetch, verifier)` → `VerifyResult` (hash, signature, validator re-run, claims, parents, errors) with `safe_summary()` |
| `scholia_a2a/sign.py` | Ed25519 compact JWS over the hash; keygen; OKP JWK import/export |
| `scholia_a2a/graph.py` | `ProvenanceGraph` (nodes = traces by hash, edges = parent links + intra-trace claims) and `render_html()` |
| `scholia_a2a/schema/provenance-v1.schema.json` | JSON Schema (2020-12) for the metadata block |
| `demo/analyst.py`, `demo/planner.py` | the two A2A agents; `demo/common.py` assembles the Starlette app and adds the header echo middleware |
| `demo/plain_client.py`, `demo/scenario.py`, `demo/run_demo.sh` | the non-activated client, the scenario runner, the one-shot launcher |

## Metadata example

As returned by the analyst (body shortened). Keys are the extension URI plus `/<key>`:

```json
{
  "https://scholialang.org/ext/a2a/provenance/v1/trace": {
    "mode": "inline", "format": "srml",
    "body": "<Step id=\"S_01\">\n  <Hypothesis id=\"H_01\">Dapr Agents and OpenTalon can interoperate over A2A without custom glue.</Hypothesis>\n  <Evidence id=\"E_01\" for=\"H_01\" polarity=\"supports\">Dapr Agents and OpenTalon both publish an Agent Card at /.well-known/agent-card.json</Evidence>\n  <Evidence id=\"E_02\" for=\"H_01\" polarity=\"refutes\">Dapr Agents speaks A2A 0.3 while OpenTalon speaks A2A 1.0; the extension header name differs between 0.3 and 1.0</Evidence>\n  ...\n  <Finding id=\"F_01\" for_hyp=\"H_01\" status=\"unmet\">REFER:E_01 REFER:E_02 REFER:E_03 REFER:E_04 Dapr Agents and OpenTalon need a compatibility shim ...</Finding>\n</Step>\n"
  },
  "https://scholialang.org/ext/a2a/provenance/v1/sha256": "sha256:6ba19a1717d1…",
  "https://scholialang.org/ext/a2a/provenance/v1/parent": ["sha256:8184daa45da1…"],
  "https://scholialang.org/ext/a2a/provenance/v1/claims": [{ "finding": "F_01", "depends_on": ["E_01", "E_02", "E_03", "E_04"] }],
  "https://scholialang.org/ext/a2a/provenance/v1/validator": { "version": "0.7.2", "ok": true, "errors": [] },
  "https://scholialang.org/ext/a2a/provenance/v1/signature": "eyJhbGciOiJFZERTQSIs….eyJraWQiOiJhbmFseXN0LTk2MDIiLCJzaGEyNTYiOi….<sig>"
}
```

Agent Card entry (the analyst also publishes its verification key here):

```json
{ "uri": "https://scholialang.org/ext/a2a/provenance/v1",
  "description": "Scholialang reasoning provenance on messages and artifacts",
  "required": false,
  "params": { "scholia_version": "0.7", "modes": ["inline", "reference"], "signing": ["none", "jws"],
              "max_inline_bytes": 65536,
              "public_key_jwk": { "kty": "OKP", "crv": "Ed25519", "x": "…", "kid": "analyst-9602", "alg": "EdDSA" } } }
```

Programmatic use:

```python
from scholia_a2a import build_provenance, verify_provenance, Ed25519Signer, Ed25519Verifier
signer = Ed25519Signer.generate(kid="me")
meta = build_provenance(srml_text, parents=[upstream_hash], signer=signer)   # -> dict for Artifact(metadata=meta)
result = verify_provenance(meta, verifier=Ed25519Verifier.from_jwk(signer.public_jwk()))
result.ok, result.errors, result.safe_summary()
```

## Security notes

- **Traces are untrusted data.** `verify_provenance` parses and validates but never interprets content. Use
  `VerifyResult.safe_summary()` (ids, kinds, counts, polarity/status enums, errors) when something must go into a model's
  context; it contains no trace text. The demo analyst reports the requester's provenance to the caller as a safe summary
  only. The HTML graph renders content escaped, for humans.
- **Mismatches are reported, never ignored.** Hash, signature, validator and claims failures each set `ok=False` with a
  reason. A sender's `validator` record is advisory: the receiver re-runs scholialang and flags disagreement.
- **Hash then signature.** The hash binds content; the JWS binds the hash to a key. Tamper test 2 shows why both are needed:
  an attacker who edits and re-hashes passes the hash check and fails the signature.
- **Key discovery.** The demo publishes the signing public key in the Agent Card extension params. That is only as
  trustworthy as the card's transport (HTTPS) or its `signatures`; an unsigned card over plain HTTP binds nothing. Requester
  traces in *message* metadata have no card to carry a key, so the analyst records them as `signature: none`.
- **Privacy.** `mode="reference"` ships only a URI plus hash; `redact=True` applies the redaction profile (kinds, ids,
  attributes and `REFER:` edges kept, prose removed) before hashing. `max_inline_bytes` is enforced on build and warned on
  verify.
- **Never a trust claim.** A passing result is audit level L1 (structural). It says the trace is well-formed, unmodified,
  and internally consistent, not that the agent's stated reasoning is faithful (spec section 6, claims boundary).
- The demo binds to 127.0.0.1 only, uses in-memory task stores and fresh keys per process, and has no auth; it is a demo.

## Spec feedback

Things the implementation taught us about draft 0.1, for the next revision:

1. **Define canonicalization.** The spec hashes "the canonical trace body" without saying what canonical means; two
   implementations will not agree on hashes. This implementation uses: srml → CRLF→LF, trailing whitespace stripped per
   line, leading/trailing blank lines dropped, one final newline, UTF-8; json → sorted keys, no whitespace (JCS-like).
2. **Hash string form is inconsistent.** Section 4 shows `sha256: "9f2c…"` (bare hex) but `parent: ["sha256:41ab…"]`
   (prefixed). We emit the `sha256:` prefix everywhere (matching scholialang's `canonical_id` convention) and accept bare
   hex; the schema allows both. Pick one.
3. **Use the native `extensions` field too.** A2A 1.0 `Message` and `Artifact` carry an `extensions: string[]` field for
   exactly this purpose; the spec's data model never mentions it. We set it alongside the metadata keys. Recommend: senders
   MUST list the URI in `extensions` on any Message/Artifact that carries provenance keys.
4. **The header echo is not provided by a2a-sdk 1.2.1.** The SDK parses the inbound `A2A-Extensions` header into
   `RequestContext.requested_extensions` but does not echo it; we added ASGI middleware. Worse, the SDK *client* exposes no
   response headers, so an SDK client cannot observe the echo at all (the demo probes the endpoint with raw httpx). An
   in-band activation signal (item 3) is the practical one.
5. **`required: false` will not appear on the wire.** proto3 JSON serialization omits default-valued fields, so the
   SDK-served card shows no `required` key. Receivers must treat absence as false; the spec should say so. Likewise
   `max_inline_bytes` round-trips through `google.protobuf.Struct` as a double: the served card literally says `65536.0`.
6. **Identity binding (open question, section 8).** We chose `params.public_key_jwk` (Ed25519 OKP JWK) on the Agent Card
   entry, with `kid` in the JWS header. It works for responders. Suggest the spec allow `public_key_jwk` or `jwks_uri` in
   params and recommend Agent Card signatures to bind them. Requesters (pure clients) have no card: allow an optional
   `signer: {kid, jwk}` field or an `agent_card_url` so responders can verify requester signatures.
7. **`claims` semantics need one sentence.** Scholialang expresses Finding → Evidence dependency two ways: an inline
   `REFER:E_01` in the Finding, and indirectly via `Evidence.for = H_01` ← `Finding.for_hyp = H_01`. We define
   `depends_on` as the union; declared claims may be a subset of what the trace cites (warning), never a superset (failure).
8. **`format: "json"` has no definition.** scholialang 0.7.2 has no JSON wire format. We defined a minimal one
   (`{"steps":[{"id","atoms":[{"kind","id","attrs","content","children"}]}]}`) that maps 1:1 onto SRML for validation.
   Either specify it or drop `json` from v1.
9. **Redaction and the hash.** "sha256 identical in both modes" covers inline vs reference, but a redacted trace is a
   different body with a different hash. We hash what is shipped (so verification works) and note that the full trace's
   hash is then unknown to the receiver. Consider an optional `full_sha256` (or make redaction a mode).
10. **Version naming.** `params.scholia_version: "0.7"` is ambiguous: the scholialang *package/validator* is 0.7.2 while
    the *grammar* it implements is v0.6.2. Suggest `grammar_version` and `validator_version`.
11. **Which `metadata`?** In the SDK, `SendMessageRequest.metadata` and `Message.metadata` are different maps, and
    `RequestContext.metadata` exposes the request-level one. The spec means the Message's map; say so explicitly.
12. **`max_inline_bytes` measurement.** We measure canonical body bytes. The spec should state whether it means the body or
    the serialized metadata value.

## Status

Draft 0.1 reference implementation, September 30 2026. No remote, not published. Feedback: darren@dougfirlabs.com.
