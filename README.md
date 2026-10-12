# scholia-a2a

Reference implementation and live demo of the **Scholia Provenance Extension for A2A**, spec **draft 0.2**
(https://scholialang.org/ext/a2a/provenance/v1).

This is a *draft community extension*, not an official A2A extension. It is a profile extension (`required: false`):
agents that ignore it interoperate unchanged.

What it does: an A2A agent attaches typed, machine-validatable reasoning provenance, written as a
[Scholialang](https://scholialang.org) trace (SRML), to the `metadata` map of a Message or Artifact and announces it in
that object's `extensions` field. A sha256 of the canonical trace, an optional Ed25519 JWS over that hash, declared
Finding → Evidence `claims`, and `parent` hash links let a receiver verify the trace and stitch the traces of delegating
and delegated agents into one provenance graph.

Built against `a2a-sdk==1.2.1` (A2A protocol 1.0, protobuf types) and `scholialang==0.7.2` (grammar 0.6.2).
Public source for the draft; not on PyPI. Install from a clone (below). Licensed under Apache-2.0 (see `LICENSE`).

## Quickstart

```bash
python3 -m venv .venv && .venv/bin/pip install -e '.[test]'
./demo/run_demo.sh          # starts analyst :9602 and planner :9601 on 127.0.0.1, runs the scenario, stops them
.venv/bin/python -m pytest  # 27 tests: unit (spec vectors, every 0.2 rule), walkthrough, end-to-end on ephemeral ports
```

`run_demo.sh` prints a PASS/FAIL table (35 checks) and writes `demo-out/provenance-graph.html` (self-contained, dark
theme, inline SVG, phone-friendly), `demo-out/walkthrough.html` (a nine-step "see it in action" page generated from the
run) and `demo-out/transcript.json` (every message, artifact and verification result). The walkthrough build refuses to
write if anything that looks like private-key material is found in the page, the graph or the transcript.

The scenario:

1. **planner → analyst, extension activated.** The planner writes a Goal / Constraint / Deciding trace, signs it with an
   ephemeral Ed25519 key and ships the public half as `signer: {kid, jwk}` (a requester has no Agent Card), puts it in
   the message's own metadata, lists the URI in `Message.extensions` and also sends the `A2A-Extensions` header. The
   analyst returns an Artifact that lists the URI in its own `extensions` and whose metadata carries a Hypothesis /
   Evidence (supports, refutes, neutral) / Finding trace, validated by scholialang, signed with the key published in its
   Agent Card, with `parent` = the planner's trace hash. It reports the requester's provenance back as "integrity
   verified, identity self-asserted". The planner verifies in the spec's order (signal, format, hash, signature,
   validator, claims), then runs four tamper tests (flip a polarity → hash fails; flip and re-hash → signature fails;
   claim an uncited dependency → claims fail; strip `extensions[]` → signal fails) and two rule tests (claims strict
   subset → warning; `format: "json"` → rejected).
2. **plain client → analyst, extension not activated.** Same question, no header, no `extensions[]`, no metadata: a
   normal answer with no provenance block (required=false compatibility).
3. **third party → planner agent over A2A.** The planner is itself an A2A agent; its artifact carries a signed closing
   trace whose parent is the analyst's hash, verified with the key on the planner's Agent Card: a three-node chain.

`./demo/run_demo.sh --llm` lets the analyst rewrite its one-sentence prose summary with `claude -p`; the trace itself is
always generated deterministically and never by a model. Off by default.

## Conformance (draft 0.2)

| # | Spec section | Rule | Implementation | Test |
| --- | --- | --- | --- | --- |
| 1 | §4.1, §7 | Canonicalization: CRLF/CR→LF, strip trailing whitespace, drop leading/trailing blank lines, one final LF, UTF-8; vectors A and B → `sha256:8c27fc…` | `provenance.canonical_bytes`, `sha256_of` | `test_spec_vectors_a_and_b_hash_identically`, `test_canonicalization_steps_individually` |
| 2 | §4, §4.1 | Emit `sha256:<64 lowercase hex>`; accept bare hex from 0.1 senders | `provenance.sha256_of`, `normalize_hash` | `test_hash_form_emit_prefixed_accept_bare` |
| 3 | §3 | In-band signal: sender lists the URI in `Message.extensions` / `Artifact.extensions`; receivers decide presence from that field; keys without the URI → failure | `ext.is_signalled`, `has_provenance(metadata, extensions)`, `provenance_from`, `verify_provenance(extensions=…)`, `verify_object`; demo agents set `extensions=[URI]` | `test_in_band_signal_decides_presence`, e2e `test_in_band_signal_alone_activates…`, demo TAMPER 4 |
| 4 | §3 | Header echo SHOULD; client must not depend on it | `demo/common.ExtensionEchoMiddleware`; planner observes with a raw probe and never uses it for a decision | e2e `test_header_echo`, demo "analyst echoes A2A-Extensions (SHOULD; observed, not relied on)" |
| 5 | §3 | Serialization tolerance: absent `required` = false; integral floats for numeric params | `ext.read_extension_entry` | `test_card_entry_tolerance_required_absent_and_integral_floats`, e2e `test_agent_card_declares_extension`, demo "card params tolerated" |
| 6 | §4 Formats | SRML is the only v1 format; unknown (or missing) `format` is rejected, never guessed | `provenance.check_format`; `verify` step 1; **the 0.1 `json` mapping was removed** (not kept behind a flag; §9.3 defers JSON to v2 with RFC 8785) | `test_format_srml_only_rejected_not_guessed`, demo "RULE: format other than srml" |
| 7 | §4.2 | cited = inline REFER to Evidence ∪ Evidence sharing the Finding's hypothesis; declared ⊆ cited else FAIL; strict subset → WARNING | `provenance.cited_evidence`, `extract_claims`, `verify._check_claims` | `test_claims_cited_set_is_refer_union_shared_hypothesis`, `test_claims_subset_rules`, demo TAMPER 3 + "RULE: claims strict subset" |
| 8 | §4.3 | Redaction: `redacted: true`, `sha256` over the shipped body, optional `full_sha256` | `build_provenance(redact=True, full_sha256=…)`, `redact_srml`; verify reports `redacted`/`full_sha256` | `test_redaction_flags_and_hashes` |
| 9 | §4.4 | Responders: `params.public_key_jwk` or `jwks_uri`; requesters MAY ship `signer: {kid, jwk}` or `{agent_card_url}`; self-asserted key = integrity, not identity | `Ed25519Verifier.from_jwk/from_jwks/from_signer_field`, `VerifyResult.identity` + `signature_statement`; planner signs with `signer`, analyst verifies and reports "integrity verified, identity self-asserted"; planner card publishes its key for the closing artifact | `test_responder_key_from_card_jwk_or_jwks`, `test_requester_signer_field_is_self_asserted`, `test_hash_and_signature_tamper_detected`, demo "requester signature verified by analyst via signer" |
| 10 | §3, §4 | `grammar_version` ("0.6.2") and `validator_version` ("0.7.2") replace `scholia_version`; validator record carries both | `ext.default_params`, `provenance.run_validator`; 0.1 `version` tolerated with a warning | `test_params_and_validator_carry_grammar_and_validator_versions`, demo "card params carry grammar_version…", "validator record carries…" |
| 11 | §4 | Metadata lives in the Message's/Artifact's own map, not the request-level map | `ext.provenance_from(obj)` reads `obj.metadata` + `obj.extensions`; analyst reads `context.message`, never `RequestContext.metadata` | `test_metadata_is_the_objects_own_map_not_request_level` |
| 12 | §4.1 | `max_inline_bytes` measured on canonical body bytes | `build_provenance` raises over the limit; `verify` warns, using the limit read from the card | `test_max_inline_bytes_measured_on_canonical_body`, demo "inline body within max_inline_bytes" |
| – | §5 | Verify in order: signal, format, hash, signature, validator re-run, claims; report every mismatch; traces are untrusted data | `verify.verify_provenance`, `VerifyResult.safe_summary` | `test_safe_summary_has_no_trace_text`, demo tamper tests |
| – | schema | `schema/provenance-v1.schema.json` at 0.2: `signer`, `redacted`, `full_sha256`, `format: const "srml"`, two-version validator, Agent Card entry def | | `test_schema_validates_produced_metadata_and_rejects_bad` |

All 12 numbered items are implemented and tested. Demo: 35/35 checks PASS.

## Package layout

| File | Purpose |
| --- | --- |
| `scholia_a2a/ext.py` | `EXTENSION_URI`, `GRAMMAR_VERSION`, `VALIDATOR_VERSION`, URI-prefixed key helpers (`key("sha256")`), `agent_extension()` / `read_extension_entry()` for the Agent Card entry, `is_activated()` (header), `is_signalled()` / `has_provenance(metadata, extensions)` (in-band), `provenance_from(message_or_artifact)`, `extract()` |
| `scholia_a2a/provenance.py` | `build_provenance(trace_body, parents, claims, mode, uri, signer, redact=, full_sha256=, signer_jwk=, agent_card_url=)` → metadata dict; canonicalization + sha256 (§4.1); claims (§4.2); redaction (§4.3); validator record |
| `scholia_a2a/verify.py` | `verify_provenance(metadata, fetch, verifier, extensions=, max_inline_bytes=, allow_self_asserted=)` → `VerifyResult` (signalled, format, hash, signature + identity, validator re-run, claims, parents, redaction, errors, warnings) with `safe_summary()`; `verify_object(message_or_artifact)` |
| `scholia_a2a/sign.py` | Ed25519 compact JWS over the hash; keygen; OKP JWK import/export; `from_jwks()`, `from_signer_field()` |
| `scholia_a2a/graph.py` | `ProvenanceGraph` (nodes = traces by hash, edges = parent links + intra-trace claims) and `render_html()` |
| `scholia_a2a/schema/provenance-v1.schema.json` | JSON Schema (2020-12) for the metadata block and the Agent Card entry |
| `demo/analyst.py`, `demo/planner.py` | the two A2A agents; `demo/common.py` assembles the Starlette app and adds the header echo middleware |
| `demo/plain_client.py`, `demo/scenario.py`, `demo/run_demo.sh`, `demo/walkthrough.py` | the non-activated client, the scenario runner, the one-shot launcher, the walkthrough page generator (with the private-key scan) |

## Metadata example

As returned by the analyst (body shortened). Keys are the extension URI plus `/<key>`; the Artifact also lists the URI
in its `extensions` field:

```json
{
  "https://scholialang.org/ext/a2a/provenance/v1/trace": {
    "mode": "inline", "format": "srml",
    "body": "<Step id=\"S_01\">\n  <Hypothesis id=\"H_01\">Dapr Agents and OpenTalon can interoperate over A2A without custom glue.</Hypothesis>\n  <Evidence id=\"E_01\" for=\"H_01\" polarity=\"supports\">…</Evidence>\n  <Evidence id=\"E_02\" for=\"H_01\" polarity=\"refutes\">…</Evidence>\n  ...\n  <Finding id=\"F_01\" for_hyp=\"H_01\" status=\"unmet\">REFER:E_01 REFER:E_02 REFER:E_03 REFER:E_04 …</Finding>\n</Step>\n"
  },
  "https://scholialang.org/ext/a2a/provenance/v1/sha256": "sha256:6ba19a1717d1…",
  "https://scholialang.org/ext/a2a/provenance/v1/parent": ["sha256:8184daa45da1…"],
  "https://scholialang.org/ext/a2a/provenance/v1/claims": [{ "finding": "F_01", "depends_on": ["E_01", "E_02", "E_03", "E_04"] }],
  "https://scholialang.org/ext/a2a/provenance/v1/validator": { "validator_version": "0.7.2", "grammar_version": "0.6.2", "ok": true, "errors": [] },
  "https://scholialang.org/ext/a2a/provenance/v1/signature": "eyJhbGciOiJFZERTQSIs….eyJraWQiOiJhbmFseXN0LTk2MDIiLCJzaGEyNTYiOi….<sig>"
}
```

The planner's request message adds, because a requester has no Agent Card:

```json
"https://scholialang.org/ext/a2a/provenance/v1/signer": { "kid": "planner-3511177",
  "jwk": { "kty": "OKP", "crv": "Ed25519", "x": "…", "kid": "planner-3511177", "alg": "EdDSA" } }
```

Agent Card entry (the analyst publishes its verification key here):

```json
{ "uri": "https://scholialang.org/ext/a2a/provenance/v1",
  "description": "Scholialang reasoning provenance on messages and artifacts",
  "required": false,
  "params": { "grammar_version": "0.6.2", "validator_version": "0.7.2",
              "modes": ["inline", "reference"], "signing": ["none", "jws"], "max_inline_bytes": 65536,
              "public_key_jwk": { "kty": "OKP", "crv": "Ed25519", "x": "…", "kid": "analyst-9602", "alg": "EdDSA" } } }
```

Programmatic use:

```python
from scholia_a2a import EXTENSION_URI, build_provenance, verify_object, Ed25519Signer, Ed25519Verifier
signer = Ed25519Signer.generate(kid="me")
meta = build_provenance(srml_text, parents=[upstream_hash], signer=signer)
artifact = Artifact(parts=[...], metadata=meta, extensions=[EXTENSION_URI])     # list the URI: in-band signal (MUST)
result = verify_object(artifact, verifier=Ed25519Verifier.from_jwk(card_jwk))   # reads its own metadata + extensions
result.ok, result.errors, result.warnings, result.signature_statement, result.safe_summary()
```

## Security notes

- **Traces are untrusted data.** `verify_provenance` parses and validates but never interprets content. Use
  `VerifyResult.safe_summary()` (ids, kinds, counts, polarity/status enums, errors) when something must go into a model's
  context; it contains no trace text. The demo analyst reports the requester's provenance to the caller as a safe summary
  only. The HTML pages render content escaped, for humans.
- **Mismatches are reported, never ignored.** Signal, format, hash, signature, validator and claims failures each set
  `ok=False` with a reason. A sender's `validator` record is advisory: the receiver re-runs scholialang and flags
  disagreement.
- **Hash then signature.** The hash binds content; the JWS binds the hash to a key. Tamper test 2 shows why both are needed:
  an attacker who edits and re-hashes passes the hash check and fails the signature.
- **Identity is stated honestly.** A key from an Agent Card (`identity: agent-card`) is as trustworthy as the card's
  transport or its signatures. A key from the `signer` field (`identity: self-asserted`) proves only that the trace was
  not altered after signing; `signature_statement` says "integrity verified, identity self-asserted". Pass
  `allow_self_asserted=False` to refuse that fallback. `agent_card_url` is never fetched automatically (the URL is
  untrusted data; resolve it yourself and pass `verifier=`).
- **Privacy.** `mode="reference"` ships only a URI plus hash; `redact=True` applies the redaction profile (kinds, ids,
  attributes and `REFER:` edges kept, prose removed) before hashing, sets `redacted: true` and, by default,
  `full_sha256`. `max_inline_bytes` is enforced on build and warned on verify, both on canonical bytes.
- **Keys.** The demo generates fresh Ed25519 keys per process and never writes them. The walkthrough generator scans the
  page, the graph and the transcript (text and a structural JWK walk) for private material and refuses to write on a hit.
- **Never a trust claim.** A passing result is audit level L1 (structural). It says the trace is well-formed, unmodified,
  announced and internally consistent, not that the agent's stated reasoning is faithful (spec §6, claims boundary).
- The demo binds to 127.0.0.1 only, uses in-memory task stores and has no auth; it is a demo.

## Spec feedback

### Resolved in draft 0.2 (raised by the 0.1 implementation)

1. Canonicalization defined (§4.1) with test vectors (§7). 2. Hash form fixed to `sha256:<hex>`, bare hex accepted from
0.1. 3. `extensions[]` made the authoritative in-band signal. 4. Header echo downgraded to SHOULD; clients may not rely
on it. 5. Serialization tolerance (absent `required`, integral floats). 6. Identity binding: `public_key_jwk` /
`jwks_uri` for responders, `signer` for requesters. 7. Claims semantics (union; subset warns, superset fails).
8. `json` format dropped from v1 (deferred to v2, §9.3). 9. Redaction: `redacted`, `full_sha256`. 10. `grammar_version`
/ `validator_version`. 11. "metadata" means the object's own map. 12. `max_inline_bytes` on canonical bytes.

### Open after implementing 0.2 (candidates for 0.3)

1. **JWS payload shape is unspecified.** §4.4 says "a compact JWS over the sha256 string". This implementation signs a
   JSON payload `{"sha256": "<hash>", "kid": "<kid>"}` with protected header `{"alg": "EdDSA", "typ": "JWT", "kid"}`.
   A second implementation could equally sign the raw string bytes. Fix the payload (and add a signature test vector:
   fixed key, fixed hash, expected JWS) or interop will fail silently with `signature: failed`.
2. **Three `kid`s.** `signer.kid`, `signer.jwk.kid` and the JWS header `kid` can all be present. We require them to
   agree and fail otherwise; the spec should say so.
3. **Observation atoms and the cited set.** §4.2 defines the cited set over Evidence only, but scholialang lets a
   Finding `REFER:` an Observation and Concluding may cite Observation/Finding. We follow §4.2 strictly, so a declared
   dependency on an Observation is a superset failure. Say explicitly whether Observation counts.
4. **Absent `format`.** "Reject unknown formats rather than guess" is followed to its conclusion: a missing `format` is
   rejected too, since defaulting to srml is a guess. The spec should state this (or make `format` optional with a
   default, which would be a 0.1-compat decision).
5. **In-band signal without the header.** §3 makes the header the activation request (MAY) and `extensions[]` the
   presence signal. What should a responder do with a request that carries provenance in-band but no header? We treat it
   as activated (it is unambiguous evidence of support); the spec should say whether that is intended.
6. **`extensions[]` listed, no keys.** We fail verification (the URI is announced but nothing is there). The spec could
   instead allow listing the URI as a bare "I speak this" signal on messages that carry no trace. Pick one.
7. **Whole-Finding omission.** A claims list that leaves out a Finding which does cite evidence: strict subset at the
   list level. We warn, consistent with §4.2; the spec should say whether omitting the entry is a subset or a missing
   SHOULD.
8. **`full_sha256` disclosure.** The receiver cannot check `full_sha256`; a later disclosure step (send the full body,
   match `full_sha256`, confirm the redaction is a projection of it) is implied but not specified, and nothing says the
   redacted body must still validate (ours does, by construction).
9. **`agent_card_url` is a fetch of untrusted input.** A receiver that resolves `signer.agent_card_url` fetches a URL
   named by the sender (SSRF surface). Recommend allow-lists or same-origin rules; we never auto-fetch it.
10. **`jwks_uri` selection and caching.** Nothing says how to choose among several keys (we require exactly one
    Ed25519 key matching `kid`) or how long a fetched set may be cached.
11. **Reference-mode size.** `max_inline_bytes` bounds inline bodies; nothing bounds what a receiver should be willing
    to fetch in reference mode. Suggest the same limit applies to the fetched body.
12. **`grammar_version` mismatch.** A receiver cannot "re-run" a grammar version; we warn when the declared grammar
    differs from ours. Say whether a grammar mismatch is a warning or a failure.

## Status

Draft 0.2 reference implementation, October 3 2026 (0.1: September 30 2026). Published as the public reference
implementation for the draft community extension; the spec and this code may still change before a non-draft release.
Feedback: darren@dougfirlabs.com, or open an issue.

## License

Apache License 2.0; see `LICENSE`. This covers the code, schema, demo and this README. The spec text at
https://scholialang.org/ext/a2a/provenance/v1 is licensed separately, under the scholialang.org site's terms.
