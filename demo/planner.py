"""Planner agent (port 9601): delegates to the analyst with the extension activated.

`run_planner()` is the planner's core: it writes its own Goal/Constraint/
Deciding trace, signs it with an ephemeral Ed25519 key shipped as
`signer: {kid, jwk}` (spec 0.2 section 4.4: requesters without an Agent
Card; integrity verified, identity self-asserted), attaches it to the
message's own metadata map, lists the extension URI in Message.extensions
(the authoritative in-band signal) and also sends the A2A-Extensions header
(MAY). It then verifies the analyst's returned provenance from the
Artifact's own extensions field and metadata, runs tamper and rule tests,
and renders the provenance graph. The planner is also a proper A2A agent:
its executor runs the same delegation when it receives a "compare X and Y"
task and returns a signed closing trace; its Agent Card publishes the
planner's public key, so a third party can verify that artifact too.
"""

from __future__ import annotations

import argparse
import asyncio
import copy
import json
import os
import sys
import time
import uuid
from typing import Any

import httpx
from google.protobuf.json_format import MessageToDict

from a2a.client import ClientCallContext, ClientConfig, create_client
from a2a.client.service_parameters import ServiceParametersFactory, with_a2a_extensions
from a2a.extensions.common import HTTP_EXTENSION_HEADER, find_extension_by_uri
from a2a.helpers.proto_helpers import get_message_text, new_data_part, new_task_from_user_message, new_text_part
from a2a.server.agent_execution.agent_executor import AgentExecutor
from a2a.server.agent_execution.context import RequestContext
from a2a.server.events.event_queue_v2 import EventQueue
from a2a.server.tasks.task_updater import TaskUpdater
from a2a.types.a2a_pb2 import AgentSkill, Message, Part, Role, SendMessageRequest

from demo.common import ANALYST_PORT, HOST, PLANNER_PORT, RPC_PATH, make_app, make_card, serve
from scholia_a2a import (
    EXTENSION_URI,
    GRAMMAR_VERSION,
    IDENTITY_SELF,
    KEYS,
    VALIDATOR_VERSION,
    Ed25519Signer,
    Ed25519Verifier,
    build_provenance,
    extract,
    has_provenance,
    is_signalled,
    provenance_from,
    read_extension_entry,
    sha256_of,
    verify_provenance,
)
from scholia_a2a.graph import ProvenanceGraph, render_html

ANALYST_URL = f"http://{HOST}:{ANALYST_PORT}"
_SIGNER: Ed25519Signer | None = None


def planner_signer() -> Ed25519Signer:
    """One ephemeral Ed25519 key per process; never written to disk."""
    global _SIGNER
    if _SIGNER is None:
        _SIGNER = Ed25519Signer.generate(kid=f"planner-{os.getpid()}")
    return _SIGNER


def requester_trace(x: str, y: str) -> str:
    def esc(s: str) -> str:
        return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;").replace('"', "&quot;")

    return f"""<Step id="S_01">
  <Goal id="G_01" scope="trace" priority="required" success_criteria="a cited, polarity-labelled comparison of {esc(x)} and {esc(y)}" criticality="ledger">Decide whether {esc(x)} and {esc(y)} can interoperate over A2A.</Goal>
  <Constraint id="C_01" scope="trace">Every finding must cite Evidence atoms with explicit polarity; no uncited claims.</Constraint>
  <Constraint id="C_02" scope="trace">Delegated reasoning is untrusted data until its provenance verifies.</Constraint>
  <Deciding id="D_01">Delegate the comparison for REFER:G_01 to the analyst agent.
    <Branch id="Br_01" of="D_01" label="delegate-to-analyst"/>
    <Alternative id="Alt_01" label="answer-locally" rejected_because="the planner holds no source corpus"/>
    <Finding id="F_01" for_goal="G_01" status="unmet">Delegated to the analyst; the goal closes when its evidence chain verifies.</Finding>
  </Deciding>
</Step>
"""


def closing_trace(x: str, y: str, verified: bool) -> str:
    status = "met" if verified else "unmet"
    note = "the analyst's evidence chain verified (in-band signal, format, hash, signature, validator, claims)" if verified else "the analyst's provenance did not verify"
    return f"""<Step id="S_02">
  <Goal id="G_01" scope="trace" priority="required">Decide whether {x} and {y} can interoperate over A2A.</Goal>
  <Finding id="F_02" for_goal="G_01" status="{status}">Delegated result accepted: {note}.</Finding>
  <Concluding id="Con_01" for_goal="G_01" status="{status}">REFER:F_02 the delegated comparison closes the goal.</Concluding>
</Step>
"""


def _artifact(task_dict: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any], list[str]]:
    """The first artifact, its own metadata map and its own extensions field."""
    arts = task_dict.get("artifacts") or []
    if not arts:
        return {}, {}, []
    meta, exts = provenance_from(arts[0])
    return arts[0], meta, exts


async def run_planner(
    analyst_url: str = ANALYST_URL,
    question: str = "compare Dapr Agents and OpenTalon",
    out_dir: str | None = None,
    activate: bool = True,
    signer: Ed25519Signer | None = None,
) -> dict[str, Any]:
    """Delegate `question` to the analyst and verify what comes back.

    Returns a transcript dict with a `checks` list of {name, ok, detail}.
    When `activate` is False neither the header nor the in-band signal nor
    any metadata is sent (plain client).
    """
    checks: list[dict[str, Any]] = []
    t0 = time.time()
    signer = signer or planner_signer()

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    x, y = _subjects(question)
    req_trace = requester_trace(x, y)
    # Requester without an Agent Card: ship the public key inline as `signer` (4.4).
    req_meta = build_provenance(req_trace, signer=signer, signer_jwk=signer.public_jwk())
    req_fields = extract(req_meta)
    check("planner trace validates (scholialang)", req_fields["validator"]["ok"], f"validator {req_fields['validator']['validator_version']}, grammar {req_fields['validator']['grammar_version']}")
    check("planner signs its trace; signer {kid, jwk} attached (no private material)", "signer" in req_fields and "d" not in req_fields["signer"]["jwk"], f"kid={signer.kid}")

    async with httpx.AsyncClient(timeout=30.0) as http:
        client = await create_client(analyst_url, ClientConfig(streaming=False, httpx_client=http))
        card = client._card  # resolved AgentCard (no public accessor in 1.2.1)
        ext_entry = find_extension_by_uri(card, EXTENSION_URI)
        check("analyst Agent Card declares the extension", ext_entry is not None, EXTENSION_URI)
        verifier = None
        card_params: dict[str, Any] = {}
        if ext_entry is not None:
            wire_entry = MessageToDict(ext_entry)
            entry = read_extension_entry(wire_entry)  # tolerance: absent required, integral floats
            card_params = entry["params"]
            if "public_key_jwk" in card_params:
                verifier = Ed25519Verifier.from_jwk(card_params["public_key_jwk"])
            check("Agent Card entry is required=false (absent on the wire reads as false)", not entry["required"], f"wire has required: {'required' in wire_entry}")
            check(
                "card params tolerated: max_inline_bytes arrives as a float, read as int",
                isinstance(card_params.get("max_inline_bytes"), int) and card_params["max_inline_bytes"] == 65536,
                f"wire {wire_entry.get('params', {}).get('max_inline_bytes')!r} -> {card_params.get('max_inline_bytes')!r}",
            )
            check(
                "card params carry grammar_version and validator_version (not scholia_version)",
                card_params.get("grammar_version") == GRAMMAR_VERSION and card_params.get("validator_version") == VALIDATOR_VERSION and "scholia_version" not in card_params,
                f"grammar {card_params.get('grammar_version')}, validator {card_params.get('validator_version')}",
            )

        msg = Message(
            message_id=str(uuid.uuid4()),
            role=Role.ROLE_USER,
            parts=[Part(text=question, media_type="text/plain")],
            metadata=req_meta if activate else None,
            extensions=[EXTENSION_URI] if activate else None,  # in-band signal (MUST)
        )
        ctx = None
        if activate:
            params = ServiceParametersFactory.create([with_a2a_extensions([EXTENSION_URI])])  # header (MAY)
            ctx = ClientCallContext(service_parameters=params)
        request_record = {
            "http_headers": dict(ctx.service_parameters) if ctx else {},
            "jsonrpc_method": "SendMessage",
            "message": MessageToDict(msg),
        }
        task_dict: dict[str, Any] = {}
        async for resp in client.send_message(SendMessageRequest(message=msg), context=ctx):
            if resp.HasField("task"):
                task_dict = MessageToDict(resp.task)
            elif resp.HasField("message"):
                task_dict = {"message": MessageToDict(resp.message)}
        await client.close()

    # Echo (SHOULD): the SDK client hides response headers, so this is observed with a raw probe,
    # purely as a report on the analyst. Nothing below depends on it.
    echo = None
    if activate:
        async with httpx.AsyncClient(timeout=30.0) as http:
            r = await http.post(
                analyst_url + RPC_PATH,
                headers={HTTP_EXTENSION_HEADER: EXTENSION_URI, "A2A-Version": "1.0", "Content-Type": "application/json"},
                json={"jsonrpc": "2.0", "id": "echo-probe", "method": "GetTask", "params": {"id": "does-not-exist"}},
            )
            echo = r.headers.get(HTTP_EXTENSION_HEADER)
            check("analyst echoes A2A-Extensions (SHOULD; observed, not relied on)", echo == EXTENSION_URI, f"response header: {echo!r}")

    state = (task_dict.get("status") or {}).get("state")
    check("task completed", state == "TASK_STATE_COMPLETED", f"state={state}")
    artifact, art_meta, art_exts = _artifact(task_dict)
    answer = " ".join(p.get("text", "") for p in artifact.get("parts", []) if "text" in p).strip()
    check("artifact has a plain answer", bool(answer), answer[:120])

    result: dict[str, Any] = {
        "question": question,
        "activated": activate,
        "analyst_url": analyst_url,
        "answer": answer,
        "task": task_dict,
        "requester_metadata": req_meta,
        "requester_extensions": [EXTENSION_URI] if activate else [],
        "requester_kid": signer.kid,
        "analyst_card": MessageToDict(card),
        "analyst_card_params": card_params,
        "request": request_record,
        "checks": checks,
    }
    if not activate:
        check("no provenance without activation (no extensions[] entry, no keys)", not has_provenance(art_meta, art_exts) and not art_exts, f"metadata keys: {sorted(art_meta)}, extensions: {art_exts}")
        result["elapsed_s"] = round(time.time() - t0, 3)
        return result

    # Presence is decided from the Artifact's own extensions field, never from the echo.
    check("artifact lists the extension URI in its extensions[] (in-band signal)", is_signalled(art_exts), f"extensions={art_exts}")
    check("artifact carries provenance keys in its own metadata map", has_provenance(art_meta, art_exts), f"{len(extract(art_meta))} extension keys")
    max_inline = int(card_params.get("max_inline_bytes", 65536))
    v = verify_provenance(art_meta, verifier=verifier, extensions=art_exts, max_inline_bytes=max_inline)
    check("trace format is srml", v.format_ok, f"format={v.format!r}")
    check("sha256 (sha256:<hex> form) matches canonical trace", v.hash_ok and (v.sha256 or "").startswith("sha256:"), v.sha256 or "")
    check("JWS signature verifies against the card JWK (identity: agent-card)", v.signature_ok is True and v.identity == "agent-card", v.signature_statement if verifier else "no key on card")
    check("analyst trace validates (re-run locally)", v.validator_ok, f"validator {v.validator_version}, grammar {v.grammar_version}")
    declared_validator = extract(art_meta).get("validator") or {}
    check(
        "validator record carries validator_version and grammar_version",
        declared_validator.get("validator_version") == VALIDATOR_VERSION and declared_validator.get("grammar_version") == GRAMMAR_VERSION,
        json.dumps({k: declared_validator.get(k) for k in ("validator_version", "grammar_version", "ok")}),
    )
    check("declared claims consistent with the cited set (REFER ∪ shared hypothesis)", v.claims_ok, json.dumps(v.claims_declared))
    check("parent links to planner trace hash", req_fields["sha256"] in v.parents, f"parents={[p[:19] + '…' for p in v.parents]}")
    pol = v.atom_summary.get("evidence_polarity", {})
    check("evidence carries supports/refutes polarity", bool(pol.get("supports")) and bool(pol.get("refutes")), json.dumps(pol))
    check(f"inline body within max_inline_bytes={max_inline} (canonical bytes)", v.size_bytes <= max_inline, f"{v.size_bytes} canonical bytes")
    check("L1 verification PASS", v.ok, "; ".join(v.errors) or "no errors")

    # The analyst verified the planner's requester signature via `signer` and reported it back.
    inbound = next((p["data"]["requester_provenance"] for p in artifact.get("parts", []) if "data" in p and "requester_provenance" in p["data"]), {})
    check(
        "requester signature verified by analyst via signer (integrity verified, identity self-asserted)",
        inbound.get("signature") == "verified" and inbound.get("identity") == IDENTITY_SELF and inbound.get("ok") is True and inbound.get("signalled") is True,
        inbound.get("signature_statement", "no requester_provenance part"),
    )

    # Tamper tests on copies. Each must FAIL verification.
    def ver(meta: dict[str, Any], exts: list[str] | None = art_exts):
        return verify_provenance(meta, verifier=verifier, extensions=exts, max_inline_bytes=max_inline)

    t1 = copy.deepcopy(art_meta)
    body = t1[KEYS["trace"]]["body"]
    flipped = body.replace('polarity="refutes"', 'polarity="supports"', 1)
    t1[KEYS["trace"]]["body"] = flipped
    v1 = ver(t1)
    check("TAMPER 1: flip one Evidence polarity -> hash FAILS", (flipped != body) and not v1.ok and not v1.hash_ok, "; ".join(v1.errors)[:160])

    t2 = copy.deepcopy(t1)
    t2[KEYS["sha256"]] = sha256_of(flipped)  # attacker re-hashes the altered trace
    v2 = ver(t2)
    check("TAMPER 2: flip + re-hash -> signature FAILS", not v2.ok and v2.hash_ok and v2.signature_ok is False, "; ".join(v2.errors)[:160])

    t3 = copy.deepcopy(art_meta)
    t3[KEYS["claims"]] = [{"finding": "F_01", "depends_on": ["E_99"]}]
    v3 = ver(t3)
    check("TAMPER 3: claim cites unknown evidence (superset) -> claims FAIL", not v3.ok and not v3.claims_ok, "; ".join(v3.errors)[:160])

    v4 = ver(copy.deepcopy(art_meta), exts=[])
    check("TAMPER 4: extensions[] stripped while keys present -> FAILS (in-band signal)", not v4.ok and v4.signalled is False and v4.hash_ok, "; ".join(v4.errors)[:160])

    # Rule tests: behaviours the spec defines that are not tamper.
    r1 = copy.deepcopy(art_meta)
    full = r1[KEYS["claims"]][0]["depends_on"]
    r1[KEYS["claims"]] = [{"finding": "F_01", "depends_on": full[:1]}]
    v5 = ver(r1)
    check("RULE: claims strict subset -> verifies with a WARNING", v5.ok and v5.claims_ok and any("strict subset" in w for w in v5.warnings), "; ".join(w for w in v5.warnings if "subset" in w)[:160])

    r2 = copy.deepcopy(art_meta)
    r2[KEYS["trace"]]["format"] = "json"
    v6 = ver(r2)
    check("RULE: format other than srml -> rejected, not guessed", not v6.ok and not v6.format_ok and not v6.hash_ok, "; ".join(v6.errors)[:160])

    result.update(
        {
            "artifact_metadata": art_meta,
            "artifact_extensions": art_exts,
            "tamper_changes": {
                "flip_polarity": 'In a copy of the artifact metadata, the first polarity="refutes" in the trace body was changed to polarity="supports". Nothing else touched.',
                "flip_and_rehash": "Same flip, and the attacker also recomputed sha256 over the altered body so the hash check passes.",
                "bad_claim": 'The claims list was replaced with {"finding": "F_01", "depends_on": ["E_99"]}: a dependency on evidence that does not exist in the trace (a superset of the cited set).',
                "drop_extensions": "The artifact's extensions[] field was emptied while every provenance key stayed in metadata: the in-band signal (MUST) is missing.",
            },
            "rule_changes": {
                "claims_subset": f"The declared claim for F_01 was reduced to {full[:1]} out of the cited set {full}: a strict subset, which the spec treats as a warning, not a failure.",
                "format_json": 'trace.format was changed from "srml" to "json": v1 defines only srml, so the receiver rejects it rather than guessing.',
            },
            "verification": v.safe_summary(),
            "requester_provenance_as_seen_by_analyst": inbound,
            "tamper": {"flip_polarity": v1.safe_summary(), "flip_and_rehash": v2.safe_summary(), "bad_claim": v3.safe_summary(), "drop_extensions": v4.safe_summary()},
            "rules": {"claims_subset": v5.safe_summary(), "format_json": v6.safe_summary()},
            "echo_header": echo,
        }
    )

    # Provenance graph across both agents.
    g = ProvenanceGraph()
    g.add(req_meta, "planner (requester)", "Goal · Constraint · Deciding", verify=verify_provenance(req_meta, extensions=[EXTENSION_URI]))
    g.add(art_meta, "analyst (responder)", "Hypothesis · Evidence → Finding", verify=v)
    for c in checks:
        g.add_event(c["name"], c["ok"], c["detail"])
    html = render_html(
        g,
        "Scholia provenance across two A2A agents",
        f"planner → analyst · {question} · in-band signal + A2A-Extensions header · {time.strftime('%Y-%m-%d %H:%M')} · draft 0.2 reference implementation",
    )
    result["graph"] = g.to_dict()
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, "provenance-graph.html"), "w", encoding="utf-8") as f:
            f.write(html)
        with open(os.path.join(out_dir, "transcript.json"), "w", encoding="utf-8") as f:
            json.dump(result, f, indent=1, ensure_ascii=False, default=str)
    result["html"] = html
    result["elapsed_s"] = round(time.time() - t0, 3)
    return result


def _subjects(question: str) -> tuple[str, str]:
    from demo.analyst import parse_subjects

    return parse_subjects(question)


class PlannerExecutor(AgentExecutor):
    """Serve the planner over A2A: delegate to the analyst, return a verified summary."""

    def __init__(self, analyst_url: str = ANALYST_URL, signer: Ed25519Signer | None = None):
        self.analyst_url = analyst_url
        self.signer = signer or planner_signer()

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.current_task is None and context.message is not None:
            await event_queue.enqueue_event(new_task_from_user_message(context.message))
        updater = TaskUpdater(event_queue, context.task_id or "", context.context_id or "")
        await updater.start_work()
        question = get_message_text(context.message) if context.message else "compare Dapr Agents and OpenTalon"
        res = await run_planner(self.analyst_url, question, out_dir=None, activate=True, signer=self.signer)
        passed = sum(1 for c in res["checks"] if c["ok"])
        text = f"{res['answer']} Provenance verified: {passed}/{len(res['checks'])} checks passed."
        parts = [new_text_part(text), new_data_part({"checks": res["checks"], "verification": res.get("verification")})]
        # The planner's artifact carries a closing trace whose parent is the analyst's trace,
        # which in turn points at the planner's requester trace: a three-node chain. It is
        # signed with the key the planner's Agent Card publishes (responder role, 4.4).
        analyst_hash = (res.get("verification") or {}).get("sha256")
        own = build_provenance(
            closing_trace(*_subjects(question), verified=bool((res.get("verification") or {}).get("ok"))),
            parents=[analyst_hash] if analyst_hash else [],
            signer=self.signer,
        )
        _, msg_exts = provenance_from(context.message) if context.message is not None else ({}, [])
        activated = EXTENSION_URI in context.requested_extensions or is_signalled(msg_exts)
        await updater.add_artifact(parts, name="plan", metadata=own if activated else None, extensions=[EXTENSION_URI] if activated else None)
        await updater.complete()

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        updater = TaskUpdater(event_queue, context.task_id or "", context.context_id or "")
        await updater.cancel()


def build(port: int = PLANNER_PORT, analyst_url: str = ANALYST_URL, signer: Ed25519Signer | None = None):
    signer = signer or planner_signer()
    skill = AgentSkill(
        id="plan-compare",
        name="Plan and delegate a comparison",
        description="Delegates 'compare X and Y' to the analyst with Scholia provenance activated and verifies the result.",
        tags=["planning", "delegation", "provenance"],
        examples=["compare Dapr Agents and OpenTalon"],
    )
    card = make_card(
        "planner",
        "Delegating planner that verifies Scholia provenance from downstream agents.",
        port,
        skill,
        extension_params={"public_key_jwk": signer.public_jwk()},
    )
    return make_app(card, PlannerExecutor(analyst_url, signer)), card


def print_table(checks: list[dict[str, Any]]) -> bool:
    width = max(len(c["name"]) for c in checks)
    for c in checks:
        print(f"  {'PASS' if c['ok'] else 'FAIL'}  {c['name']:<{width}}  {c['detail'][:70]}")
    ok = all(c["ok"] for c in checks)
    print(f"  {'ALL PASS' if ok else 'FAILURES'}: {sum(c['ok'] for c in checks)}/{len(checks)}")
    return ok


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--port", type=int, default=PLANNER_PORT)
    ap.add_argument("--analyst", default=ANALYST_URL)
    ap.add_argument("--run", action="store_true", help="run the delegation scenario as a client instead of serving")
    ap.add_argument("--out", default="demo-out")
    ap.add_argument("--question", default="compare Dapr Agents and OpenTalon")
    args = ap.parse_args()
    if args.run:
        res = asyncio.run(run_planner(args.analyst, args.question, args.out))
        sys.exit(0 if print_table(res["checks"]) else 1)
    app, _ = build(args.port, args.analyst)
    print(f"planner listening on http://127.0.0.1:{args.port}", file=sys.stderr, flush=True)
    serve(app, args.port)
