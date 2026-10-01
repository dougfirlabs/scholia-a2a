"""Planner agent (port 9601): delegates to the analyst with the extension activated.

`run_planner()` is the planner's core: it writes its own Goal/Constraint/
Deciding trace, attaches it to the message metadata, activates the extension
via the A2A-Extensions header, verifies the analyst's returned provenance,
runs tamper tests, and renders the provenance graph. The planner is also a
proper A2A agent: its executor runs the same delegation when it receives a
"compare X and Y" task, so a third party can drive the whole chain over A2A.
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
from scholia_a2a import EXTENSION_URI, KEYS, Ed25519Verifier, build_provenance, extract, has_provenance, sha256_of, verify_provenance
from scholia_a2a.graph import ProvenanceGraph, render_html

ANALYST_URL = f"http://{HOST}:{ANALYST_PORT}"


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
    note = "the analyst's evidence chain verified (hash, signature, validator, claims)" if verified else "the analyst's provenance did not verify"
    return f"""<Step id="S_02">
  <Goal id="G_01" scope="trace" priority="required">Decide whether {x} and {y} can interoperate over A2A.</Goal>
  <Finding id="F_02" for_goal="G_01" status="{status}">Delegated result accepted: {note}.</Finding>
  <Concluding id="Con_01" for_goal="G_01" status="{status}">REFER:F_02 the delegated comparison closes the goal.</Concluding>
</Step>
"""


def _artifact_meta(task_dict: dict[str, Any]) -> tuple[dict[str, Any], dict[str, Any]]:
    arts = task_dict.get("artifacts") or []
    if not arts:
        return {}, {}
    return arts[0], arts[0].get("metadata") or {}


async def run_planner(
    analyst_url: str = ANALYST_URL,
    question: str = "compare Dapr Agents and OpenTalon",
    out_dir: str | None = None,
    activate: bool = True,
) -> dict[str, Any]:
    """Delegate `question` to the analyst and verify what comes back.

    Returns a transcript dict with a `checks` list of {name, ok, detail}.
    When `activate` is False the extension header is not sent (plain client).
    """
    checks: list[dict[str, Any]] = []
    t0 = time.time()

    def check(name: str, ok: bool, detail: str = "") -> None:
        checks.append({"name": name, "ok": bool(ok), "detail": detail})

    x, y = _subjects(question)
    req_trace = requester_trace(x, y)
    req_meta = build_provenance(req_trace, fmt="srml")
    req_fields = extract(req_meta)
    check("planner trace validates (scholialang)", req_fields["validator"]["ok"], f"validator {req_fields['validator']['version']}")

    async with httpx.AsyncClient(timeout=30.0) as http:
        client = await create_client(analyst_url, ClientConfig(streaming=False, httpx_client=http))
        card = client._card  # resolved AgentCard (no public accessor in 1.2.1)
        ext_entry = find_extension_by_uri(card, EXTENSION_URI)
        check("analyst Agent Card declares the extension", ext_entry is not None, EXTENSION_URI)
        verifier = None
        if ext_entry is not None:
            params = MessageToDict(ext_entry.params)
            if "public_key_jwk" in params:
                verifier = Ed25519Verifier.from_jwk(params["public_key_jwk"])
            check("Agent Card entry is required=false", not ext_entry.required, "optional profile extension")

        msg = Message(
            message_id=str(uuid.uuid4()),
            role=Role.ROLE_USER,
            parts=[Part(text=question, media_type="text/plain")],
            metadata=req_meta if activate else None,
            extensions=[EXTENSION_URI] if activate else None,
        )
        ctx = None
        if activate:
            params = ServiceParametersFactory.create([with_a2a_extensions([EXTENSION_URI])])
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

    # Echo check: the SDK client hides response headers, so probe the RPC endpoint directly.
    echo = None
    if activate:
        async with httpx.AsyncClient(timeout=30.0) as http:
            r = await http.post(
                analyst_url + RPC_PATH,
                headers={HTTP_EXTENSION_HEADER: EXTENSION_URI, "A2A-Version": "1.0", "Content-Type": "application/json"},
                json={"jsonrpc": "2.0", "id": "echo-probe", "method": "GetTask", "params": {"id": "does-not-exist"}},
            )
            echo = r.headers.get(HTTP_EXTENSION_HEADER)
            check("A2A-Extensions header echoed by analyst", echo == EXTENSION_URI, f"response header: {echo!r}")

    state = (task_dict.get("status") or {}).get("state")
    check("task completed", state == "TASK_STATE_COMPLETED", f"state={state}")
    artifact, art_meta = _artifact_meta(task_dict)
    answer = " ".join(p.get("text", "") for p in artifact.get("parts", []) if "text" in p).strip()
    check("artifact has a plain answer", bool(answer), answer[:120])

    result: dict[str, Any] = {
        "question": question,
        "activated": activate,
        "analyst_url": analyst_url,
        "answer": answer,
        "task": task_dict,
        "requester_metadata": req_meta,
        "analyst_card": MessageToDict(card),
        "request": request_record,
        "checks": checks,
    }
    if not activate:
        check("no provenance metadata without activation", not has_provenance(art_meta), f"metadata keys: {sorted(art_meta)}")
        result["elapsed_s"] = round(time.time() - t0, 3)
        return result

    check("artifact carries provenance metadata", has_provenance(art_meta), f"{len(extract(art_meta))} extension keys")
    v = verify_provenance(art_meta, verifier=verifier)
    check("sha256 matches canonical trace", v.hash_ok, v.sha256 or "")
    check("JWS signature verifies against card JWK", v.signature_ok is True, "EdDSA / Ed25519" if verifier else "no key on card")
    check("analyst trace validates (re-run locally)", v.validator_ok, f"validator {v.validator_version}")
    check("declared claims consistent with trace", v.claims_ok, json.dumps(v.claims_declared))
    check("parent links to planner trace hash", req_fields["sha256"] in v.parents, f"parents={[p[:19] + '…' for p in v.parents]}")
    pol = v.atom_summary.get("evidence_polarity", {})
    check("evidence carries supports/refutes polarity", bool(pol.get("supports")) and bool(pol.get("refutes")), json.dumps(pol))
    check("L1 verification PASS", v.ok, "; ".join(v.errors) or "no errors")

    # Tamper tests on copies. Each must FAIL verification.
    t1 = copy.deepcopy(art_meta)
    body = t1[KEYS["trace"]]["body"]
    flipped = body.replace('polarity="refutes"', 'polarity="supports"', 1)
    t1[KEYS["trace"]]["body"] = flipped
    v1 = verify_provenance(t1, verifier=verifier)
    check("TAMPER 1: flip one Evidence polarity -> hash FAILS", (flipped != body) and not v1.ok and not v1.hash_ok, "; ".join(v1.errors)[:160])

    t2 = copy.deepcopy(t1)
    t2[KEYS["sha256"]] = sha256_of(flipped)  # attacker re-hashes the altered trace
    v2 = verify_provenance(t2, verifier=verifier)
    check("TAMPER 2: flip + re-hash -> signature FAILS", not v2.ok and v2.hash_ok and v2.signature_ok is False, "; ".join(v2.errors)[:160])

    t3 = copy.deepcopy(art_meta)
    t3[KEYS["claims"]] = [{"finding": "F_01", "depends_on": ["E_99"]}]
    v3 = verify_provenance(t3, verifier=verifier)
    check("TAMPER 3: claim cites unknown evidence -> claims FAIL", not v3.ok and not v3.claims_ok, "; ".join(v3.errors)[:160])

    result.update(
        {
            "artifact_metadata": art_meta,
            "tamper_changes": {
                "flip_polarity": 'In a copy of the artifact metadata, the first polarity="refutes" in the trace body was changed to polarity="supports". Nothing else touched.',
                "flip_and_rehash": "Same flip, and the attacker also recomputed sha256 over the altered body so the hash check passes.",
                "bad_claim": 'The claims list was replaced with {"finding": "F_01", "depends_on": ["E_99"]}: a dependency on evidence that does not exist in the trace.',
            },
            "verification": v.safe_summary(),
            "tamper": {"flip_polarity": v1.safe_summary(), "flip_and_rehash": v2.safe_summary(), "bad_claim": v3.safe_summary()},
            "echo_header": echo,
        }
    )

    # Provenance graph across both agents.
    g = ProvenanceGraph()
    g.add(req_meta, "planner (requester)", "Goal · Constraint · Deciding", verify=verify_provenance(req_meta))
    g.add(art_meta, "analyst (responder)", "Hypothesis · Evidence → Finding", verify=v)
    for c in checks:
        g.add_event(c["name"], c["ok"], c["detail"])
    html = render_html(
        g,
        "Scholia provenance across two A2A agents",
        f"planner → analyst · {question} · A2A-Extensions activated · {time.strftime('%Y-%m-%d %H:%M')} · draft 0.1 reference implementation",
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

    def __init__(self, analyst_url: str = ANALYST_URL):
        self.analyst_url = analyst_url

    async def execute(self, context: RequestContext, event_queue: EventQueue) -> None:
        if context.current_task is None and context.message is not None:
            await event_queue.enqueue_event(new_task_from_user_message(context.message))
        updater = TaskUpdater(event_queue, context.task_id or "", context.context_id or "")
        await updater.start_work()
        question = get_message_text(context.message) if context.message else "compare Dapr Agents and OpenTalon"
        res = await run_planner(self.analyst_url, question, out_dir=None, activate=True)
        passed = sum(1 for c in res["checks"] if c["ok"])
        text = f"{res['answer']} Provenance verified: {passed}/{len(res['checks'])} checks passed."
        parts = [new_text_part(text), new_data_part({"checks": res["checks"], "verification": res.get("verification")})]
        # The planner's artifact carries a closing trace whose parent is the analyst's trace,
        # which in turn points at the planner's requester trace: a three-node chain.
        analyst_hash = (res.get("verification") or {}).get("sha256")
        own = build_provenance(
            closing_trace(*_subjects(question), verified=bool((res.get("verification") or {}).get("ok"))),
            parents=[analyst_hash] if analyst_hash else [],
        )
        activated = EXTENSION_URI in context.requested_extensions
        await updater.add_artifact(parts, name="plan", metadata=own if activated else None)
        await updater.complete()

    async def cancel(self, context: RequestContext, event_queue: EventQueue) -> None:
        updater = TaskUpdater(event_queue, context.task_id or "", context.context_id or "")
        await updater.cancel()


def build(port: int = PLANNER_PORT, analyst_url: str = ANALYST_URL):
    skill = AgentSkill(
        id="plan-compare",
        name="Plan and delegate a comparison",
        description="Delegates 'compare X and Y' to the analyst with Scholia provenance activated and verifies the result.",
        tags=["planning", "delegation", "provenance"],
        examples=["compare Dapr Agents and OpenTalon"],
    )
    card = make_card("planner", "Delegating planner that verifies Scholia provenance from downstream agents.", port, skill)
    return make_app(card, PlannerExecutor(analyst_url)), card


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
