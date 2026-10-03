"""Run the full demo scenario against the two running agents and print PASS/FAIL.

1. planner (as client) -> analyst, extension activated: verify + tamper tests
2. plain client -> analyst, extension NOT activated: normal answer, no provenance
3. third party -> planner agent over A2A, extension activated: the planner's
   artifact carries a closing trace whose parent is the analyst's trace hash
Writes demo-out/provenance-graph.html and demo-out/transcript.json.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import os
import sys
import uuid

import httpx
from google.protobuf.json_format import MessageToDict

from a2a.client import ClientCallContext, ClientConfig, create_client
from a2a.client.service_parameters import ServiceParametersFactory, with_a2a_extensions
from a2a.types.a2a_pb2 import Message, Part, Role, SendMessageRequest

from demo.common import ANALYST_PORT, HOST, PLANNER_PORT
from demo.plain_client import ask
from demo.planner import print_table, run_planner
from scholia_a2a import EXTENSION_URI, Ed25519Verifier, has_provenance, is_signalled, provenance_from, verify_provenance
from scholia_a2a.graph import ProvenanceGraph, render_html


async def via_planner_agent(planner_url: str, question: str) -> dict:
    async with httpx.AsyncClient(timeout=60.0) as http:
        client = await create_client(planner_url, ClientConfig(streaming=False, httpx_client=http))
        msg = Message(message_id=str(uuid.uuid4()), role=Role.ROLE_USER, parts=[Part(text=question, media_type="text/plain")])
        ctx = ClientCallContext(service_parameters=ServiceParametersFactory.create([with_a2a_extensions([EXTENSION_URI])]))
        task = {}
        async for resp in client.send_message(SendMessageRequest(message=msg), context=ctx):
            if resp.HasField("task"):
                task = MessageToDict(resp.task)
        await client.close()
    return task


def _card_jwk(card: dict) -> dict | None:
    return next((e.get("params", {}).get("public_key_jwk") for e in card.get("capabilities", {}).get("extensions", []) if e.get("uri") == EXTENSION_URI), None)


async def main(analyst_url: str, planner_url: str, out_dir: str, question: str) -> int:
    checks: list[dict] = []

    print("\n[1] planner -> analyst, extension activated")
    res = await run_planner(analyst_url, question, out_dir=None, activate=True)
    checks += res["checks"]

    print("[2] plain client -> analyst, extension NOT activated")
    plain = await ask(analyst_url, question)
    checks.append({"name": "plain client: normal answer, task completed", "ok": plain["state"] == "TASK_STATE_COMPLETED" and bool(plain["answer"]), "detail": plain["answer"][:80]})
    checks.append({"name": "plain client: no provenance block, no extensions[] entry", "ok": not plain["has_provenance"] and not plain["extensions"], "detail": f"metadata keys={plain['metadata_keys']}, extensions={plain['extensions']}"})

    print("[3] third party -> planner agent (A2A) -> analyst")
    task = await via_planner_agent(planner_url, question)
    art = (task.get("artifacts") or [{}])[0]
    meta, exts = provenance_from(art)
    # The planner is a responder here: its Agent Card publishes the verification key.
    async with httpx.AsyncClient(timeout=30.0) as http:
        card = (await http.get(analyst_url + "/.well-known/agent-card.json")).json()
        planner_card = (await http.get(planner_url + "/.well-known/agent-card.json")).json()
    planner_jwk = _card_jwk(planner_card)
    pv = verify_provenance(meta, verifier=Ed25519Verifier.from_jwk(planner_jwk) if planner_jwk else None, extensions=exts)
    analyst_hash = (res.get("verification") or {}).get("sha256")
    checks.append({"name": "planner agent task completed over A2A", "ok": (task.get("status") or {}).get("state") == "TASK_STATE_COMPLETED", "detail": (task.get("status") or {}).get("state", "")})
    checks.append({"name": "planner artifact lists the extension URI in extensions[]", "ok": is_signalled(exts), "detail": f"extensions={exts}"})
    checks.append({"name": "planner artifact carries verified closing trace", "ok": has_provenance(meta, exts) and pv.ok, "detail": "; ".join(pv.errors) or pv.sha256 or ""})
    checks.append({"name": "planner closing trace signed; verifies with the planner card key", "ok": pv.signature_ok is True and pv.identity == "agent-card", "detail": pv.signature_statement})
    # The planner-agent run resolved the analyst again, so its analyst hash is the same trace content => same sha256.
    checks.append({"name": "planner closing trace parent == analyst trace hash", "ok": bool(analyst_hash) and analyst_hash in pv.parents, "detail": f"parents={[p[:19] + '…' for p in pv.parents]}"})

    # Graph with all three nodes; responder nodes are verified with the keys from their Agent Cards,
    # the requester node with its self-asserted `signer` key.
    jwk = _card_jwk(card)
    verifier = Ed25519Verifier.from_jwk(jwk) if jwk else None
    g = ProvenanceGraph()
    g.add(res["requester_metadata"], "planner (requester)", "Goal · Constraint · Deciding", extensions=res["requester_extensions"])
    g.add(res["artifact_metadata"], "analyst (responder)", "Hypothesis · Evidence → Finding", verifier=verifier, extensions=res["artifact_extensions"])
    if has_provenance(meta, exts):
        g.add(meta, "planner (closing, via A2A)", "Goal · Finding · Concluding", verify=pv)
    for c in checks:
        g.add_event(c["name"], c["ok"], c["detail"])
    html = render_html(
        g,
        "Scholia provenance across two A2A agents",
        f"planner → analyst → planner · “{question}” · in-band extensions[] signal · signed Ed25519 · grammar 0.6.2 / validator 0.7.2 · draft 0.2 reference implementation",
    )
    os.makedirs(out_dir, exist_ok=True)
    with open(os.path.join(out_dir, "provenance-graph.html"), "w", encoding="utf-8") as f:
        f.write(html)
    res.pop("html", None)
    res["planner_card"] = planner_card
    res["planner_agent_verification"] = pv.safe_summary()
    res["plain_client"] = plain
    res["planner_agent_task"] = task
    res["graph"] = g.to_dict()
    res["checks"] = checks
    with open(os.path.join(out_dir, "transcript.json"), "w", encoding="utf-8") as f:
        json.dump(res, f, indent=1, ensure_ascii=False, default=str)

    print("\nRESULTS")
    ok = print_table(checks)
    print(f"\nwrote {out_dir}/provenance-graph.html and {out_dir}/transcript.json")
    return 0 if ok else 1


if __name__ == "__main__":
    ap = argparse.ArgumentParser()
    ap.add_argument("--analyst", default=f"http://{HOST}:{ANALYST_PORT}")
    ap.add_argument("--planner", default=f"http://{HOST}:{PLANNER_PORT}")
    ap.add_argument("--out", default="demo-out")
    ap.add_argument("--question", default="compare Dapr Agents and OpenTalon")
    a = ap.parse_args()
    sys.exit(asyncio.run(main(a.analyst, a.planner, a.out, a.question)))
