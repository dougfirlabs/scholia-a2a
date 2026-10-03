"""End-to-end: both demo agents on ephemeral localhost ports, driven over A2A."""

from __future__ import annotations

import asyncio
import json
import os
import socket
import sys
import threading
import time

import httpx
import pytest
import uvicorn

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from demo import analyst as analyst_mod  # noqa: E402
from demo import planner as planner_mod  # noqa: E402
from demo.plain_client import ask  # noqa: E402
from demo.scenario import via_planner_agent  # noqa: E402
from scholia_a2a import EXTENSION_URI, Ed25519Signer, Ed25519Verifier, build_provenance, has_provenance, read_extension_entry, verify_object, verify_provenance  # noqa: E402
from scholia_a2a.graph import ProvenanceGraph, render_html  # noqa: E402


def _free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


class _Server:
    def __init__(self, app, port: int):
        self.server = uvicorn.Server(uvicorn.Config(app, host="127.0.0.1", port=port, log_level="error"))
        self.thread = threading.Thread(target=self.server.run, daemon=True)
        self.port = port

    def start(self) -> None:
        self.thread.start()
        deadline = time.time() + 15
        while time.time() < deadline:
            try:
                httpx.get(f"http://127.0.0.1:{self.port}/.well-known/agent-card.json", timeout=1).raise_for_status()
                return
            except Exception:
                time.sleep(0.05)
        raise RuntimeError("server did not start")

    def stop(self) -> None:
        self.server.should_exit = True
        self.thread.join(timeout=10)


@pytest.fixture(scope="module")
def agents():
    a_port, p_port = _free_port(), _free_port()
    analyst_app, _card, _signer = analyst_mod.build(a_port)
    planner_app, _ = planner_mod.build(p_port, analyst_url=f"http://127.0.0.1:{a_port}")
    servers = [_Server(analyst_app, a_port), _Server(planner_app, p_port)]
    for s in servers:
        s.start()
    yield {"analyst": f"http://127.0.0.1:{a_port}", "planner": f"http://127.0.0.1:{p_port}"}
    for s in servers:
        s.stop()


def test_agent_card_declares_extension(agents):
    card = httpx.get(agents["analyst"] + "/.well-known/agent-card.json").json()
    exts = card["capabilities"]["extensions"]
    assert [e["uri"] for e in exts] == [EXTENSION_URI]
    assert not exts[0].get("required", False)
    assert exts[0]["params"]["modes"] == ["inline", "reference"]
    assert exts[0]["params"]["public_key_jwk"]["crv"] == "Ed25519"
    assert "d" not in exts[0]["params"]["public_key_jwk"]
    # What the wire looks like (proto3 Struct) and how the receiver reads it (section 3 tolerance).
    assert "required" not in exts[0] and exts[0]["params"]["max_inline_bytes"] == 65536.0
    entry = read_extension_entry(exts[0])
    assert entry["required"] is False and entry["params"]["max_inline_bytes"] == 65536
    assert entry["params"]["grammar_version"] == "0.6.2" and entry["params"]["validator_version"] == "0.7.2"
    pcard = httpx.get(agents["planner"] + "/.well-known/agent-card.json").json()
    assert pcard["capabilities"]["extensions"][0]["params"]["public_key_jwk"]["crv"] == "Ed25519"


def test_header_echo(agents):
    r = httpx.post(
        agents["analyst"] + "/a2a",
        headers={"A2A-Extensions": EXTENSION_URI + ", https://other.example/ext", "A2A-Version": "1.0"},
        json={"jsonrpc": "2.0", "id": 1, "method": "GetTask", "params": {"id": "nope"}},
    )
    assert r.headers.get("A2A-Extensions") == EXTENSION_URI  # only supported URIs are echoed
    r2 = httpx.post(agents["analyst"] + "/a2a", headers={"A2A-Version": "1.0"}, json={"jsonrpc": "2.0", "id": 1, "method": "GetTask", "params": {"id": "nope"}})
    assert "A2A-Extensions" not in r2.headers


def test_planner_to_analyst_activated(agents, tmp_path):
    res = asyncio.run(planner_mod.run_planner(agents["analyst"], "compare Dapr Agents and OpenTalon", out_dir=str(tmp_path)))
    failed = [c for c in res["checks"] if not c["ok"]]
    assert not failed, failed
    assert res["verification"]["ok"] and res["verification"]["signature"] == "verified" and res["verification"]["identity"] == "agent-card"
    assert res["verification"]["signalled"] is True and res["verification"]["format"] == "srml"
    assert res["artifact_extensions"] == [EXTENSION_URI]
    assert res["tamper"]["flip_polarity"]["ok"] is False
    assert res["tamper"]["flip_and_rehash"]["signature"] == "failed"
    assert res["tamper"]["bad_claim"]["claims_ok"] is False
    assert res["tamper"]["drop_extensions"]["ok"] is False and res["tamper"]["drop_extensions"]["signalled"] is False
    assert res["rules"]["claims_subset"]["ok"] is True and any("strict subset" in w for w in res["rules"]["claims_subset"]["warnings"])
    assert res["rules"]["format_json"]["ok"] is False
    seen = res["requester_provenance_as_seen_by_analyst"]
    assert seen["signature"] == "verified" and seen["identity"] == "self-asserted" and seen["signature_statement"] == "integrity verified, identity self-asserted"
    sent_signer = res["request"]["message"]["metadata"][planner_mod.KEYS["signer"]]
    assert sent_signer["kid"] == res["requester_kid"] and "d" not in sent_signer["jwk"]  # public JWK only on the wire
    from demo.walkthrough import scan_secrets  # same scanner that gates the published pages
    assert scan_secrets(json.dumps(res, default=str)) == []
    assert (tmp_path / "provenance-graph.html").stat().st_size > 5000
    assert (tmp_path / "transcript.json").exists()
    html = (tmp_path / "provenance-graph.html").read_text()
    assert "<svg" in html and "<script" not in html and "http://" not in html.split("<body")[0].replace("http://www.w3.org", "")


def test_plain_client_not_activated(agents):
    res = asyncio.run(ask(agents["analyst"], "compare Dapr Agents and OpenTalon"))
    assert res["state"] == "TASK_STATE_COMPLETED"
    assert res["answer"]
    assert res["has_provenance"] is False and res["metadata_keys"] == [] and res["extensions"] == []


def test_third_party_via_planner_agent(agents):
    task = asyncio.run(via_planner_agent(agents["planner"], "compare OpenTalon and Dapr Agents"))
    assert task["status"]["state"] == "TASK_STATE_COMPLETED"
    art = task["artifacts"][0]
    assert art["extensions"] == [EXTENSION_URI]
    meta = art["metadata"]
    assert has_provenance(meta, art["extensions"])
    pcard = httpx.get(agents["planner"] + "/.well-known/agent-card.json").json()
    verifier = Ed25519Verifier.from_jwk(pcard["capabilities"]["extensions"][0]["params"]["public_key_jwk"])
    v = verify_object(art, verifier=verifier)
    assert v.ok and len(v.parents) == 1 and v.signature_ok is True and v.identity == "agent-card"
    g = ProvenanceGraph()
    g.add(meta, "planner", extensions=art["extensions"])
    assert "UNCHECKED" not in render_html(g) and "not in graph" in render_html(g)  # parent stub drawn


def test_in_band_signal_alone_activates_and_header_alone_without_keys_is_fine(agents):
    """Message.extensions + keys, no header: the analyst still attaches provenance and links the parent."""
    from a2a.client import ClientConfig, create_client
    from a2a.types.a2a_pb2 import Message, Part, Role, SendMessageRequest
    from google.protobuf.json_format import MessageToDict

    signer = Ed25519Signer.generate("req-inband")
    req = build_provenance(planner_mod.requester_trace("Foo", "Bar"), signer=signer, signer_jwk=signer.public_jwk())

    async def send(metadata, extensions):
        async with httpx.AsyncClient(timeout=30.0) as http:
            client = await create_client(agents["analyst"], ClientConfig(streaming=False, httpx_client=http))
            msg = Message(message_id="x", role=Role.ROLE_USER, parts=[Part(text="compare Foo and Bar")], metadata=metadata, extensions=extensions)
            task = {}
            async for resp in client.send_message(SendMessageRequest(message=msg)):
                if resp.HasField("task"):
                    task = MessageToDict(resp.task)
            await client.close()
            return task

    task = asyncio.run(send(req, [EXTENSION_URI]))
    art = task["artifacts"][0]
    assert art["extensions"] == [EXTENSION_URI]
    v = verify_object(art)
    assert v.present and v.hash_ok and v.parents == [req[planner_mod.KEYS["sha256"]]]
    seen = next(p["data"]["requester_provenance"] for p in art["parts"] if "data" in p and "requester_provenance" in p["data"])
    assert seen["ok"] and seen["signature"] == "verified" and seen["identity"] == "self-asserted"
    # Keys without the in-band signal and without the header: not provenance; a plain answer, no parent link.
    task2 = asyncio.run(send(req, None))
    art2 = task2["artifacts"][0]
    assert not art2.get("extensions") and not art2.get("metadata")


def test_unknown_subjects_still_answer(agents):
    res = asyncio.run(planner_mod.run_planner(agents["analyst"], "compare Foo and Bar", out_dir=None))
    assert all(c["ok"] for c in res["checks"]), [c for c in res["checks"] if not c["ok"]]
