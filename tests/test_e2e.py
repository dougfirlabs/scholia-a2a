"""End-to-end: both demo agents on ephemeral localhost ports, driven over A2A."""

from __future__ import annotations

import asyncio
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
from scholia_a2a import EXTENSION_URI, has_provenance, verify_provenance  # noqa: E402
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
    assert res["verification"]["ok"] and res["verification"]["signature"] == "verified"
    assert res["tamper"]["flip_polarity"]["ok"] is False
    assert res["tamper"]["flip_and_rehash"]["signature"] == "failed"
    assert res["tamper"]["bad_claim"]["claims_ok"] is False
    assert (tmp_path / "provenance-graph.html").stat().st_size > 5000
    assert (tmp_path / "transcript.json").exists()
    html = (tmp_path / "provenance-graph.html").read_text()
    assert "<svg" in html and "<script" not in html and "http://" not in html.split("<body")[0].replace("http://www.w3.org", "")


def test_plain_client_not_activated(agents):
    res = asyncio.run(ask(agents["analyst"], "compare Dapr Agents and OpenTalon"))
    assert res["state"] == "TASK_STATE_COMPLETED"
    assert res["answer"]
    assert res["has_provenance"] is False and res["metadata_keys"] == []


def test_third_party_via_planner_agent(agents):
    task = asyncio.run(via_planner_agent(agents["planner"], "compare OpenTalon and Dapr Agents"))
    assert task["status"]["state"] == "TASK_STATE_COMPLETED"
    meta = task["artifacts"][0]["metadata"]
    assert has_provenance(meta)
    v = verify_provenance(meta)
    assert v.ok and len(v.parents) == 1
    g = ProvenanceGraph()
    g.add(meta, "planner")
    assert "UNCHECKED" not in render_html(g) and "not in graph" in render_html(g)  # parent stub drawn


def test_unknown_subjects_still_answer(agents):
    res = asyncio.run(planner_mod.run_planner(agents["analyst"], "compare Foo and Bar", out_dir=None))
    assert all(c["ok"] for c in res["checks"]), [c for c in res["checks"] if not c["ok"]]
