"""The walkthrough generator: private-key scan (all three demo keys) and page build."""

from __future__ import annotations

import asyncio
import base64
import json
import os
import sys

import pytest
from cryptography.hazmat.primitives import serialization

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)

from demo import walkthrough as wt  # noqa: E402
from scholia_a2a import Ed25519Signer  # noqa: E402
from scholia_a2a.sign import private_key_to_pem  # noqa: E402


def _private_jwk(signer: Ed25519Signer) -> dict:
    raw = signer.private_key.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())
    return {**signer.public_jwk(), "d": base64.urlsafe_b64encode(raw).rstrip(b"=").decode()}


def test_scanner_catches_private_material_in_every_form():
    s = Ed25519Signer.generate("k")
    priv = _private_jwk(s)
    assert "jwk-private-member" in wt.scan_secrets(json.dumps(priv))
    assert "jwk-private-member" in wt.scan_secrets(json.dumps(priv, indent=1))
    assert "pem-armour" in wt.scan_secrets(private_key_to_pem(s.private_key).decode())
    assert "private-key-text" in wt.scan_secrets("-----BEGIN PRIVATE KEY-----")
    assert "d-equals-scalar" in wt.scan_secrets("x=abc d=" + priv["d"])
    # Structural scan: a private JWK anywhere in a transcript, under any key (card key or requester signer key).
    transcript = {"analyst_card": {"capabilities": {"extensions": [{"params": {"public_key_jwk": s.public_jwk()}}]}},
                  "request": {"message": {"metadata": {"…/signer": {"kid": "k", "jwk": priv}}}}}
    hits = wt.scan_json_for_private_jwk(transcript)
    assert hits == ["$.request.message.metadata.…/signer.jwk"]
    # Public material is clean, including kid strings that contain the letter d.
    clean = {"kid": "planner-123", "jwk": s.public_jwk(), "card": {"public_key_jwk": s.public_jwk()}}
    assert wt.scan_secrets(json.dumps(clean, indent=1)) == [] and wt.scan_json_for_private_jwk(clean) == []


def test_walkthrough_builds_clean_from_a_real_run(tmp_path):
    from tests.test_e2e import _Server, _free_port  # reuse the server harness
    from demo import analyst as analyst_mod, planner as planner_mod

    a_port = _free_port()
    app, _c, _s = analyst_mod.build(a_port)
    srv = _Server(app, a_port)
    srv.start()
    try:
        res = asyncio.run(planner_mod.run_planner(f"http://127.0.0.1:{a_port}", "compare Dapr Agents and OpenTalon", out_dir=str(tmp_path)))
    finally:
        srv.stop()
    assert all(c["ok"] for c in res["checks"]), [c for c in res["checks"] if not c["ok"]]
    transcript = json.load(open(tmp_path / "transcript.json"))
    graph = (tmp_path / "provenance-graph.html").read_text()
    page = wt.build(transcript, graph, "test", "graph.html")
    assert wt.scan_secrets(page) == [] and wt.scan_secrets(graph) == [] and wt.scan_json_for_private_jwk(transcript) == []
    assert "<script" not in page and 'name="viewport"' in page
    assert "identity self-asserted" in page and "TAMPER 4" in page and "RULE: claims strict subset" in page and "RULE: format other than srml" in page
    assert "draft 0.2" in page and "\"scholia_version\"" not in page  # the old param is gone from every JSON block
    # Every check name from the run appears on the page somewhere.
    import html
    for c in res["checks"]:
        assert html.escape(c["name"].split(" (")[0]) in page, c["name"]
