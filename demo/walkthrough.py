"""Generate a phone-first "see it in action" walkthrough from the real demo transcript.

    python -m demo.walkthrough --transcript demo-out/transcript.json --out demo-out/walkthrough.html

Self-contained dark HTML, no external JS. Fails the build if anything that
looks like a private key reaches the output.
"""

from __future__ import annotations

import argparse
import html
import json
import os
import re
import subprocess
import sys
import time
import xml.etree.ElementTree as ET
from typing import Any

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), ".."))

from scholia_a2a import EXTENSION_URI, KEYS  # noqa: E402
from scholia_a2a.graph import KIND_COLORS, POLARITY_COLORS  # noqa: E402

e = html.escape
STATUS_COLORS = {"met": "#3fb950", "unmet": "#d29922", "partially_met": "#d29922"}
# Private-key material must never reach a served page or transcript: a JWK `d` member
# (Ed25519 private scalar), PEM armour, or a raw urlsafe-b64 32-byte scalar after "d=".
SECRET_PATTERNS = {
    "jwk-private-member": re.compile(r'"d"\s*:'),
    "pem-armour": re.compile(r"-----BEGIN"),
    "private-key-text": re.compile(r"PRIVATE KEY"),  # PEM header form; prose may say "private key"
    "d-equals-scalar": re.compile(r"\bd=[A-Za-z0-9_-]{43}(?![A-Za-z0-9_-])"),
}


def short(h: str | None, n: int = 12) -> str:
    if not h:
        return ""
    return h.split(":", 1)[-1][:n] + "…"


def pre(obj: Any, max_lines: int = 16, label: str = "show full") -> str:
    """Pretty JSON, trimmed to max_lines with a <details> holding the full text."""
    text = obj if isinstance(obj, str) else json.dumps(obj, indent=1, ensure_ascii=False)
    lines = text.split("\n")
    if len(lines) <= max_lines:
        return f"<pre>{e(text)}</pre>"
    head = "\n".join(lines[:max_lines])
    return (
        f"<pre>{e(head)}\n<span class=dim>… {len(lines) - max_lines} more lines</span></pre>"
        f"<details><summary>{e(label)} ({len(lines)} lines)</summary><pre>{e(text)}</pre></details>"
    )


def trim_meta(meta: dict[str, Any]) -> dict[str, Any]:
    """Copy of a metadata map with long strings shortened for the trimmed view."""
    out: dict[str, Any] = {}
    for k, v in meta.items():
        kk = k.replace(EXTENSION_URI + "/", "…/v1/")
        if isinstance(v, dict) and "body" in v:
            v = {**v, "body": (v["body"][:90] + "… (rendered below)")}
        elif isinstance(v, str) and len(v) > 60:
            v = v[:28] + "…" + v[-16:]
        out[kk] = v
    return out


def srml_html(body: str) -> str:
    """Render SRML atoms as readable rows: kind badge, id, attributes, content."""
    try:
        root = ET.fromstring(f"<__r__>{body}</__r__>")
    except ET.ParseError:
        return f"<pre>{e(body)}</pre>"
    rows: list[str] = []

    def walk(el: ET.Element, depth: int) -> None:
        kind = el.tag
        if kind == "__r__":
            for c in el:
                walk(c, depth)
            return
        col = KIND_COLORS.get(kind, "#8b949e")
        attrs = dict(el.attrib)
        aid = attrs.pop("id", "")
        tags = []
        pol = attrs.pop("polarity", None)
        if pol:
            tags.append(f'<span class="tag" style="--c:{POLARITY_COLORS.get(pol, "#8b949e")}">{e(pol)}</span>')
        st = attrs.pop("status", None)
        if st:
            tags.append(f'<span class="tag" style="--c:{STATUS_COLORS.get(st, "#d29922")}">status={e(st)}</span>')
        attr_txt = " ".join(f'<span class=attr>{e(k)}=<i>{e(v)}</i></span>' for k, v in attrs.items())
        text = " ".join((el.text or "").split())
        text_html = re.sub(r"\b((?:REFER|IMPLIES):[A-Za-z0-9_:.\-]+)", r'<span class=ref>\1</span>', e(text))
        rows.append(
            f'<div class="atom" style="--c:{col};margin-left:{depth * 14}px">'
            f'<div class="ah"><span class="kind">{e(kind)}</span> <span class="aid">{e(aid)}</span> {" ".join(tags)}</div>'
            + (f'<div class="attrs">{attr_txt}</div>' if attr_txt else "")
            + (f'<div class="txt">{text_html}</div>' if text else "")
            + "</div>"
        )
        for c in el:
            walk(c, depth + 1)

    walk(root, 0)
    return '<div class="atoms">' + "".join(rows) + "</div>" + f"<details><summary>show raw SRML</summary><pre>{e(body)}</pre></details>"


def badge(ok: bool, good_when_false: bool = False) -> str:
    if good_when_false:
        return '<span class="badge bad">FAIL</span> <span class="good">correct: tamper caught</span>' if not ok else '<span class="badge warn">PASSED (tamper missed!)</span>'
    return '<span class="badge ok">PASS</span>' if ok else '<span class="badge bad">FAIL</span>'


def checks_table(checks: list[dict[str, Any]], names: list[str] | None = None, prefix: str | None = None) -> str:
    sel = [c for c in checks if (names is None or c["name"] in names) and (prefix is None or c["name"].startswith(prefix))]
    rows = "".join(f"<tr><td>{badge(c['ok'])}</td><td>{e(c['name'])}</td><td class=dim>{e(c['detail'][:140])}</td></tr>" for c in sel)
    return f'<div class="scroll"><table><tr><th></th><th>check</th><th>detail</th></tr>{rows}</table></div>'


def step(n: int, title: str, why: str, body: str) -> str:
    return f'<section class="step" id="s{n}"><div class="sn">{n}</div><h2>{e(title)}</h2><p class="why">{e(why)}</p>{body}</section>'


CSS = """
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2128;--border:#30363d;--fg:#e6edf3;--dim:#8b949e;--accent:#58a6ff;--purple:#bc8cff;--green:#3fb950;--amber:#d29922;--red:#f85149}
*{box-sizing:border-box}html{-webkit-font-smoothing:antialiased}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
.wrap{max-width:820px;margin:0 auto;padding:0 16px 3rem}
.banner{background:#bc8cff18;border-bottom:1px solid #bc8cff44;padding:.6rem 16px;font-size:.84rem;color:var(--fg)}
.banner b{color:var(--purple)}.banner a{color:var(--accent);word-break:break-all;text-decoration:none}
h1{font-size:1.4rem;margin:1rem 0 .2rem;text-wrap:balance}.sub{color:var(--dim);font-size:.88rem;margin:.2rem 0 1rem}
.toc{display:flex;flex-wrap:wrap;gap:.4rem;margin:.6rem 0 1rem}.toc a{font-size:.8rem;color:var(--accent);text-decoration:none;border:1px solid var(--border);border-radius:20px;padding:.1rem .6rem;background:var(--panel)}
.step{position:relative;background:var(--panel);border:1px solid var(--border);border-radius:14px;padding:.9rem 1rem 1rem;margin:1rem 0}
.sn{position:absolute;top:-.7rem;left:.9rem;background:var(--purple);color:#0d1117;font-weight:800;font-size:.8rem;border-radius:20px;padding:.05rem .6rem}
h2{font-size:1.1rem;margin:.3rem 0 .3rem;color:var(--fg);text-wrap:balance}h3{font-size:.86rem;color:var(--dim);text-transform:uppercase;letter-spacing:.04em;margin:1rem 0 .3rem}
.why{color:#c9d1d9;margin:.2rem 0 .7rem;text-wrap:pretty}
pre{white-space:pre-wrap;word-break:break-word;background:var(--panel2);border:1px solid var(--border);border-radius:10px;padding:.55rem .7rem;font:.74rem/1.45 ui-monospace,SFMono-Regular,Menlo,monospace;margin:.4rem 0;max-height:60vh;overflow:auto}
code{font:.84em ui-monospace,SFMono-Regular,Menlo,monospace;background:#0d1117;border:1px solid var(--border);border-radius:5px;padding:.02rem .3rem;word-break:break-all}
details{margin:.3rem 0}summary{cursor:pointer;color:var(--accent);font-size:.86rem}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch}
table{border-collapse:collapse;width:100%;font-size:.82rem;margin:.4rem 0}th{background:var(--panel2);color:var(--dim);text-align:left;padding:.3rem .45rem;border:1px solid var(--border)}
td{padding:.3rem .45rem;border:1px solid var(--border);vertical-align:top;word-break:break-word}
.badge{display:inline-block;font-size:.72rem;font-weight:800;border-radius:20px;padding:.05rem .5rem;border:1px solid var(--border);white-space:nowrap}
.badge.ok{color:var(--green);background:#3fb95022;border-color:#3fb95055}.badge.bad{color:var(--red);background:#f8514922;border-color:#f8514955}.badge.warn{color:var(--amber);background:#d2992222;border-color:#d2992255}
.good{color:var(--green);font-size:.8rem;font-weight:700}
.dim{color:var(--dim)}.ok{color:var(--green);font-weight:700}.bad{color:var(--red);font-weight:700}
.kv{display:grid;grid-template-columns:auto minmax(0,1fr);gap:.25rem .7rem;font-size:.84rem;margin:.4rem 0}.kv>div{min-width:0;word-break:break-word}.kv div:nth-child(odd){color:var(--dim);white-space:nowrap}.kv code{display:inline-block;max-width:100%}
.hdr{background:#0d1117;border:1px solid var(--border);border-radius:8px;padding:.4rem .6rem;font:.78rem/1.5 ui-monospace,Menlo,monospace;word-break:break-all}.hdr b{color:var(--accent)}
.atoms{margin:.4rem 0}.atom{border-left:3px solid var(--c);background:var(--panel2);border-radius:0 8px 8px 0;padding:.35rem .6rem;margin:.3rem 0;font-size:.84rem}
.ah{display:flex;flex-wrap:wrap;gap:.4rem;align-items:center}.kind{color:var(--c);font-weight:800}.aid{font:.8rem ui-monospace,Menlo,monospace;color:var(--fg)}
.tag{display:inline-block;font-size:.7rem;font-weight:800;color:var(--c);background:color-mix(in srgb,var(--c) 15%,transparent);border:1px solid var(--c);border-radius:20px;padding:0 .45rem}
.attrs{font:.74rem ui-monospace,Menlo,monospace;color:var(--dim);margin:.15rem 0}.attr i{color:#c9d1d9;font-style:normal}
.txt{color:#c9d1d9;margin-top:.15rem;text-wrap:pretty}.ref{color:#f0883e;font:.8rem ui-monospace,Menlo,monospace}
.answer{background:#3fb95012;border:1px solid #3fb95044;border-radius:9px;padding:.5rem .7rem;margin:.4rem 0}
.hl{background:#58a6ff18;border:1px solid #58a6ff44;border-radius:9px;padding:.5rem .7rem;margin:.5rem 0;font-size:.9rem}
.graphwrap{overflow-x:auto;-webkit-overflow-scrolling:touch;border:1px solid var(--border);border-radius:12px;background:var(--panel2);margin:.5rem 0}
.foot{color:var(--dim);font-size:.78rem;margin-top:2rem;border-top:1px solid var(--border);padding-top:.6rem;word-break:break-all}
a{color:var(--accent)}
"""


def build(transcript: dict[str, Any], graph_html: str | None, commit: str, graph_link: str) -> str:
    t = transcript
    checks = {c["name"]: c for c in t["checks"]}
    req_meta = t["requester_metadata"]
    art_meta = t["artifact_metadata"]
    card = t.get("analyst_card", {})
    ext_entry = next((x for x in card.get("capabilities", {}).get("extensions", []) if x.get("uri") == EXTENSION_URI), {})
    req = t.get("request", {})
    msg = req.get("message", {})
    v = t["verification"]
    task = t["task"]
    artifact = (task.get("artifacts") or [{}])[0]
    answer_parts = [p for p in artifact.get("parts", []) if "text" in p]
    data_parts = [p for p in artifact.get("parts", []) if "data" in p]
    closing_task = t.get("planner_agent_task", {})
    closing_art = (closing_task.get("artifacts") or [{}])[0]
    closing_meta = closing_art.get("metadata") or {}
    analyst_hash = v.get("sha256", "")
    planner_hash = req_meta[KEYS["sha256"]]
    sections: list[str] = []

    # 1 Discovery
    card_params = t.get("analyst_card_params") or {}
    sections.append(step(1, "Discovery: the analyst's Agent Card",
        "The planner fetches the analyst's Agent Card and finds the provenance extension listed under capabilities.extensions, marked optional, with grammar and validator versions and the analyst's public verification key. The wire form omits required (proto3 default) and serialises max_inline_bytes as 65536.0; the receiver reads both tolerantly.",
        f'<div class="kv"><div>GET</div><div><code>{e(t["analyst_url"])}/.well-known/agent-card.json</code></div>'
        f'<div>agent</div><div>{e(card.get("name", ""))} · {e(card.get("description", ""))}</div>'
        f'<div>required</div><div><code>{e(str(ext_entry.get("required", False)).lower())}</code> <span class=dim>(absent on the wire = false)</span></div>'
        f'<div>max_inline_bytes</div><div><code>{e(str(ext_entry.get("params", {}).get("max_inline_bytes")))}</code> on the wire → <code>{e(str(card_params.get("max_inline_bytes")))}</code> read</div>'
        f'<div>versions</div><div>grammar <code>{e(str(card_params.get("grammar_version")))}</code> · validator <code>{e(str(card_params.get("validator_version")))}</code></div></div>'
        + checks_table(t["checks"], ["analyst Agent Card declares the extension", "Agent Card entry is required=false (absent on the wire reads as false)"]) + checks_table(t["checks"], prefix="card params")
        + pre(ext_entry, 40) + f"<details><summary>show the whole Agent Card</summary><pre>{e(json.dumps(card, indent=1))}</pre></details>"))

    # 2 Request
    req_body = req_meta[KEYS["trace"]]["body"]
    hdrs = req.get("http_headers", {})
    hdr_html = "".join(f"<div><b>{e(k)}:</b> {e(val)}</div>" for k, val in hdrs.items()) or "<div class=dim>(none recorded)</div>"
    signer_field = req_meta.get(KEYS["signer"], {})
    sections.append(step(2, "Request: planner → analyst (message/send)",
        "The planner lists the extension URI in Message.extensions (the authoritative in-band signal), attaches its Goal / Constraint / Deciding trace in the message's own metadata map, signs the hash with an ephemeral Ed25519 key and ships the public half as signer {kid, jwk} because a requester has no Agent Card. It also sends the A2A-Extensions header, which the spec allows but nobody relies on.",
        f'<h3>Message</h3><div class="kv"><div>role</div><div><code>{e(msg.get("role", ""))}</code></div>'
        f'<div>text</div><div>“{e(" ".join(p.get("text", "") for p in msg.get("parts", [])))}”</div>'
        f'<div>extensions[]</div><div><code>{e(", ".join(msg.get("extensions", [])))}</code> <span class=dim>← in-band signal (MUST)</span></div>'
        f'<div>metadata sha256</div><div><code>{e(planner_hash)}</code></div>'
        f'<div>signer</div><div><code>kid={e(str(signer_field.get("kid", "")))}</code> · jwk <code>{e(str(signer_field.get("jwk", {}).get("kty", "")))}/{e(str(signer_field.get("jwk", {}).get("crv", "")))}</code> x=<code>{e(str(signer_field.get("jwk", {}).get("x", ""))[:16])}…</code> <span class=dim>(public key only; the private key never leaves the planner process)</span></div></div>'
        f'<h3>HTTP request headers (added by the planner)</h3><div class="hdr">{hdr_html}<div class=dim>A2A-Version: 1.0 and Content-Type are added by the SDK · JSON-RPC method <b>{e(req.get("jsonrpc_method", "SendMessage"))}</b></div></div>'
        f'<h3>Planner trace (metadata …/v1/trace, SRML rendered)</h3>{srml_html(req_body)}'
        f'<h3>Message metadata (trimmed)</h3>{pre(trim_meta(req_meta), 34)}'
        + checks_table(t["checks"], ["planner trace validates (scholialang)", "planner signs its trace; signer {kid, jwk} attached (no private material)"])
        + f'<details><summary>show full message as sent (JSON)</summary><pre>{e(json.dumps(msg, indent=1, ensure_ascii=False))}</pre></details>'))

    # 3 Signal and echo
    echo = t.get("echo_header")
    art_exts = t.get("artifact_extensions") or artifact.get("extensions", [])
    sections.append(step(3, "Signal: extensions[] is authoritative; the header echo is only a courtesy",
        "Draft 0.2 moved the activation signal in-band: every Message or Artifact that carries provenance keys must list the extension URI in its own extensions field, and receivers decide presence from that field. The analyst still echoes the A2A-Extensions header (a SHOULD), observed here with a raw probe because the SDK client cannot see response headers; the planner's verification never consults it.",
        f'<div class="kv"><div>Message.extensions</div><div><code>{e(", ".join(msg.get("extensions", [])))}</code></div>'
        f'<div>Artifact.extensions</div><div><code>{e(", ".join(art_exts))}</code></div>'
        f'<div>echo header</div><div><code>A2A-Extensions: {e(str(echo))}</code> <span class=dim>(SHOULD; not relied on)</span></div></div>'
        + checks_table(t["checks"], ["artifact lists the extension URI in its extensions[] (in-band signal)", "analyst echoes A2A-Extensions (SHOULD; observed, not relied on)"])))

    # 4 Response
    f = {k.replace(EXTENSION_URI + "/", ""): val for k, val in art_meta.items() if k.startswith(EXTENSION_URI)}
    trace = f.get("trace", {})
    sig = f.get("signature", "")
    seen = t.get("requester_provenance_as_seen_by_analyst") or {}
    sections.append(step(4, "Response: the analyst's artifact with provenance",
        "The analyst answers normally (text plus a data table) and, because the extension is active, its artifact lists the URI in extensions[] and its own metadata carries the reasoning trace: Evidence atoms with polarity, a Finding with a status, the sha256:<hex> hash, the parent link to the planner's trace, the declared claims, the validator record with grammar and validator versions, and a signature. It also reports back what it saw of the planner's provenance: integrity verified, identity self-asserted.",
        f'<h3>Task</h3><div class="kv"><div>state</div><div><code>{e(task.get("status", {}).get("state", ""))}</code></div><div>artifact</div><div>{e(artifact.get("name", ""))} · extensions[] = <code>{e(", ".join(art_exts))}</code></div></div>'
        f'<h3>Answer (text part)</h3><div class="answer">{e(" ".join(p["text"] for p in answer_parts))}</div>'
        + checks_table(t["checks"], ["task completed", "artifact has a plain answer"])
        + f'<h3>Requester provenance, as the analyst saw it</h3><div class="hl">{badge(bool(seen.get("ok")))} signature <b>{e(str(seen.get("signature")))}</b> · identity <b>{e(str(seen.get("identity")))}</b> · “{e(str(seen.get("signature_statement", "")))}” · signalled {e(str(seen.get("signalled")))}</div>'
        + (f'<details><summary>show data parts (comparison table, requester provenance summary)</summary><pre>{e(json.dumps([p["data"] for p in data_parts], indent=1, ensure_ascii=False))}</pre></details>' if data_parts else "")
        + f'<h3>Analyst trace (…/v1/trace, SRML rendered)</h3>{srml_html(trace.get("body", ""))}'
        f'<h3>Provenance fields</h3><div class="kv">'
        f'<div>trace.format</div><div><code>{e(str(trace.get("format")))}</code> <span class=dim>(the only v1 format)</span></div>'
        f'<div>sha256</div><div><code>{e(f.get("sha256", ""))}</code></div>'
        f'<div>parent</div><div><code>{e(", ".join(f.get("parent", [])))}</code> <span class=dim>= planner trace hash</span></div>'
        f'<div>claims</div><div><code>{e(json.dumps(f.get("claims", [])))}</code></div>'
        f'<div>validator</div><div><code>{e(json.dumps(f.get("validator", {})))}</code></div>'
        f'<div>signature</div><div><code>{e(sig[:40])}…</code> <span class=dim>JWS compact, EdDSA, kid={e(json.loads(_b64json(sig.split(".")[0])).get("kid", "")) if sig else ""}</span></div></div>'
        f'<h3>Artifact metadata (trimmed)</h3>{pre(trim_meta(art_meta), 30)}'
        f'<details><summary>show full artifact (JSON)</summary><pre>{e(json.dumps(artifact, indent=1, ensure_ascii=False))}</pre></details>'))

    # 5 Verification
    ver_names = [c["name"] for c in t["checks"] if c["name"] in {
        "artifact carries provenance keys in its own metadata map", "trace format is srml", "sha256 (sha256:<hex> form) matches canonical trace",
        "JWS signature verifies against the card JWK (identity: agent-card)", "analyst trace validates (re-run locally)",
        "validator record carries validator_version and grammar_version", "declared claims consistent with the cited set (REFER ∪ shared hypothesis)",
        "parent links to planner trace hash", "evidence carries supports/refutes polarity",
        "requester signature verified by analyst via signer (integrity verified, identity self-asserted)", "L1 verification PASS",
    } or c["name"].startswith("inline body within max_inline_bytes")]
    sections.append(step(5, "Verification: the planner checks everything itself, in the spec's order",
        "In-band signal, format, canonical hash, signature with the key from the Agent Card, validator re-run, then claims against the cited set (inline REFER union shared hypothesis). The analyst did the same for the planner's trace using the inline signer key. All of that is audit level L1 (structural).",
        checks_table(t["checks"], ver_names)
        + f'<div class="hl">L1 result: {badge(v.get("ok", False))} · signature <b>{e(v.get("signature_statement", v.get("signature", "")))}</b> · validator {e(v.get("validator_version", ""))} / grammar {e(v.get("grammar_version", ""))} · atoms {e(json.dumps(v.get("atoms", {}).get("kinds", {})))} · polarity {e(json.dumps(v.get("atoms", {}).get("evidence_polarity", {})))}</div>'
        f'<details><summary>show verifier output (safe summary, no trace text)</summary><pre>{e(json.dumps(v, indent=1))}</pre></details>'))

    # 6 Tamper
    tam = t.get("tamper", {})
    changes = t.get("tamper_changes", {})
    tamper_rows = []
    for key_, label, caught in (
        ("flip_polarity", "TAMPER 1: flip one Evidence polarity", "hash check"),
        ("flip_and_rehash", "TAMPER 2: flip and re-hash", "signature check"),
        ("bad_claim", "TAMPER 3: claim an uncited dependency (superset)", "claims check"),
        ("drop_extensions", "TAMPER 4: strip extensions[] but keep the keys", "in-band signal check"),
    ):
        r = tam.get(key_, {})
        tamper_rows.append(
            f'<div class="step" style="margin:.6rem 0;padding-top:.8rem"><h2 style="font-size:1rem">{e(label)}</h2>'
            f'<p class="why">{e(changes.get(key_, ""))}</p>'
            f'<div class="kv"><div>verdict</div><div>{badge(r.get("ok", True), good_when_false=True)}</div>'
            f'<div>caught by</div><div><b>{e(caught)}</b></div>'
            f'<div>signalled</div><div class="{"ok" if r.get("signalled") else "bad"}">{e(str(r.get("signalled")))}</div>'
            f'<div>hash_ok</div><div class="{"ok" if r.get("hash_ok") else "bad"}">{e(str(r.get("hash_ok")))}</div>'
            f'<div>signature</div><div class="{"ok" if r.get("signature") == "verified" else "bad"}">{e(str(r.get("signature")))}</div>'
            f'<div>claims_ok</div><div class="{"ok" if r.get("claims_ok") else "bad"}">{e(str(r.get("claims_ok")))}</div>'
            f'<div>errors</div><div class=dim>{e("; ".join(r.get("errors", []))[:300])}</div></div></div>'
        )
    sections.append(step(6, "Tamper tests: a FAIL here is the good outcome",
        "Four altered copies of the real artifact are verified again; each must fail, and the table shows which layer catches it: the hash binds content, the signature binds the hash to the analyst's key, the claims check binds the declared dependencies to the trace, and the in-band signal check refuses provenance keys that are not announced in extensions[].",
        "".join(tamper_rows) + checks_table(t["checks"], prefix="TAMPER")))

    # 7 Rules
    rules = t.get("rules", {})
    rchanges = t.get("rule_changes", {})
    rule_rows = []
    for key_, label, expect in (
        ("claims_subset", "RULE: claims strict subset → PASS with a warning", "verifies; warning lists the omitted evidence"),
        ("format_json", "RULE: format other than srml → rejected", "fails before hashing; never guessed"),
    ):
        r = rules.get(key_, {})
        rule_rows.append(
            f'<div class="step" style="margin:.6rem 0;padding-top:.8rem"><h2 style="font-size:1rem">{e(label)}</h2>'
            f'<p class="why">{e(rchanges.get(key_, ""))}</p>'
            f'<div class="kv"><div>verdict</div><div>{badge(bool(r.get("ok")))} <span class=dim>expected: {e(expect)}</span></div>'
            f'<div>format</div><div><code>{e(str(r.get("format")))}</code></div>'
            f'<div>claims_ok</div><div class="{"ok" if r.get("claims_ok") else "bad"}">{e(str(r.get("claims_ok")))}</div>'
            f'<div>warnings</div><div class=dim>{e("; ".join(r.get("warnings", []))[:300]) or "none"}</div>'
            f'<div>errors</div><div class=dim>{e("; ".join(r.get("errors", []))[:300]) or "none"}</div></div></div>'
        )
    sections.append(step(7, "Rules: subset claims warn, unknown formats are rejected",
        "Two behaviours draft 0.2 pins down that are not tampering. Declaring fewer dependencies than the trace cites is honest under-claiming, so it passes with a warning; declaring more is a failure (tamper test 3). And since v1 defines exactly one trace format, anything else is rejected rather than parsed on a guess.",
        "".join(rule_rows) + checks_table(t["checks"], prefix="RULE:")))

    # 8 Compatibility
    pc = t.get("plain_client", {})
    sections.append(step(8, "Compatibility: a client that never heard of the extension",
        "The same question sent without the header, without extensions[] and without metadata gets the same normal answer, an artifact with no extensions[] entry and no provenance block, which is what required=false promises.",
        f'<div class="kv"><div>header</div><div><span class=dim>(no A2A-Extensions)</span></div><div>state</div><div><code>{e(str(pc.get("state")))}</code></div>'
        f'<div>answer</div><div class="answer">{e(str(pc.get("answer", "")))}</div>'
        f'<div>artifact extensions[]</div><div><code>{e(json.dumps(pc.get("extensions", [])))}</code></div>'
        f'<div>metadata keys</div><div><code>{e(json.dumps(pc.get("metadata_keys", [])))}</code></div>'
        f'<div>has provenance</div><div><code>{e(str(pc.get("has_provenance")).lower())}</code></div></div>'
        + checks_table(t["checks"], prefix="plain client")))

    # 9 Closing
    cf = {k.replace(EXTENSION_URI + "/", ""): val for k, val in closing_meta.items() if k.startswith(EXTENSION_URI)}
    closing_body = cf.get("trace", {}).get("body", "")
    pav = t.get("planner_agent_verification") or {}
    chain = f'<div class="hl">planner request <code>{e(short(planner_hash))}</code> ← analyst <code>{e(short(analyst_hash))}</code> ← planner closing <code>{e(short(cf.get("sha256")))}</code></div>'
    graph_block = ""
    if graph_html:
        m = re.search(r"<svg.*?</svg>", graph_html, re.S)
        if m:
            graph_block = f'<h3>Provenance graph</h3><div class="graphwrap">{m.group(0)}</div>'
    graph_block += f'<p><a href="{e(graph_link)}">Open the full provenance graph page →</a></p>'
    sections.append(step(9, "Closing: the planner as an A2A agent",
        "A third party asks the planner over A2A; the planner delegates to the analyst, verifies the result, and returns its own closing trace (Goal → Finding → Concluding) whose parent is the analyst's hash. Here the planner is a responder, so its Agent Card publishes its public key and the closing artifact's signature verifies against it; the whole delegation is one hash-linked graph.",
        f'<div class="kv"><div>state</div><div><code>{e(closing_task.get("status", {}).get("state", ""))}</code></div>'
        f'<div>extensions[]</div><div><code>{e(", ".join(closing_art.get("extensions", [])))}</code></div>'
        f'<div>parent</div><div><code>{e(", ".join(cf.get("parent", [])))}</code> <span class=dim>= analyst trace hash</span></div>'
        f'<div>signature</div><div><b>{e(str(pav.get("signature_statement", pav.get("signature", ""))))}</b></div></div>'
        + chain + checks_table(t["checks"], prefix="planner ")
        + (f'<h3>Closing trace (SRML rendered)</h3>{srml_html(closing_body)}' if closing_body else "")
        + f'<details><summary>show closing artifact metadata</summary><pre>{e(json.dumps(closing_meta, indent=1, ensure_ascii=False))}</pre></details>'
        + graph_block))

    total = len(t["checks"])
    passed = sum(1 for c in t["checks"] if c["ok"])
    toc = "".join(f'<a href="#s{i}">{i}. {n}</a>' for i, n in enumerate(["Discovery", "Request", "Signal", "Response", "Verification", "Tamper", "Rules", "Compatibility", "Closing"], 1))
    stamp = time.strftime("%Y-%m-%d %H:%M %Z")
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Scholia A2A walkthrough</title><style>{CSS}</style></head><body>
<div class="banner"><b>Reference implementation of Scholia Provenance for A2A — spec draft 0.2.</b> Spec: <a href="{EXTENSION_URI}">{EXTENSION_URI}</a></div>
<div class="wrap">
<h1>See it in action: provenance across two A2A agents</h1>
<div class="sub">Generated from the real demo run · question “{e(t.get("question", ""))}” · {passed}/{total} checks passed · a2a-sdk 1.2.1 · grammar 0.6.2 · validator 0.7.2 · keys ephemeral, public halves only</div>
<div class="toc">{toc}</div>
{''.join(sections)}
<div class="foot">scholia-a2a commit {e(commit)} · generated {e(stamp)} · demo transcript {e(os.path.basename(t.get("_path", "transcript.json")))} · generated demo page</div>
</div></body></html>"""


def _b64json(seg: str) -> str:
    import base64

    try:
        return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4)).decode()
    except Exception:
        return "{}"


def scan_secrets(text: str) -> list[str]:
    """Names of secret-like patterns found in `text` (empty list = clean)."""
    return [name for name, rx in SECRET_PATTERNS.items() if rx.search(text)]


def scan_json_for_private_jwk(obj: Any, path: str = "$") -> list[str]:
    """Paths of any JWK-looking object (kty present) that carries a private member."""
    hits: list[str] = []
    if isinstance(obj, dict):
        if "kty" in obj and any(k in obj for k in ("d", "p", "q", "dp", "dq", "qi", "k")):
            hits.append(path)
        for k, v in obj.items():
            hits += scan_json_for_private_jwk(v, f"{path}.{k}")
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            hits += scan_json_for_private_jwk(v, f"{path}[{i}]")
    return hits


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--transcript", default="demo-out/transcript.json")
    ap.add_argument("--graph", default="demo-out/provenance-graph.html")
    ap.add_argument("--graph-link", default="scholia-a2a-demo-graph.html")
    ap.add_argument("--out", default="demo-out/walkthrough.html")
    a = ap.parse_args()
    with open(a.transcript, encoding="utf-8") as fh:
        transcript = json.load(fh)
    transcript["_path"] = a.transcript
    graph_html = open(a.graph, encoding="utf-8").read() if os.path.exists(a.graph) else None
    try:
        commit = subprocess.run(["git", "rev-parse", "--short", "HEAD"], capture_output=True, text=True, check=True).stdout.strip()
    except Exception:
        commit = "unknown"
    page = build(transcript, graph_html, commit, a.graph_link)
    # Scan everything that will be served or published: the page, the graph, and the transcript
    # (text and structure, so a private JWK member is caught whichever key it belongs to:
    # the analyst's card key, the planner's card key or the planner's requester `signer` key).
    hits = [f"page:{h}" for h in scan_secrets(page)]
    hits += [f"graph:{h}" for h in scan_secrets(graph_html or "")]
    hits += [f"transcript:{h}" for h in scan_secrets(open(a.transcript, encoding="utf-8").read())]
    hits += [f"transcript-jwk:{h}" for h in scan_json_for_private_jwk(transcript)]
    if hits:
        print(f"REFUSING to write {a.out}: secret-like patterns found: {hits}", file=sys.stderr)
        return 2
    with open(a.out, "w", encoding="utf-8") as fh:
        fh.write(page)
    print(f"wrote {a.out} ({len(page)} bytes), commit {commit}, secret scan clean (page, graph, transcript)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
