"""Cross-agent provenance DAG and a self-contained HTML/SVG renderer.

Nodes are traces keyed by sha256; edges are `parent` links between traces
and Finding -> Evidence claims inside a trace. The HTML is dark-themed,
inline SVG only, no external assets, and readable on a phone (one trace
card fits a 375px viewport; wider graphs scroll sideways).
"""

from __future__ import annotations

import html
import json
from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping

from . import ext
from .provenance import normalize_hash, parse_trace, walk_atoms
from .verify import VerifyResult, verify_provenance

KIND_COLORS = {
    "Goal": "#bc8cff",
    "Constraint": "#d29922",
    "Deciding": "#58a6ff",
    "Branch": "#58a6ff",
    "Alternative": "#8b949e",
    "Hypothesis": "#79c0ff",
    "Evidence": "#3fb950",
    "Observation": "#56d4dd",
    "Finding": "#f0883e",
    "Concluding": "#ff7b72",
    "Step": "#8b949e",
}
POLARITY_COLORS = {"supports": "#3fb950", "refutes": "#f85149", "neutral": "#8b949e"}


@dataclass
class AtomRow:
    kind: str
    id: str
    polarity: str | None = None
    status: str | None = None
    preview: str = ""


@dataclass
class TraceNode:
    sha256: str
    agent: str
    label: str = ""
    parents: list[str] = field(default_factory=list)
    claims: list[dict[str, Any]] = field(default_factory=list)
    atoms: list[AtomRow] = field(default_factory=list)
    verify: VerifyResult | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class ProvenanceGraph:
    def __init__(self) -> None:
        self.nodes: dict[str, TraceNode] = {}
        self.events: list[dict[str, Any]] = []

    def add(
        self,
        metadata: Mapping[str, Any],
        agent: str,
        label: str = "",
        verify: VerifyResult | None = None,
        preview_chars: int = 110,
        fetch: Any = None,
        verifier: Any = None,
    ) -> TraceNode:
        if verify is None:
            verify = verify_provenance(metadata, fetch=fetch, verifier=verifier)
        fields = ext.extract(metadata)
        sha = normalize_hash(str(fields.get("sha256", "0" * 64))) if fields.get("sha256") else "sha256:" + "0" * 64
        node = TraceNode(sha256=sha, agent=agent, label=label, verify=verify, metadata=dict(metadata))
        node.parents = list(verify.parents)
        node.claims = list(fields.get("claims") or [])
        trace = fields.get("trace") or {}
        body = trace.get("body") if trace.get("mode") == "inline" else (fetch(trace["uri"]) if fetch and trace.get("uri") else None)
        if body is not None:
            try:
                for a in walk_atoms(parse_trace(body, trace.get("format", "srml"))):
                    if a.kind in ("Branch", "Alternative", "Print"):
                        continue
                    text = " ".join((a.content or "").split())
                    if len(text) > preview_chars:
                        text = text[: preview_chars - 1] + "…"
                    node.atoms.append(
                        AtomRow(
                            kind=a.kind,
                            id=a.id or "",
                            polarity=getattr(a, "polarity", None) if a.kind == "Evidence" else None,
                            status=getattr(a, "status", None) if a.kind in ("Finding", "Concluding") else None,
                            preview=text,
                        )
                    )
            except Exception:
                pass
        self.nodes[sha] = node
        return node

    def add_event(self, name: str, ok: bool, detail: str = "") -> None:
        self.events.append({"name": name, "ok": ok, "detail": detail})

    def edges(self) -> list[tuple[str, str]]:
        return [(n.sha256, p) for n in self.nodes.values() for p in n.parents]

    def depth(self, sha: str, _seen: frozenset[str] = frozenset()) -> int:
        node = self.nodes.get(sha)
        if node is None or sha in _seen:
            return 0
        ps = [p for p in node.parents if p in self.nodes]
        if not ps:
            return 0
        return 1 + max(self.depth(p, _seen | {sha}) for p in ps)

    def to_dict(self) -> dict[str, Any]:
        return {
            "nodes": [
                {
                    "sha256": n.sha256,
                    "agent": n.agent,
                    "label": n.label,
                    "parents": n.parents,
                    "claims": n.claims,
                    "ok": n.verify.ok if n.verify else None,
                    "atoms": [a.__dict__ for a in n.atoms],
                }
                for n in self.nodes.values()
            ],
            "edges": [{"from": a, "to": b} for a, b in self.edges()],
            "events": self.events,
        }


# ------------------------------------------------------------------ render

_CSS = """
:root{--bg:#0d1117;--panel:#161b22;--panel2:#1c2128;--border:#30363d;--fg:#e6edf3;--dim:#8b949e;--accent:#58a6ff;--purple:#bc8cff;--green:#3fb950;--amber:#d29922;--red:#f85149}
*{box-sizing:border-box}html{-webkit-font-smoothing:antialiased}
body{margin:0;background:var(--bg);color:var(--fg);font:15px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
.wrap{max-width:1100px;margin:0 auto;padding:1.2rem 16px 3rem}
h1{font-size:1.35rem;margin:.2rem 0;text-wrap:balance}h2{font-size:1.05rem;color:var(--purple);margin:1.8rem 0 .5rem;border-bottom:1px solid var(--border);padding-bottom:.3rem}
.sub{color:var(--dim);font-size:.88rem;margin:.2rem 0 .8rem}
.scroll{overflow-x:auto;-webkit-overflow-scrolling:touch;border:1px solid var(--border);border-radius:12px;background:var(--panel)}
svg{display:block}
.card{background:var(--panel);border:1px solid var(--border);border-radius:12px;padding:.8rem 1rem;margin:.8rem 0}
table{border-collapse:collapse;width:100%;font-size:.86rem}th{background:var(--panel2);color:var(--dim);text-align:left;padding:.35rem .5rem;border:1px solid var(--border)}
td{padding:.35rem .5rem;border:1px solid var(--border);vertical-align:top;word-break:break-word}
.ok{color:var(--green);font-weight:700}.bad{color:var(--red);font-weight:700}.dim{color:var(--dim)}
code{font:.84em ui-monospace,SFMono-Regular,Menlo,monospace;background:#0d1117;border:1px solid var(--border);border-radius:5px;padding:.02rem .3rem}
pre{white-space:pre-wrap;word-break:break-word;background:var(--panel2);border:1px solid var(--border);border-radius:10px;padding:.6rem .8rem;font:.76rem/1.42 ui-monospace,SFMono-Regular,Menlo,monospace;max-height:50vh;overflow:auto}
details{margin:.4rem 0}summary{cursor:pointer;color:var(--accent)}
.legend{display:flex;flex-wrap:wrap;gap:.5rem .9rem;font-size:.8rem;color:var(--dim);margin:.6rem 0 0}
.legend span::before{content:"";display:inline-block;width:.7em;height:.7em;border-radius:3px;margin-right:.35em;background:var(--c);vertical-align:-.05em}
.badge{display:inline-block;font-size:.72rem;font-weight:700;border-radius:20px;padding:.05rem .5rem;border:1px solid var(--border)}
.badge.ok{background:#3fb95022;border-color:#3fb95055}.badge.bad{background:#f8514922;border-color:#f8514955}
.foot{color:var(--dim);font-size:.78rem;margin-top:2rem;border-top:1px solid var(--border);padding-top:.6rem}
"""


def _short(sha: str) -> str:
    h = sha.split(":", 1)[-1]
    return h[:12]


def render_html(graph: ProvenanceGraph, title: str = "Scholia provenance graph", subtitle: str = "") -> str:
    """Self-contained dark HTML page with an inline-SVG DAG and verification tables."""
    e = html.escape
    nodes = list(graph.nodes.values())
    # Column per depth (parents left, children right); order within column by insertion.
    cols: dict[int, list[TraceNode]] = {}
    for n in nodes:
        cols.setdefault(graph.depth(n.sha256), []).append(n)
    ncols = (max(cols) + 1) if cols else 1

    card_w, col_gap, row_h, head_h, pad = 330, 70, 36, 64, 12
    margin_l = 24
    positions: dict[str, tuple[float, float, float]] = {}  # sha -> (x, y, h)
    col_heights: dict[int, float] = {}
    for d in range(ncols):
        y = 20.0
        for n in cols.get(d, []):
            h = head_h + row_h * max(1, len(n.atoms)) + pad
            x = margin_l + d * (card_w + col_gap)
            positions[n.sha256] = (x, y, h)
            y += h + 28
        col_heights[d] = y
    total_w = margin_l + ncols * (card_w + col_gap)
    total_h = max(col_heights.values()) + 10 if col_heights else 120

    svg: list[str] = []
    svg.append(
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{total_w}" height="{total_h}" viewBox="0 0 {total_w} {total_h}" '
        'font-family="-apple-system,BlinkMacSystemFont,Segoe UI,Helvetica,Arial,sans-serif" font-size="12">'
    )
    svg.append(
        '<defs><marker id="arr" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="8" markerHeight="8" orient="auto-start-reverse">'
        '<path d="M0 0L10 5L0 10z" fill="#58a6ff"/></marker>'
        '<marker id="arrc" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="7" markerHeight="7" orient="auto-start-reverse">'
        '<path d="M0 0L10 5L0 10z" fill="#f0883e"/></marker></defs>'
    )
    # Parent edges (child -> parent).
    for n in nodes:
        cx, cy, ch = positions[n.sha256]
        for p in n.parents:
            if p not in positions:
                # Unknown parent: draw a stub to the left.
                svg.append(f'<path d="M{cx} {cy+30} L{cx-40} {cy+30}" stroke="#8b949e" stroke-dasharray="4 3" fill="none" marker-end="url(#arr)"/>')
                svg.append(f'<text x="{cx-42}" y="{cy+24}" fill="#8b949e" font-size="10" text-anchor="end">parent {e(_short(p))}… (not in graph)</text>')
                continue
            px, py, ph = positions[p]
            x1, y1 = cx, cy + 30
            x2, y2 = px + card_w, py + 30
            mx = (x1 + x2) / 2
            svg.append(f'<path d="M{x1} {y1} C{mx} {y1} {mx} {y2} {x2} {y2}" stroke="#58a6ff" stroke-width="2" fill="none" marker-end="url(#arr)"/>')
            svg.append(f'<text x="{mx}" y="{min(y1,y2)-8}" fill="#58a6ff" font-size="10" text-anchor="middle">parent = sha256 of requester trace</text>')
    # Cards.
    for n in nodes:
        x, y, h = positions[n.sha256]
        ok = n.verify.ok if n.verify else None
        stroke = "#3fb950" if ok else ("#f85149" if ok is False else "#30363d")
        svg.append(f'<rect x="{x}" y="{y}" width="{card_w}" height="{h}" rx="12" fill="#1c2128" stroke="{stroke}" stroke-width="1.5"/>')
        svg.append(f'<text x="{x+14}" y="{y+22}" fill="#e6edf3" font-size="14" font-weight="700">{e(n.agent)}</text>')
        badge = "VERIFIED" if ok else ("FAILED" if ok is False else "UNCHECKED")
        bcol = "#3fb950" if ok else ("#f85149" if ok is False else "#8b949e")
        svg.append(f'<text x="{x+card_w-14}" y="{y+22}" fill="{bcol}" font-size="11" font-weight="700" text-anchor="end">{badge}</text>')
        svg.append(f'<text x="{x+14}" y="{y+40}" fill="#8b949e" font-size="10.5" font-family="ui-monospace,Menlo,monospace">sha256:{e(_short(n.sha256))}…  {e(n.label)}</text>')
        sig = n.verify.safe_summary()["signature"] if n.verify else "none"
        svg.append(f'<text x="{x+14}" y="{y+54}" fill="#8b949e" font-size="10.5">signature: {e(sig)} · validator {e(str(n.verify.validator_version or "") if n.verify else "")}</text>')
        row_y = {}
        for i, a in enumerate(n.atoms):
            ry = y + head_h + i * row_h
            row_y[a.id] = ry + row_h / 2
            col = KIND_COLORS.get(a.kind, "#8b949e")
            svg.append(f'<rect x="{x+34}" y="{ry+6}" width="{card_w-48}" height="{row_h-10}" rx="7" fill="#161b22" stroke="#30363d"/>')
            svg.append(f'<rect x="{x+34}" y="{ry+6}" width="5" height="{row_h-10}" rx="2" fill="{col}"/>')
            label = f"{a.kind} {a.id}".strip()
            svg.append(f'<text x="{x+46}" y="{ry+19}" fill="{col}" font-size="11" font-weight="700">{e(label)}</text>')
            tag = a.polarity or a.status
            if tag:
                tcol = POLARITY_COLORS.get(tag, "#d29922")
                svg.append(f'<text x="{x+card_w-20}" y="{ry+19}" fill="{tcol}" font-size="10.5" font-weight="700" text-anchor="end">{e(tag)}</text>')
            prev = a.preview
            if len(prev) > 52:
                prev = prev[:51] + "…"
            svg.append(f'<text x="{x+46}" y="{ry+30}" fill="#c9d1d9" font-size="10.5">{e(prev)}</text>')
        # Intra-trace claim edges: Finding -> Evidence, drawn in the left gutter.
        for c in n.claims:
            fy = row_y.get(c.get("finding"))
            if fy is None:
                continue
            for k, d in enumerate(c.get("depends_on", [])):
                dy = row_y.get(d)
                if dy is None:
                    continue
                gx = x + 34
                bend = x + 12 - 4 * (k % 3)
                svg.append(f'<path d="M{gx} {fy} C{bend} {fy} {bend} {dy} {gx} {dy}" stroke="#f0883e" stroke-width="1.5" fill="none" marker-end="url(#arrc)"/>')
    svg.append("</svg>")

    # Tables.
    rows = []
    for n in nodes:
        v = n.verify
        s = v.safe_summary() if v else {}
        def cell(val: Any) -> str:
            if val is True:
                return '<td class="ok">yes</td>'
            if val is False:
                return '<td class="bad">NO</td>'
            return f'<td class="dim">{e(str(val))}</td>'
        rows.append(
            "<tr>"
            f"<td><b>{e(n.agent)}</b><br><span class=dim>{e(n.label)}</span></td>"
            f"<td><code>{e(_short(n.sha256))}…</code></td>"
            + cell(s.get("hash_ok")) + f"<td>{e(str(s.get('signature')))}</td>" + cell(s.get("validator_ok")) + cell(s.get("claims_ok"))
            + f"<td>{', '.join(e(_short(p)) + '…' for p in n.parents) or '<span class=dim>none (root)</span>'}</td>"
            + (f'<td class="ok">PASS</td>' if (v and v.ok) else '<td class="bad">FAIL</td>')
            + "</tr>"
        )
    ev_rows = "".join(
        f"<tr><td>{e(ev['name'])}</td><td class=\"{'ok' if ev['ok'] else 'bad'}\">{'PASS' if ev['ok'] else 'FAIL'}</td><td>{e(ev['detail'])}</td></tr>"
        for ev in graph.events
    )
    legend = "".join(f'<span style="--c:{c}">{e(k)}</span>' for k, c in KIND_COLORS.items() if k != "Step")
    legend += '<span style="--c:#58a6ff">parent link</span><span style="--c:#f0883e">claim: Finding → Evidence</span>'
    details = "".join(
        f"<details><summary>{e(n.agent)} · metadata (raw, escaped) · {e(_short(n.sha256))}…</summary><pre>{e(json.dumps(n.metadata, indent=1, ensure_ascii=False))}</pre></details>"
        for n in nodes
    )
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>{e(title)}</title><style>{_CSS}</style></head><body><div class="wrap">
<h1>{e(title)}</h1><div class="sub">{e(subtitle)}</div>
<div class="scroll">{''.join(svg)}</div>
<div class="legend">{legend}</div>
<h2>Verification (L1 structural)</h2>
<div class="scroll" style="border:0"><table><tr><th>Trace</th><th>sha256</th><th>hash</th><th>signature</th><th>validator</th><th>claims</th><th>parents</th><th>verdict</th></tr>{''.join(rows)}</table></div>
{'<h2>Checks</h2><div class="scroll" style="border:0"><table><tr><th>Check</th><th>Result</th><th>Detail</th></tr>' + ev_rows + '</table></div>' if graph.events else ''}
<h2>Raw metadata</h2>{details}
<div class="foot">Scholia Provenance Extension for A2A, draft 0.1 reference implementation. Trace content shown here is untrusted data, rendered escaped; it is never placed in a model's instruction context by this tool.</div>
</div></body></html>"""
