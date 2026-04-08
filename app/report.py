from __future__ import annotations

import html

from app.models import AnalyzeResponse, Finding


def _sev_color(sev: str) -> str:
    return {"high": "#b42318", "medium": "#b54708", "low": "#1d4ed8"}.get(sev, "#111827")


def render_html_report(resp: AnalyzeResponse) -> str:
    rows = "\n".join(_finding_card(f) for f in resp.findings) or "<p>Aucun finding.</p>"
    return f"""<!doctype html>
<html lang="fr">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>Rapport — Détection buffer overflow</title>
  <style>
    body {{ font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial; margin: 24px; color: #111827; }}
    .top {{ display:flex; justify-content:space-between; align-items:flex-end; gap: 16px; flex-wrap: wrap; }}
    .meta {{ color:#374151; font-size: 14px; }}
    .grid {{ display:grid; grid-template-columns: 1fr; gap: 12px; margin-top: 16px; }}
    .card {{ border: 1px solid #e5e7eb; border-radius: 12px; padding: 14px; }}
    .title {{ display:flex; align-items:center; justify-content:space-between; gap: 12px; }}
    .badge {{ font-size: 12px; padding: 2px 8px; border-radius: 999px; color: white; }}
    pre {{ background:#0b1020; color:#e5e7eb; padding: 10px; border-radius: 10px; overflow:auto; }}
    code {{ font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
    .kv {{ display:flex; gap: 10px; flex-wrap: wrap; margin-top: 6px; color:#374151; font-size: 13px; }}
  </style>
</head>
<body>
  <div class="top">
    <div>
      <h2 style="margin:0">Rapport d’analyse</h2>
      <div class="meta">Langage: <b>{html.escape(resp.language.value)}</b> — Findings: <b>{len(resp.findings)}</b></div>
    </div>
  </div>
  <div class="grid">
    {rows}
  </div>
</body>
</html>"""


def _finding_card(f: Finding) -> str:
    sev = html.escape(f.severity)
    cwes = ", ".join(html.escape(c) for c in f.cwe) if f.cwe else "—"
    loc = f"{f.location.file}:{f.location.line}:{f.location.column}"
    snippet = f.snippet or ""
    return f"""
<div class="card">
  <div class="title">
    <div>
      <div style="font-weight:700">{html.escape(f.title)}</div>
      <div class="kv">
        <div><b>Rule</b>: {html.escape(f.rule_id)}</div>
        <div><b>Severity</b>: {sev}</div>
        <div><b>CWE</b>: {cwes}</div>
        <div><b>Loc</b>: {html.escape(loc)}</div>
      </div>
    </div>
    <span class="badge" style="background:{_sev_color(f.severity)}">{sev}</span>
  </div>
  <p style="margin:10px 0 6px 0"><b>Message</b>: {html.escape(f.message)}</p>
  <p style="margin:0 0 10px 0"><b>Explication</b>: {html.escape(f.explanation)}</p>
  {"<pre><code>"+html.escape(snippet)+"</code></pre>" if snippet else ""}
</div>
"""

