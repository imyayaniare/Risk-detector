function sevColor(sev) {
  if (sev === "high") return "#b42318";
  if (sev === "medium") return "#b54708";
  return "#1d4ed8";
}

function escapeHtml(s) {
  return String(s)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

let lastJson = null;

async function analyze() {
  const lang = document.getElementById("lang").value;
  const code = document.getElementById("code").value;
  const summary = document.getElementById("summary");
  const results = document.getElementById("results");
  const downloadJsonBtn = document.getElementById("downloadJsonBtn");
  const openHtmlBtn = document.getElementById("openHtmlBtn");

  results.innerHTML = "";
  summary.textContent = "Analyse en cours…";
  downloadJsonBtn.disabled = true;
  openHtmlBtn.disabled = true;

  const res = await fetch("/analyze", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ language: lang, code }),
  });

  if (!res.ok) {
    const txt = await res.text();
    summary.textContent = "Erreur: " + txt;
    return;
  }

  const data = await res.json();
  lastJson = data;

  const n = data.findings.length;
  summary.textContent = `OK — ${n} finding(s).`;

  if (n === 0) {
    results.innerHTML = `<div class="card">Aucun finding.</div>`;
  } else {
    results.innerHTML = data.findings
      .map((f) => {
        const cwe = (f.cwe && f.cwe.length) ? f.cwe.join(", ") : "—";
        const loc = `${f.location.file}:${f.location.line}:${f.location.column}`;
        const snippet = f.snippet ? `<pre><code>${escapeHtml(f.snippet)}</code></pre>` : "";
        return `
          <div class="card">
            <div class="cardTop">
              <div>
                <div style="font-weight:700">${escapeHtml(f.title)}</div>
                <div class="meta">
                  <div><b>Severity</b>: ${escapeHtml(f.severity)}</div>
                  <div><b>CWE</b>: ${escapeHtml(cwe)}</div>
                  <div><b>Rule</b>: ${escapeHtml(f.rule_id)}</div>
                  <div><b>Loc</b>: ${escapeHtml(loc)}</div>
                </div>
              </div>
              <div class="badge" style="background:${sevColor(f.severity)}">${escapeHtml(f.severity)}</div>
            </div>
            <div style="margin-top:10px"><b>Message</b>: ${escapeHtml(f.message)}</div>
            <div style="margin-top:6px"><b>Explication</b>: ${escapeHtml(f.explanation)}</div>
            ${snippet}
          </div>
        `;
      })
      .join("");
  }

  downloadJsonBtn.disabled = false;
  openHtmlBtn.disabled = false;
}

function downloadJson() {
  if (!lastJson) return;
  const blob = new Blob([JSON.stringify(lastJson, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = "analysis.json";
  a.click();
  URL.revokeObjectURL(url);
}

async function openHtmlReport() {
  const lang = document.getElementById("lang").value;
  const code = document.getElementById("code").value;
  const res = await fetch("/report", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ language: lang, code }),
  });
  const html = await res.text();
  const w = window.open("", "_blank");
  w.document.open();
  w.document.write(html);
  w.document.close();
}

document.getElementById("analyzeBtn").addEventListener("click", analyze);
document.getElementById("downloadJsonBtn").addEventListener("click", downloadJson);
document.getElementById("openHtmlBtn").addEventListener("click", openHtmlReport);

