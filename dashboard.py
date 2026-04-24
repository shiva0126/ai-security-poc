#!/usr/bin/env python3
"""
AI Security POC Dashboard
Run: python3 dashboard.py
Access: http://localhost:9002
"""
import os, sys, json
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import findings as F
from fastapi import FastAPI, Response
from fastapi.responses import HTMLResponse
import uvicorn

app = FastAPI(title="AI Security POC Dashboard")

HTML = r"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width,initial-scale=1"/>
<title>AI Security POC</title>
<style>
:root{
  --bg:#020617;--panel:#0f172a;--panel2:#111827;--border:#1e293b;
  --text:#e2e8f0;--muted:#64748b;--blue:#38bdf8;--navy:#1e40af;
  --green:#22c55e;--red:#ef4444;--amber:#f59e0b;--purple:#a78bfa;
  --teal:#14b8a6;--cyan:#06b6d4;
}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:ui-sans-serif,system-ui,sans-serif;font-size:14px}
.wrap{max-width:1600px;margin:0 auto;padding:20px}

/* Header */
.header{display:flex;justify-content:space-between;align-items:center;
  padding:16px 24px;background:var(--panel);border:1px solid var(--border);
  border-radius:12px;margin-bottom:20px}
.header-left h1{font-size:22px;font-weight:700;color:var(--blue)}
.header-left .sub{font-size:12px;color:var(--muted);margin-top:2px}
.header-right{display:flex;align-items:center;gap:12px}
.live-badge{display:flex;align-items:center;gap:6px;background:#0f2a1a;
  border:1px solid var(--green);border-radius:20px;padding:4px 12px;font-size:12px;color:var(--green)}
.live-dot{width:8px;height:8px;background:var(--green);border-radius:50%;animation:pulse 2s infinite}
@keyframes pulse{0%,100%{opacity:1}50%{opacity:.3}}
.run-btn{background:var(--navy);color:white;border:none;border-radius:8px;
  padding:8px 18px;font-size:13px;cursor:pointer;transition:opacity .2s}
.run-btn:hover{opacity:.8}
.conf-badge{background:#2d1515;border:1px solid var(--red);color:var(--red);
  border-radius:4px;padding:2px 8px;font-size:11px}

/* Stats */
.stats{display:grid;grid-template-columns:repeat(6,1fr);gap:12px;margin-bottom:20px}
.stat{background:var(--panel);border:1px solid var(--border);border-radius:10px;padding:16px;text-align:center}
.stat-val{font-size:32px;font-weight:800;line-height:1}
.stat-label{font-size:11px;color:var(--muted);margin-top:6px;text-transform:uppercase;letter-spacing:.05em}
.c-red{color:var(--red)} .c-amber{color:var(--amber)} .c-blue{color:var(--blue)}
.c-green{color:var(--green)} .c-purple{color:var(--purple)} .c-teal{color:var(--teal)}

/* Layout */
.grid-main{display:grid;grid-template-columns:1fr 340px;gap:16px;margin-bottom:16px}
.grid-bottom{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.card{background:var(--panel);border:1px solid var(--border);border-radius:10px;overflow:hidden}
.card-hdr{padding:12px 16px;border-bottom:1px solid var(--border);
  display:flex;justify-content:space-between;align-items:center}
.card-hdr h2{font-size:13px;font-weight:600;color:var(--blue);text-transform:uppercase;letter-spacing:.05em}
.card-body{padding:0;overflow-y:auto;max-height:420px}

/* Findings table */
table{width:100%;border-collapse:collapse}
th{background:#0a1628;color:var(--muted);font-size:11px;text-transform:uppercase;
  letter-spacing:.05em;padding:8px 12px;text-align:left;position:sticky;top:0}
td{padding:8px 12px;border-bottom:1px solid var(--border);font-size:12px;vertical-align:top}
tr:hover td{background:#0d1f35}

/* Badges */
.badge{display:inline-block;border-radius:4px;padding:1px 6px;font-size:11px;font-weight:600}
.sev-Critical{background:#3d0f0f;color:var(--red);border:1px solid #7b1111}
.sev-High{background:#2d1f06;color:var(--amber);border:1px solid #854f0b}
.sev-Medium{background:#102038;color:var(--blue);border:1px solid #1e40af}
.sev-Low{background:#0a2016;color:var(--green);border:1px solid #166534}
.sev-Info{background:#1a1a2e;color:var(--purple);border:1px solid #4c1d95}

.st-VULNERABLE{background:#3d0f0f;color:var(--red);border:1px solid #7b1111}
.st-RESISTANT,.st-PASS,.st-RUNNING,.st-DEFLECTED,.st-CONTAINED{background:#0a2016;color:var(--green)}
.st-SKIP,.st-SKIP2{background:#1a1a1a;color:var(--muted)}
.st-FAIL,.st-ERROR,.st-DOWN{background:#3d0f0f;color:var(--red)}
.st-PARTIAL{background:#2d1f06;color:var(--amber)}
.st-EXCESSIVE_AGENCY{background:#2d1206;color:#fb7a28}
.st-REVEALS_INTERNALS{background:#2d1f06;color:var(--amber)}
.st-MCP_INJECTED{background:#2d0a2d;color:#d946ef;border:1px solid #7e22ce}
.st-PROTOCOL_ABUSE{background:#1a0d2e;color:#818cf8;border:1px solid #3730a3}
.st-SSRF_ATTEMPT{background:#3d0f1a;color:#fb7185;border:1px solid #9f1239}
.st-JAILBREAK_ATTEMPT{background:#2d1a06;color:#fb923c;border:1px solid #9a3412}
.st-TIMEOUT{background:#1a1a1a;color:#6b7280;border:1px solid #374151}

/* Payload detail row */
.detail-row td{padding:0}
.detail-inner{padding:10px 16px;background:#06101f;border-top:1px solid #1e3a5f}
.detail-inner pre{font-size:11px;white-space:pre-wrap;word-break:break-all;margin-top:4px;max-height:120px;overflow-y:auto}
.detail-label{font-size:10px;color:var(--muted);text-transform:uppercase;letter-spacing:.05em;margin-top:8px}
.detail-label:first-child{margin-top:0}

/* Filter bar */
.filter-bar{padding:8px 16px;border-bottom:1px solid var(--border);
  display:flex;gap:8px;align-items:center;flex-wrap:wrap}
.filter-bar select{background:#0f172a;color:var(--text);border:1px solid var(--border);
  border-radius:4px;padding:3px 8px;font-size:12px;cursor:pointer}

/* Service status */
.svc-list{padding:12px 16px}
.svc-row{display:flex;justify-content:space-between;align-items:center;
  padding:8px 0;border-bottom:1px solid var(--border)}
.svc-row:last-child{border-bottom:none}
.svc-name{font-size:13px}
.svc-url{font-size:10px;color:var(--muted)}
.svc-badge-ok{background:#0a2016;color:var(--green);border:1px solid #166534;
  border-radius:20px;padding:2px 10px;font-size:11px}
.svc-badge-off{background:#2d1515;color:var(--red);border:1px solid #991b1b;
  border-radius:20px;padding:2px 10px;font-size:11px}
.svc-badge-cred{background:#2d1f06;color:var(--amber);border:1px solid #854f0b;
  border-radius:20px;padding:2px 10px;font-size:11px}

/* Framework */
.fw-row{padding:8px 16px;border-bottom:1px solid var(--border);font-size:12px}
.fw-tag{display:inline-block;background:#102038;color:var(--blue);border-radius:4px;
  padding:1px 6px;font-size:10px;margin-right:4px;margin-bottom:2px}

/* OWASP chart */
.bar-chart{padding:12px 16px}
.bar-row{display:flex;align-items:center;gap:8px;margin-bottom:8px}
.bar-label{width:50px;font-size:11px;color:var(--muted)}
.bar-track{flex:1;height:16px;background:#1e293b;border-radius:4px;overflow:hidden}
.bar-fill{height:100%;border-radius:4px;transition:width .3s}
.bar-fill-red{background:var(--red)}
.bar-fill-amber{background:var(--amber)}
.bar-fill-blue{background:var(--blue)}
.bar-count{width:24px;font-size:11px;text-align:right;color:var(--muted)}

/* Runs */
.run-row{padding:8px 16px;border-bottom:1px solid var(--border);display:flex;
  justify-content:space-between;align-items:center;font-size:12px}
.run-id{font-family:monospace;font-size:11px;color:var(--cyan)}
.run-meta{color:var(--muted);font-size:11px}
.run-score{font-size:13px;font-weight:700;color:var(--green)}

/* Timestamp */
.ts{font-size:10px;color:var(--muted)}
.tag-count{background:#102038;color:var(--blue);border-radius:20px;
  padding:1px 8px;font-size:11px}

/* Gap warning */
.gap-banner{background:#1a0a00;border:1px solid var(--red);border-radius:8px;
  padding:12px 16px;margin-bottom:16px;display:flex;align-items:flex-start;gap:12px}
.gap-icon{font-size:20px;color:var(--red)}
.gap-text{font-size:13px;color:var(--red);font-weight:600}
.gap-sub{font-size:12px;color:#94a3b8;margin-top:2px}
</style>
</head>
<body>
<div class="wrap">

<div class="header">
  <div class="header-left">
    <h1>AI SECURITY POC</h1>
    <div class="sub">Qualys TotalAI · CrowdStrike AIDR · Morphisec · Splunk SIEM · OWASP LLM Top 10 · MITRE ATLAS</div>
  </div>
  <div class="header-right">
    <span class="conf-badge">CONFIDENTIAL</span>
    <div class="live-badge"><span class="live-dot"></span>LIVE</div>
    <button class="run-btn" onclick="runTests()">▶ Run Tests</button>
    <button class="run-btn" style="background:#0f3d2e" onclick="location.reload()">⟳ Refresh</button>
  </div>
</div>

<div class="gap-banner">
  <div class="gap-icon">⚠</div>
  <div>
    <div class="gap-text">CRITICAL GAP — THE VISIBILITY FLOOR</div>
    <div class="gap-sub">The entire four-tool stack activates only AFTER deployment. Training data poisoning, model weight tampering, and serialization attacks are completely invisible to CrowdStrike AIDR, Morphisec, Qualys TotalAI, and Splunk.</div>
  </div>
</div>

<div class="stats" id="stats">
  <div class="stat"><div class="stat-val c-red" id="s-critical">—</div><div class="stat-label">Critical</div></div>
  <div class="stat"><div class="stat-val c-amber" id="s-high">—</div><div class="stat-label">High</div></div>
  <div class="stat"><div class="stat-val c-blue" id="s-medium">—</div><div class="stat-label">Medium</div></div>
  <div class="stat"><div class="stat-val c-red" id="s-vuln">—</div><div class="stat-label">Vulnerable</div></div>
  <div class="stat"><div class="stat-val c-green" id="s-pass">—</div><div class="stat-label">Tests Passed</div></div>
  <div class="stat"><div class="stat-val c-purple" id="s-total">—</div><div class="stat-label">Total Findings</div></div>
</div>

<div class="grid-main">
  <div class="card">
    <div class="card-hdr">
      <h2>Security Findings</h2>
      <span class="tag-count" id="findings-count">0</span>
    </div>
    <div class="filter-bar">
      <span style="font-size:11px;color:var(--muted)">FILTER:</span>
      <select id="catFilter" onchange="filterFindings()">
        <option value="">All Categories</option>
        <option value="MCP Protocol Abuse">MCP Protocol Abuse</option>
        <option value="Prompt Injection">Prompt Injection</option>
        <option value="Context Manipulation">Context Manipulation</option>
        <option value="Info Disclosure">Info Disclosure</option>
        <option value="Excessive Agency">Excessive Agency</option>
        <option value="Infrastructure">Infrastructure</option>
        <option value="DLP">DLP</option>
      </select>
      <select id="sevFilter" onchange="filterFindings()">
        <option value="">All Severities</option>
        <option value="Critical">Critical</option>
        <option value="High">High</option>
        <option value="Medium">Medium</option>
        <option value="Low">Low</option>
        <option value="Info">Info</option>
      </select>
      <select id="statusFilter" onchange="filterFindings()">
        <option value="">All Statuses</option>
        <option value="VULNERABLE">VULNERABLE</option>
        <option value="MCP_INJECTED">MCP_INJECTED</option>
        <option value="SSRF_ATTEMPT">SSRF_ATTEMPT</option>
        <option value="PROTOCOL_ABUSE">PROTOCOL_ABUSE</option>
        <option value="REVEALS_INTERNALS">REVEALS_INTERNALS</option>
        <option value="RESISTANT">RESISTANT</option>
      </select>
      <span style="font-size:11px;color:var(--muted);margin-left:4px">
        Click any row to expand payload &amp; response
      </span>
    </div>
    <div class="card-body">
      <table>
        <thead><tr>
          <th>Test</th><th>Finding</th><th>Category</th><th>OWASP</th><th>Severity</th><th>Status</th><th>Framework</th>
        </tr></thead>
        <tbody id="findings-body"><tr><td colspan="7" style="text-align:center;color:var(--muted);padding:32px">No findings yet — click Run Tests</td></tr></tbody>
      </table>
    </div>
  </div>

  <div style="display:flex;flex-direction:column;gap:16px">
    <div class="card">
      <div class="card-hdr"><h2>Service Status</h2></div>
      <div class="svc-list" id="svc-list">Loading...</div>
    </div>
    <div class="card">
      <div class="card-hdr"><h2>Findings by OWASP</h2></div>
      <div class="bar-chart" id="owasp-chart">Loading...</div>
    </div>
  </div>
</div>

<div class="grid-bottom">
  <div class="card">
    <div class="card-hdr"><h2>Test Run History</h2></div>
    <div class="card-body" id="runs-body">Loading...</div>
  </div>
  <div class="card">
    <div class="card-hdr"><h2>Framework Mapping</h2></div>
    <div class="card-body" id="framework-body">Loading...</div>
  </div>
</div>

</div>

<script>
const SEV_ORDER = {Critical:0,High:1,Medium:2,Low:3,Info:4};

function badge(cls, text) {
  return `<span class="badge ${cls}">${text}</span>`;
}

async function loadData() {
  try {
    const [summary, findings, runs, services] = await Promise.all([
      fetch('/api/summary').then(r=>r.json()),
      fetch('/api/findings').then(r=>r.json()),
      fetch('/api/runs').then(r=>r.json()),
      fetch('/api/services').then(r=>r.json()),
    ]);

    // Stats
    document.getElementById('s-critical').textContent = summary.critical;
    document.getElementById('s-high').textContent     = summary.high;
    document.getElementById('s-medium').textContent   = summary.medium;
    document.getElementById('s-vuln').textContent     = summary.vulnerable;
    document.getElementById('s-pass').textContent     = summary.tests_passed ?? '—';
    document.getElementById('s-total').textContent    = summary.total;
    document.getElementById('findings-count').textContent = findings.length;

    // Findings table
    const tbody = document.getElementById('findings-body');
    if (findings.length === 0) {
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center;color:var(--muted);padding:32px">No findings yet — click Run Tests</td></tr>';
    } else {
      const sorted = findings.sort((a,b) => (SEV_ORDER[a.severity]||9)-(SEV_ORDER[b.severity]||9));
      tbody.innerHTML = sorted.flatMap(f => {
        const esc = s => (s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
        const statusKey = (f.status||'').replace(/ /g,'_');
        const hasPL = f.payload && f.payload.trim();
        const hasRP = f.response_preview && f.response_preview.trim();
        const mainRow = `
        <tr class="finding-row" data-cat="${esc(f.category||'')}" data-sev="${esc(f.severity||'')}" data-status="${esc(f.status||'')}"
            onclick="toggleDetail(this)" style="cursor:pointer">
          <td><span style="font-family:monospace;font-size:11px;color:var(--cyan)">${f.test_num||''}</span></td>
          <td style="max-width:200px">${esc(f.finding_name)}</td>
          <td><span style="color:var(--muted);font-size:11px">${esc(f.category||'')}</span></td>
          <td>${f.owasp_id ? badge('sev-High', f.owasp_id) : ''}</td>
          <td>${badge('sev-'+(f.severity||'Info'), f.severity||'Info')}</td>
          <td>${badge('st-'+statusKey, f.status||'')}</td>
          <td style="max-width:160px;font-size:10px;color:var(--muted)">${esc((f.framework||'').split('—')[0])}</td>
        </tr>`;
        const detailRow = (hasPL || hasRP) ? `
        <tr class="detail-row" style="display:none">
          <td colspan="7"><div class="detail-inner">
            ${hasPL ? `<div class="detail-label">Payload</div><pre style="color:#fbbf24">${esc(f.payload||'')}</pre>` : ''}
            ${hasRP ? `<div class="detail-label">Response Preview</div><pre style="color:#94a3b8">${esc(f.response_preview||'')}</pre>` : ''}
            ${f.remediation ? `<div class="detail-label">Remediation</div><div style="font-size:11px;color:#4ade80;margin-top:4px">${esc(f.remediation)}</div>` : ''}
          </div></td>
        </tr>` : '';
        return [mainRow, detailRow];
      }).join('');
    }
    filterFindings();

    // Services
    const KNOWN = [
      {name:'Ollama',url:'http://localhost:11434',req:true},
      {name:'Open WebUI',url:'http://localhost:3001',req:false},
      {name:'ChromaDB',url:'http://localhost:8000',req:false},
      {name:'RAG API',url:'http://localhost:9001',req:false},
      {name:'MCP Server',url:'http://localhost:8765',req:false},
      {name:'LiteLLM + AIDR',url:'http://localhost:4000',note:'Needs CS_AIDR_TOKEN'},
    ];
    const svcMap = {};
    services.forEach(s => { svcMap[s.service_name] = s; });
    document.getElementById('svc-list').innerHTML = KNOWN.map(k => {
      const s = svcMap[k.name];
      let badgeHtml;
      if (k.note) {
        badgeHtml = `<span class="svc-badge-cred">⚿ CREDS</span>`;
      } else if (s && s.status==='RUNNING') {
        badgeHtml = `<span class="svc-badge-ok">● RUNNING</span>`;
      } else {
        badgeHtml = `<span class="svc-badge-off">○ OFFLINE</span>`;
      }
      return `<div class="svc-row">
        <div><div class="svc-name">${k.name}</div><div class="svc-url">${k.url}</div></div>
        ${badgeHtml}
      </div>`;
    }).join('');

    // OWASP chart
    const owaspCounts = {};
    findings.forEach(f => {
      if (f.owasp_id) owaspCounts[f.owasp_id] = (owaspCounts[f.owasp_id]||0)+1;
    });
    const max = Math.max(1,...Object.values(owaspCounts));
    const colors = {LLM01:'red',LLM03:'red',LLM06:'amber',LLM07:'amber',LLM08:'red',LLM10:'amber'};
    const owaspOrder = ['LLM01','LLM03','LLM06','LLM07','LLM08','LLM10'];
    document.getElementById('owasp-chart').innerHTML = owaspOrder.map(id => {
      const cnt = owaspCounts[id]||0;
      const pct = Math.max(2, Math.round((cnt/max)*100));
      const col = colors[id]||'blue';
      return `<div class="bar-row">
        <div class="bar-label">${id}</div>
        <div class="bar-track"><div class="bar-fill bar-fill-${col}" style="width:${pct}%"></div></div>
        <div class="bar-count">${cnt}</div>
      </div>`;
    }).join('');

    // Runs
    document.getElementById('runs-body').innerHTML = runs.length === 0
      ? '<div style="padding:32px;text-align:center;color:var(--muted)">No runs yet</div>'
      : runs.map(r => {
          const rate = r.total_tests > 0 ? Math.round((r.passed/r.total_tests)*100) : 0;
          const dt = r.started_at ? r.started_at.slice(0,19).replace('T',' ') : '';
          return `<div class="run-row">
            <div>
              <div class="run-id">${r.run_id}</div>
              <div class="run-meta">${dt} · ${r.label||''}</div>
            </div>
            <div style="text-align:right">
              <div class="run-score">${rate}%</div>
              <div class="run-meta">${r.passed||0}P / ${r.failed||0}F / ${r.skipped||0}S</div>
            </div>
          </div>`;
        }).join('');

    // Framework mapping
    const frameworks = [
      {tag:'MITRE ATLAS', detail:'AML.T0051 (Prompt Injection) · AML.T0054 (RAG Poisoning) · AML.T0012 (Model Extraction) · AML.T0048 (Excessive Agency)'},
      {tag:'OWASP LLM', detail:'LLM01 Prompt Injection · LLM03 Training Data Poisoning · LLM06 Sensitive Disclosure · LLM08 Excessive Agency · LLM10 Model Theft'},
      {tag:'NIST AI RMF', detail:'MS-2.5 AI system robustness · MS-2.6 Model integrity monitoring · GV-1 AI risk governance'},
      {tag:'EU AI Act', detail:'Art.9 Risk management · Art.10 Data governance · Art.13 Transparency · Art.17 Quality management'},
      {tag:'ISO 42001', detail:'Not currently covered — Phase C roadmap target (180-365 days)'},
      {tag:'GDPR', detail:'Art.25 Privacy by design · Membership inference protection · Training data PII controls'},
    ];
    document.getElementById('framework-body').innerHTML = frameworks.map(f => `
      <div class="fw-row">
        <span class="fw-tag">${f.tag}</span>
        <span style="color:var(--muted);font-size:11px">${f.detail}</span>
      </div>`).join('');

  } catch(e) {
    console.error('Dashboard load error:', e);
  }
}

async function runTests() {
  const btn = document.querySelector('.run-btn');
  btn.textContent = '⏳ Running...';
  btn.disabled = true;
  try {
    const r = await fetch('/api/run-tests', {method:'POST'});
    const data = await r.json();
    btn.textContent = '✓ Done — Refreshing';
    setTimeout(() => { location.reload(); }, 1500);
  } catch(e) {
    btn.textContent = '✗ Error';
    btn.disabled = false;
    setTimeout(() => { btn.textContent = '▶ Run Tests'; }, 3000);
  }
}

function toggleDetail(tr) {
  const next = tr.nextElementSibling;
  if (next && next.classList.contains('detail-row')) {
    next.style.display = next.style.display === 'none' ? '' : 'none';
  }
}

function filterFindings() {
  const cat    = document.getElementById('catFilter')?.value    || '';
  const sev    = document.getElementById('sevFilter')?.value    || '';
  const status = document.getElementById('statusFilter')?.value || '';
  let visible = 0;
  document.querySelectorAll('.finding-row').forEach(tr => {
    const match = (!cat    || tr.dataset.cat    === cat)
               && (!sev    || tr.dataset.sev    === sev)
               && (!status || tr.dataset.status === status);
    tr.style.display = match ? '' : 'none';
    const next = tr.nextElementSibling;
    if (next && next.classList.contains('detail-row'))
      next.style.display = 'none';
    if (match) visible++;
  });
  const cnt = document.getElementById('findings-count');
  if (cnt) cnt.textContent = visible || document.querySelectorAll('.finding-row').length;
}

loadData();
setInterval(loadData, 20000);
</script>
</body>
</html>
"""

@app.get("/", response_class=HTMLResponse)
def dashboard(): return HTML

@app.get("/api/summary")
def api_summary():
    s = F.get_summary()
    runs = F.get_all_runs()
    total_passed = sum(r.get("passed",0) for r in runs[:1])
    s["tests_passed"] = total_passed
    return s

@app.get("/api/findings")
def api_findings(): return F.get_findings()

@app.get("/api/runs")
def api_runs(): return F.get_all_runs()

@app.get("/api/services")
def api_services(): return F.get_service_checks()

@app.post("/api/run-tests")
async def api_run_tests():
    import subprocess, sys
    result = subprocess.Popen(
        [sys.executable, "test/run_tests.py"],
        cwd=os.path.dirname(os.path.abspath(__file__)),
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
    )
    return {"status": "started", "pid": result.pid}

if __name__ == "__main__":
    uvicorn.run(app, host="0.0.0.0", port=9002, log_level="warning")
