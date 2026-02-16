from flask import Flask, jsonify, render_template_string, send_from_directory, request
from pathlib import Path
import json, os, re
from datetime import datetime

RUNS_DIR = os.environ.get("RUNS_DIR", "/runs")
OUTDIR = Path(RUNS_DIR) / "output"
REPORTDIR = Path(RUNS_DIR) / "reports"
STATUSDIR = Path(RUNS_DIR) / "status"
QUEUEDIR = Path(RUNS_DIR) / "queue"

app = Flask(__name__)

STAGE_PROGRESS = {
    "init": 5,
    "dns_recon": 12,
    "reachability_probe": 20,
    "whois": 28,
    "nmap": 45,
    "nuclei": 60,
    "zap": 78,
    "subdomains": 86,
    "subdomain_probe": 90,
    "deep_ports": 94,
    "risk": 97,
    "writing_outputs": 99,
    "done": 100,
    "done_unreachable": 100,
}

def safe_name(s: str) -> str:
    return re.sub(r"[^a-zA-Z0-9._-]+", "_", s or "scan")

def human_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).isoformat(timespec="seconds")

def load_json(path: Path, default=None):
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return default if default is not None else {}

HTML = r"""
<!doctype html>
<html>
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Site Checker</title>
  <style>
    :root{
      --bg:#0b1220;
      --card:#0f1a30;
      --card2:#101f3b;
      --text:#e8eefc;
      --muted:#9bb0d0;
      --line:rgba(255,255,255,.10);
      --accent:#5dd6c7;
      --warn:#ffcc66;
      --bad:#ff6b6b;
      --good:#69db7c;
      --shadow: 0 18px 50px rgba(0,0,0,.45);
      --radius: 18px;
    }
    *{box-sizing:border-box}
    body{
      margin:0;
      font-family: ui-sans-serif, system-ui, -apple-system, Segoe UI, Roboto, Arial;
      background: radial-gradient(1200px 800px at 20% -10%, rgba(93,214,199,.25), transparent 60%),
                  radial-gradient(900px 600px at 100% 20%, rgba(130,170,255,.20), transparent 60%),
                  var(--bg);
      color:var(--text);
    }
    .wrap{max-width:1180px;margin:0 auto;padding:26px}
    .topbar{
      display:flex;gap:14px;flex-wrap:wrap;align-items:center;justify-content:space-between;
      margin-bottom:18px;
    }
    .brand{
      display:flex;gap:12px;align-items:center;
    }
    .logo{
      width:38px;height:38px;border-radius:14px;
      background: linear-gradient(135deg, rgba(93,214,199,1), rgba(130,170,255,1));
      box-shadow: var(--shadow);
    }
    h1{font-size:20px;margin:0}
    .sub{color:var(--muted);font-size:13px;margin-top:2px}
    .grid{
      display:grid;
      grid-template-columns: 1.1fr 1fr;
      gap:14px;
    }
    @media (max-width: 980px){
      .grid{grid-template-columns:1fr}
    }
    .card{
      background: linear-gradient(180deg, rgba(255,255,255,.06), rgba(255,255,255,.03));
      border:1px solid var(--line);
      border-radius: var(--radius);
      padding:16px;
      box-shadow: var(--shadow);
    }
    .card h2{margin:0 0 12px 0;font-size:15px;color:#dfe9ff}
    .row{display:flex;gap:10px;flex-wrap:wrap}
    input, select{
      width:100%;
      padding:12px 12px;
      border-radius:14px;
      border:1px solid var(--line);
      background: rgba(0,0,0,.18);
      color:var(--text);
      outline:none;
    }
    input::placeholder{color:rgba(232,238,252,.55)}
    .btn{
      padding:11px 14px;
      border-radius:14px;
      border:1px solid rgba(93,214,199,.35);
      background: rgba(93,214,199,.15);
      color: var(--text);
      cursor:pointer;
      font-weight:600;
    }
    .btn:hover{background: rgba(93,214,199,.22)}
    .btn:disabled{opacity:.5;cursor:not-allowed}
    .btn2{
      border:1px solid rgba(130,170,255,.35);
      background: rgba(130,170,255,.12);
    }
    .pill{
      display:inline-flex;align-items:center;gap:6px;
      padding:6px 10px;border-radius:999px;
      border:1px solid var(--line);
      background: rgba(0,0,0,.15);
      color: var(--muted);
      font-size:12px;
    }
    .progress{
      width:100%;
      height:10px;
      border-radius:999px;
      background: rgba(255,255,255,.08);
      overflow:hidden;
      border:1px solid var(--line);
    }
    .bar{
      height:100%;
      width:0%;
      background: linear-gradient(90deg, rgba(93,214,199,1), rgba(130,170,255,1));
    }
    .mono{
      font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, "Liberation Mono", monospace;
      font-size:12px;
      color: rgba(232,238,252,.92);
      white-space:pre-wrap;
      word-break:break-word;
      background: rgba(0,0,0,.18);
      border:1px solid var(--line);
      padding:12px;
      border-radius:14px;
      max-height:260px;
      overflow:auto;
    }
    table{width:100%;border-collapse:collapse}
    th, td{padding:10px 8px;border-bottom:1px solid rgba(255,255,255,.08);font-size:13px}
    th{color:var(--muted);font-weight:600;text-align:left}
    a{color: var(--accent);text-decoration:none}
    .small{font-size:12px;color:var(--muted)}
    .actions{display:flex;gap:8px;flex-wrap:wrap}
    .tag{
      display:inline-flex;align-items:center;
      padding:4px 8px;border-radius:999px;
      border:1px solid var(--line);
      font-size:12px;color:var(--muted);
      background: rgba(0,0,0,.14);
    }
    .ok{border-color: rgba(105,219,124,.35); color: rgba(105,219,124,.95)}
    .bad{border-color: rgba(255,107,107,.35); color: rgba(255,107,107,.95)}
    .warn{border-color: rgba(255,204,102,.35); color: rgba(255,204,102,.95)}
  </style>
</head>
<body>
  <div class="wrap">
    <div class="topbar">
      <div class="brand">
        <div class="logo"></div>
        <div>
          <h1>Site Checker</h1>
          <div class="sub">Run scans from the browser • Live status • History • Reports</div>
        </div>
      </div>
      <div class="row">
        <span class="pill" id="worker">worker: unknown</span>
        <span class="pill" id="now">loading…</span>
      </div>
    </div>

    <div class="grid">
      <!-- Left: Run + Live -->
      <div class="card">
        <h2>Run a scan</h2>
        <div class="row">
          <div style="flex:2;min-width:260px">
            <input id="target" placeholder="https://example.com" />
            <div class="small" style="margin-top:8px">Tip: include https://</div>
          </div>
          <div style="flex:1;min-width:200px">
            <select id="profile">
              <option value="">NMAP_PROFILE (keep default)</option>
              <option value="SAFE">SAFE</option>
              <option value="FULL">FULL</option>
            </select>
            <div class="small" style="margin-top:8px">Optional override</div>
          </div>
        </div>

        <div class="row" style="margin-top:10px">
          <div style="flex:1;min-width:200px">
            <select id="zapmode">
              <option value="">ZAP_MODE (keep default)</option>
              <option value="baseline">baseline (safe)</option>
              <option value="full">full (active/attack)</option>
            </select>
            <div class="small" style="margin-top:8px">Only use “full” with permission</div>
          </div>
          <div style="flex:1;min-width:200px">
            <select id="subenum">
              <option value="">SUBDOMAIN_ENUM (keep default)</option>
              <option value="1">on</option>
              <option value="0">off</option>
            </select>
            <div class="small" style="margin-top:8px">Speed vs coverage</div>
          </div>
        </div>

        <div class="row" style="margin-top:12px">
          <button class="btn" id="runBtn" onclick="runScan()">▶ Run scan</button>
          <button class="btn btn2" onclick="refreshAll()">⟳ Refresh</button>
          <span class="pill" id="queued">queue: 0</span>
        </div>

        <div style="margin-top:16px;display:flex;align-items:center;justify-content:space-between;gap:10px">
          <div>
            <div class="small">Current stage</div>
            <div style="font-weight:700" id="stageTxt">—</div>
          </div>
          <div class="tag" id="pctTag">0%</div>
        </div>

        <div style="margin-top:10px" class="progress">
          <div class="bar" id="bar"></div>
        </div>

        <div style="margin-top:12px">
          <div class="small">Latest status JSON</div>
          <div class="mono" id="statusBox">loading…</div>
        </div>
      </div>

      <!-- Right: Reports -->
      <div class="card">
        <h2>Reports</h2>
        <div class="row" style="margin-bottom:10px">
          <input id="q" placeholder="Search reports (domain, date…)" oninput="loadReports()" />
        </div>
        <table>
          <thead><tr><th>Report</th><th>When</th><th>Actions</th></tr></thead>
          <tbody id="reports"></tbody>
        </table>
      </div>
    </div>

    <div class="card" style="margin-top:14px">
      <h2>Last 10 scans (history)</h2>
      <table>
        <thead><tr><th>Target</th><th>When</th><th>Risk</th><th>Outputs</th></tr></thead>
        <tbody id="history"></tbody>
      </table>
      <div class="small" style="margin-top:10px">History is derived from the most recent <code>/runs/output/*_combined.json</code> files.</div>
    </div>

  </div>

<script>
function stageToPct(stage){
  if(!stage) return 0;
  return ({"__MAP__":0})[stage] || 0;
}

async function runScan(){
  const target = document.getElementById('target').value.trim();
  if(!target.startsWith('http://') && !target.startsWith('https://')){
    alert("Please include http:// or https://");
    return;
  }
  const env = {};
  const profile = document.getElementById('profile').value;
  const zapmode = document.getElementById('zapmode').value;
  const subenum = document.getElementById('subenum').value;

  if(profile) env["NMAP_PROFILE"] = profile;
  if(zapmode) env["ZAP_MODE"] = zapmode;
  if(subenum) env["SUBDOMAIN_ENUM"] = subenum;

  document.getElementById('runBtn').disabled = true;
  document.getElementById('runBtn').textContent = "Queued…";

  const r = await fetch('/api/run', {
    method:'POST',
    headers:{'Content-Type':'application/json'},
    body: JSON.stringify({target, env})
  });
  const j = await r.json();
  document.getElementById('runBtn').disabled = false;
  document.getElementById('runBtn').textContent = "▶ Run scan";

  if(!j.ok){
    alert("Failed: " + (j.error || "unknown"));
  } else {
    document.getElementById('target').value = '';
    refreshAll();
  }
}

async function loadStatus(){
  const r = await fetch('/api/status/latest');
  const j = await r.json();

  const stage = j.stage || j.stage_name || j.step || j.status || '—';
  const pct = stageToPct(stage);

  document.getElementById('stageTxt').textContent = stage;
  document.getElementById('pctTag').textContent = pct + "%";
  document.getElementById('bar').style.width = pct + "%";
  document.getElementById('statusBox').textContent = JSON.stringify(j, null, 2);
}

async function loadReports(){
  const q = document.getElementById('q').value.trim();
  const r = await fetch('/api/reports?q=' + encodeURIComponent(q));
  const j = await r.json();
  const tb = document.getElementById('reports');
  tb.innerHTML = '';
  (j.items || []).forEach(x=>{
    const tr = document.createElement('tr');

    const td1 = document.createElement('td');
    const a = document.createElement('a');
    a.href = '/reports/' + encodeURIComponent(x.name);
    a.textContent = x.name;
    td1.appendChild(a);

    const td2 = document.createElement('td');
    td2.textContent = x.mtime;

    const td3 = document.createElement('td');
    const div = document.createElement('div');
    div.className = 'actions';

    const open = document.createElement('a');
    open.className = 'btn btn2';
    open.style.padding = '7px 10px';
    open.textContent = 'Open';
    open.href = '/reports/' + encodeURIComponent(x.name);
    open.target = '_blank';

    const raw = document.createElement('a');
    raw.className = 'btn';
    raw.style.padding = '7px 10px';
    raw.textContent = 'Raw';
    raw.href = '/api/report/raw?name=' + encodeURIComponent(x.name);
    raw.target = '_blank';

    div.appendChild(open);
    div.appendChild(raw);
    td3.appendChild(div);

    tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3);
    tb.appendChild(tr);
  })
}

async function loadHistory(){
  const r = await fetch('/api/scans?limit=10');
  const j = await r.json();
  const tb = document.getElementById('history');
  tb.innerHTML = '';
  (j.items || []).forEach(x=>{
    const tr = document.createElement('tr');

    const td1 = document.createElement('td');
    td1.textContent = x.target || x.host || '—';

    const td2 = document.createElement('td');
    td2.textContent = x.timestamp || x.time || '—';

    const td3 = document.createElement('td');
    const tag = document.createElement('span');
    tag.className = 'tag ' + ((x.risk_level||'').toLowerCase()==='high'?'bad':((x.risk_level||'').toLowerCase()==='medium'?'warn':'ok'));
    tag.textContent = x.risk_level || '—';
    td3.appendChild(tag);

    const td4 = document.createElement('td');
    const div = document.createElement('div');
    div.className = 'actions';

    if(x.report_name){
      const open = document.createElement('a');
      open.className = 'btn btn2';
      open.style.padding = '7px 10px';
      open.textContent = 'Report';
      open.href = '/reports/' + encodeURIComponent(x.report_name);
      open.target = '_blank';
      div.appendChild(open);
    }
    if(x.combined_name){
      const openj = document.createElement('a');
      openj.className = 'btn';
      openj.style.padding = '7px 10px';
      openj.textContent = 'Combined JSON';
      openj.href = '/api/combined/raw?name=' + encodeURIComponent(x.combined_name);
      openj.target = '_blank';
      div.appendChild(openj);
    }
    td4.appendChild(div);

    tr.appendChild(td1); tr.appendChild(td2); tr.appendChild(td3); tr.appendChild(td4);
    tb.appendChild(tr);
  })
}

async function loadQueue(){
  const r = await fetch('/api/queue');
  const j = await r.json();
  document.getElementById('queued').textContent = 'queue: ' + (j.pending || 0);
}

async function loadWorker(){
  const r = await fetch('/api/worker');
  const j = await r.json();
  const el = document.getElementById('worker');
  if(j.ok){
    el.textContent = 'worker: ' + (j.stage || 'unknown');
  } else {
    el.textContent = 'worker: not ready';
  }
}

function refreshAll(){
  loadStatus(); loadReports(); loadHistory(); loadQueue(); loadWorker();
}

setInterval(()=>{
  document.getElementById('now').textContent = new Date().toLocaleString();
}, 1000);

refreshAll();
setInterval(loadStatus, 2500);
setInterval(loadReports, 12000);
setInterval(loadHistory, 12000);
setInterval(loadQueue, 3000);
setInterval(loadWorker, 5000);
</script>
</body>
</html>
""".replace('({"__MAP__":0})', json.dumps(STAGE_PROGRESS))

@app.get("/")
def index():
    return render_template_string(HTML)

@app.get("/api/reports")
def api_reports():
    REPORTDIR.mkdir(parents=True, exist_ok=True)
    q = (request.args.get("q") or "").strip().lower()
    items = []
    for p in sorted(REPORTDIR.glob("*_site_check_report.md"), key=lambda x: x.stat().st_mtime, reverse=True)[:200]:
        name = p.name
        if q and q not in name.lower():
            continue
        items.append({"name": name, "mtime": human_ts(p.stat().st_mtime)})
        if len(items) >= 50:
            break
    return jsonify({"items": items})

@app.get("/api/report/raw")
def api_report_raw():
    name = (request.args.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "missing name"}), 400
    f = REPORTDIR / name
    if not f.exists():
        return jsonify({"ok": False, "error": "not found"}), 404
    return f.read_text(encoding="utf-8", errors="ignore"), 200, {"Content-Type": "text/plain; charset=utf-8"}

@app.get("/api/combined/raw")
def api_combined_raw():
    name = (request.args.get("name") or "").strip()
    if not name:
        return jsonify({"ok": False, "error": "missing name"}), 400
    f = OUTDIR / name
    if not f.exists():
        return jsonify({"ok": False, "error": "not found"}), 404
    return f.read_text(encoding="utf-8", errors="ignore"), 200, {"Content-Type": "application/json; charset=utf-8"}

@app.get("/api/status/latest")
def api_status_latest():
    f = STATUSDIR / "latest.json"
    if not f.exists():
        return jsonify({"ok": False, "note": "latest.json not found yet"})
    return jsonify(load_json(f, default={"ok": False}))

@app.get("/api/scans")
def api_scans():
    OUTDIR.mkdir(parents=True, exist_ok=True)
    limit = int(request.args.get("limit") or "10")
    items = []
    for p in sorted(OUTDIR.glob("*_combined.json"), key=lambda x: x.stat().st_mtime, reverse=True)[: max(1, min(limit, 50))]:
        j = load_json(p, default={})
        report_path = (j.get("report_path") or "")
        combined_path = (j.get("combined_json_path") or "")
        items.append({
            "target": j.get("target") or j.get("host") or "",
            "timestamp": j.get("timestamp") or human_ts(p.stat().st_mtime),
            "risk_level": j.get("risk_level") or "",
            "report_name": Path(report_path).name if report_path else "",
            "combined_name": Path(combined_path).name if combined_path else p.name,
        })
    return jsonify({"items": items})

@app.post("/api/run")
def api_run():
    data = request.get_json(force=True, silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target.startswith(("http://", "https://")):
        return jsonify({"ok": False, "error": "target must start with http:// or https://"}), 400

    env = data.get("env") or {}
    if not isinstance(env, dict):
        env = {}

    QUEUEDIR.mkdir(parents=True, exist_ok=True)
    job_id = f"{safe_name(target)}_{datetime.now().strftime('%Y%m%d_%H%M%S')}"
    job = {"job_id": job_id, "target": target, "env": env}

    job_path = QUEUEDIR / f"{job_id}.json"
    job_path.write_text(json.dumps(job, indent=2), encoding="utf-8")

    return jsonify({"ok": True, "job_id": job_id, "queued": str(job_path)})

@app.get("/api/queue")
def api_queue():
    QUEUEDIR.mkdir(parents=True, exist_ok=True)
    pending = len(list(QUEUEDIR.glob("*.json")))
    return jsonify({"pending": pending})

@app.get("/api/worker")
def api_worker():
    f = STATUSDIR / "worker.json"
    if not f.exists():
        return jsonify({"ok": False})
    return jsonify(load_json(f, default={"ok": False}))

@app.get("/reports/<path:name>")
def get_report(name):
    return send_from_directory(str(REPORTDIR), name)

if __name__ == "__main__":
    app.run(host="0.0.0.0", port=8088)
