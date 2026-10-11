
#!/usr/bin/env python3
"""Genera un dashboard histórico para los análisis de OWASP ZAP."""

import json
import os
from datetime import datetime, timezone
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REPORT_PATH = ROOT / "reports" / "report.json"
DOCS_DIR = ROOT / "docs"
HISTORY_PATH = DOCS_DIR / "history.json"
HTML_PATH = DOCS_DIR / "index.html"
MAX_HISTORY = 100

RISK_NAMES = {
    "3": "Alto",
    "2": "Medio",
    "1": "Bajo",
    "0": "Informativo",
    "-1": "Falso positivo",
}

RISK_ORDER = ["3", "2", "1", "0"]


def read_json(path, default=None):
    """Lee un archivo JSON; devuelve default si no existe o no es válido."""
    if default is None:
        default = {}

    try:
        with path.open("r", encoding="utf-8") as file:
            return json.load(file)
    except (OSError, json.JSONDecodeError):
        return default


def write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )


def normalize_risk(value):
    return str(value if value is not None else "0")


def extract_alerts(report):
    """Extrae alertas del JSON estándar generado por OWASP ZAP."""
    alerts = []

    for site in report.get("site", []):
        for item in site.get("alerts", []):
            riskcode = normalize_risk(item.get("riskcode", "0"))
            instances = item.get("instances") or []

            alerts.append({
                "name": item.get("name") or "Alerta sin nombre",
                "riskcode": riskcode,
                "risk": RISK_NAMES.get(riskcode, "Desconocido"),
                "confidence": item.get("confidence", ""),
                "instances": len(instances),
                "description": item.get("desc", ""),
                "solution": item.get("solution", ""),
                "reference": item.get("reference", ""),
                "url": (
                    instances[0].get("uri", "")
                    if instances and isinstance(instances[0], dict)
                    else ""
                ),
            })

    # Evita duplicados exactos de nombre y riesgo en un mismo análisis.
    unique = {}
    for alert in alerts:
        key = (alert["name"], alert["riskcode"])
        if key not in unique:
            unique[key] = alert
        else:
            unique[key]["instances"] += alert["instances"]

    return sorted(
        unique.values(),
        key=lambda item: (
            -int(item["riskcode"]) if item["riskcode"].isdigit() else 1,
            item["name"].lower(),
        ),
    )


def count_risks(alerts):
    counts = {risk: 0 for risk in RISK_ORDER}
    for alert in alerts:
        risk = normalize_risk(alert.get("riskcode", "0"))
        if risk in counts:
            counts[risk] += 1
    return counts


def count_instances(alerts):
    return sum(int(alert.get("instances", 0) or 0) for alert in alerts)


def alert_keys(alerts):
    """Clave estable para comparar alertas entre ejecuciones."""
    return {
        f'{alert.get("name", "")}||{normalize_risk(alert.get("riskcode", "0"))}'
        for alert in alerts
    }


def make_snapshot(report):
    alerts = extract_alerts(report)
    counts = count_risks(alerts)

    run_id = os.getenv("GITHUB_RUN_ID", "")
    run_number = os.getenv("GITHUB_RUN_NUMBER", "")
    commit = os.getenv("GITHUB_SHA", "")[:12]
    timestamp = datetime.now(timezone.utc).isoformat(timespec="seconds")

    return {
        "run_id": run_id,
        "run_number": run_number,
        "timestamp": timestamp,
        "commit": commit,
        "total_alerts": len(alerts),
        "total_instances": count_instances(alerts),
        "counts": counts,
        "alerts": alerts,
    }


def compare_snapshots(current, previous):
    current_keys = alert_keys(current.get("alerts", []))
    previous_keys = alert_keys(previous.get("alerts", []))

    return {
        "new": len(current_keys - previous_keys),
        "resolved": len(previous_keys - current_keys),
        "continuing": len(current_keys & previous_keys),
    }


def safe_json_for_html(data):
    """Evita que datos del informe puedan cerrar el bloque script."""
    return (
        json.dumps(data, ensure_ascii=False)
        .replace("&", "\\u0026")
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
    )


def generate_html(history):
    current = history[-1] if history else {
        "timestamp": "",
        "run_number": "",
        "commit": "",
        "total_alerts": 0,
        "total_instances": 0,
        "counts": {risk: 0 for risk in RISK_ORDER},
        "alerts": [],
    }

    previous = history[-2] if len(history) > 1 else None
    comparison = compare_snapshots(current, previous) if previous else {
        "new": 0,
        "resolved": 0,
        "continuing": 0,
    }

    # El JSON va separado de la plantilla para evitar conflictos de llaves.
    page_data = safe_json_for_html({
        "history": history,
        "current": current,
        "comparison": comparison,
    })

    template = r"""<!doctype html>
<html lang="es">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<title>Security Lab | Dashboard</title>
<style>
:root {
  --bg:#0b1020; --panel:#121a2d; --panel2:#182239;
  --text:#edf2ff; --muted:#9aa9c5; --line:#293651;
  --high:#ff657a; --medium:#ffb454; --low:#64a9ff; --info:#a995ff;
  --good:#48d6a0; --accent:#7c9cff;
}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--text);
  font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
header{padding:30px 20px 24px;border-bottom:1px solid var(--line);
  background:linear-gradient(120deg,#151f38,#0b1020)}
main{max-width:1200px;margin:auto;padding:22px 18px 50px}
h1{margin:0 0 6px;font-size:clamp(25px,4vw,36px)}
h2{font-size:19px;margin:0 0 15px}
h3{font-size:16px;margin:0 0 8px}
p{margin:5px 0;color:var(--muted)}
.muted{color:var(--muted);font-size:13px}
.topline{display:flex;justify-content:space-between;gap:15px;flex-wrap:wrap}
.pill{display:inline-block;padding:5px 10px;border-radius:20px;
  background:#202d49;color:#dce6ff;font-size:12px}
.grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:13px;margin:20px 0}
.card,.panel{background:var(--panel);border:1px solid var(--line);
  border-radius:14px;padding:17px;min-width:0}
.metric{font-size:30px;font-weight:750;margin:5px 0}
.metric-label{color:var(--muted);font-size:13px}
.high{color:var(--high)} .medium{color:var(--medium)}
.low{color:var(--low)} .info{color:var(--info)} .good{color:var(--good)}
.two{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin:14px 0}
.chart{width:100%;height:260px;display:block}
.panel{margin:14px 0}
.legend{display:flex;flex-wrap:wrap;gap:12px;font-size:12px;color:var(--muted)}
.legend span{display:flex;align-items:center;gap:6px}
.dot{width:9px;height:9px;border-radius:50%;display:inline-block}
.table-wrap{overflow-x:auto}
table{width:100%;border-collapse:collapse;font-size:13px}
th,td{text-align:left;padding:11px 10px;border-bottom:1px solid var(--line);vertical-align:top}
th{color:var(--muted);font-weight:600;white-space:nowrap}
td{overflow-wrap:anywhere}
tr:last-child td{border-bottom:0}
.risk{display:inline-block;padding:3px 8px;border-radius:6px;font-size:11px;font-weight:700}
.risk-3{color:var(--high);background:#4a202e}
.risk-2{color:var(--medium);background:#49351f}
.risk-1{color:var(--low);background:#1e3556}
.risk-0{color:var(--info);background:#30264e}
.actions{display:flex;gap:8px;flex-wrap:wrap;margin:10px 0}
button,input,select{background:var(--panel2);border:1px solid var(--line);
  border-radius:8px;color:var(--text);padding:9px 11px}
button{cursor:pointer}button:hover{border-color:var(--accent)}
input{min-width:180px;flex:1}
footer{padding-top:18px;color:var(--muted);font-size:12px;text-align:center}
.empty{padding:20px;color:var(--muted);text-align:center}
@media(max-width:760px){.grid{grid-template-columns:repeat(2,minmax(0,1fr))}
.two{grid-template-columns:1fr}.metric{font-size:26px}header{padding-top:22px}}
@media(max-width:380px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<header>
  <div class="topline">
    <div>
      <h1>Security Lab Dashboard</h1>
      <p>Historial y tendencias de OWASP ZAP · Entorno de laboratorio</p>
    </div>
    <span class="pill">ANÁLISIS DEFENSIVO</span>
  </div>
</header>
<main>
  <div class="topline">
    <div>
      <h2>Resumen de la última ejecución</h2>
      <p id="runMeta">Cargando datos...</p>
    </div>
    <span class="pill" id="historyCount">Historial: 0 ejecuciones</span>
  </div>

  <section class="grid">
    <div class="card"><div class="metric-label">Alertas detectadas</div>
      <div class="metric" id="total">—</div><div class="muted">Tipos de alerta</div></div>
    <div class="card"><div class="metric-label">Riesgo alto</div>
      <div class="metric high" id="high">—</div><div class="muted">Revisar primero</div></div>
    <div class="card"><div class="metric-label">Riesgo medio</div>
      <div class="metric medium" id="medium">—</div><div class="muted">Prioridad siguiente</div></div>
    <div class="card"><div class="metric-label">Instancias</div>
      <div class="metric" id="instances">—</div><div class="muted">Ubicaciones afectadas</div></div>
  </section>

  <section class="grid">
    <div class="card"><div class="metric-label">Alertas nuevas</div>
      <div class="metric medium" id="newAlerts">—</div><div class="muted">Frente al análisis anterior</div></div>
    <div class="card"><div class="metric-label">Alertas resueltas</div>
      <div class="metric good" id="resolvedAlerts">—</div><div class="muted">Ya no aparecen</div></div>
    <div class="card"><div class="metric-label">Alertas persistentes</div>
      <div class="metric low" id="continuingAlerts">—</div><div class="muted">Siguen presentes</div></div>
    <div class="card"><div class="metric-label">Análisis guardados</div>
      <div class="metric" id="runs">—</div><div class="muted">Máximo 100 registros</div></div>
  </section>

  <section class="two">
    <div class="panel">
      <h2>Tendencia de alertas por riesgo</h2>
      <canvas id="trendChart" class="chart" aria-label="Tendencia de alertas por riesgo"></canvas>
      <div class="legend">
        <span><i class="dot" style="background:var(--high)"></i>Alto</span>
        <span><i class="dot" style="background:var(--medium)"></i>Medio</span>
        <span><i class="dot" style="background:var(--low)"></i>Bajo</span>
        <span><i class="dot" style="background:var(--info)"></i>Informativo</span>
      </div>
    </div>
    <div class="panel">
      <h2>Distribución actual</h2>
      <canvas id="distributionChart" class="chart" aria-label="Distribución de alertas por riesgo"></canvas>
      <div class="legend">
        <span><i class="dot" style="background:var(--high)"></i>Alto</span>
        <span><i class="dot" style="background:var(--medium)"></i>Medio</span>
        <span><i class="dot" style="background:var(--low)"></i>Bajo</span>
        <span><i class="dot" style="background:var(--info)"></i>Informativo</span>
      </div>
    </div>
  </section>

  <section class="panel">
    <h2>Historial de ejecuciones</h2>
    <p>Selecciona una ejecución para consultar sus alertas.</p>
    <div class="actions">
      <input id="historySearch" type="search" placeholder="Buscar por fecha, ejecución o commit">
      <button id="downloadHistory">Exportar historial JSON</button>
    </div>
    <div class="table-wrap">
      <table><thead><tr>
        <th>Fecha UTC</th><th>Ejecución</th><th>Alto</th><th>Medio</th>
        <th>Bajo</th><th>Informativo</th><th>Total</th><th>Commit</th><th>Ver</th>
      </tr></thead><tbody id="historyTable"></tbody></table>
    </div>
  </section>

  <section class="panel">
    <h2 id="alertsTitle">Alertas de la última ejecución</h2>
    <div class="actions">
      <input id="alertSearch" type="search" placeholder="Buscar alerta o descripción">
      <select id="riskFilter" aria-label="Filtrar por riesgo">
        <option value="">Todos los riesgos</option>
        <option value="3">Alto</option><option value="2">Medio</option>
        <option value="1">Bajo</option><option value="0">Informativo</option>
      </select>
      <button id="latestButton">Volver a la última</button>
    </div>
    <div class="table-wrap">
      <table><thead><tr>
        <th>Riesgo</th><th>Alerta</th><th>Instancias</th><th>Descripción</th><th>URL de ejemplo</th>
      </tr></thead><tbody id="alertsTable"></tbody></table>
    </div>
  </section>
  <footer>Generado automáticamente por GitHub Actions · OWASP ZAP · Uso en laboratorio autorizado</footer>
</main>
<script id="dashboard-data" type="application/json">__DATA__</script>
<script>
(function(){
"use strict";
const DATA = JSON.parse(document.getElementById("dashboard-data").textContent);
const history = DATA.history || [];
const latest = DATA.current || {};
let selected = latest;
const palette = { "3":"#ff657a", "2":"#ffb454", "1":"#64a9ff", "0":"#a995ff" };
const labels = { "3":"Alto", "2":"Medio", "1":"Bajo", "0":"Informativo" };
const $ = id => document.getElementById(id);
const fmtDate = value => {
  if(!value) return "—";
  const d = new Date(value);
  return Number.isNaN(d.getTime()) ? value : d.toLocaleString("es-BO", {timeZone:"UTC"}) + " UTC";
};
const esc = value => String(value == null ? "" : value).replace(/[&<>"']/g, c => ({
  "&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"
}[c]));
function setText(id, value){ $(id).textContent = value == null ? "—" : value; }

function renderSummary(snapshot, comparison){
  const counts = snapshot.counts || {};
  setText("total", snapshot.total_alerts || 0);
  setText("high", counts["3"] || 0);
  setText("medium", counts["2"] || 0);
  setText("instances", snapshot.total_instances || 0);
  setText("newAlerts", comparison.new || 0);
  setText("resolvedAlerts", comparison.resolved || 0);
  setText("continuingAlerts", comparison.continuing || 0);
  setText("runs", history.length);
  setText("historyCount", "Historial: " + history.length + " ejecuciones");
  setText("runMeta", "Fecha: " + fmtDate(snapshot.timestamp) +
    " · Ejecución: #" + (snapshot.run_number || "—") +
    " · Commit: " + (snapshot.commit || "—"));
}

function setupCanvas(canvas){
  const rect = canvas.getBoundingClientRect();
  const ratio = window.devicePixelRatio || 1;
  canvas.width = Math.max(1, Math.round(rect.width * ratio));
  canvas.height = Math.max(1, Math.round(rect.height * ratio));
  const ctx = canvas.getContext("2d");
  ctx.setTransform(ratio,0,0,ratio,0,0);
  return {ctx,w:rect.width,h:rect.height};
}

function drawTrend(){
  const canvas = $("trendChart");
  const {ctx,w,h} = setupCanvas(canvas);
  ctx.clearRect(0,0,w,h);
  const rows = history.slice(-20);
  if(!rows.length){ctx.fillStyle="#9aa9c5";ctx.fillText("Todavía no hay historial",16,30);return;}
  const pad = {l:32,r:10,t:12,b:38};
  const pw = Math.max(1,w-pad.l-pad.r), ph = Math.max(1,h-pad.t-pad.b);
  const max = Math.max(1,...rows.map(r => RISK_ORDER.reduce((sum,k)=>sum+Number((r.counts||{})[k]||0),0)));
  ctx.font="10px system-ui";ctx.strokeStyle="#293651";ctx.fillStyle="#9aa9c5";
  for(let i=0;i<=4;i++){
    const y=pad.t+ph*i/4;
    ctx.beginPath();ctx.moveTo(pad.l,y);ctx.lineTo(w-pad.r,y);ctx.stroke();
    ctx.fillText(String(Math.round(max*(4-i)/4)),2,y+3);
  }
  RISK_ORDER.forEach(risk=>{
    ctx.strokeStyle=palette[risk];ctx.lineWidth=2;ctx.beginPath();
    rows.forEach((row,i)=>{
      const x=pad.l+(rows.length===1?pw/2:pw*i/(rows.length-1));
      const val=Number((row.counts||{})[risk]||0);
      const y=pad.t+ph-(val/max)*ph;
      if(i===0)ctx.moveTo(x,y);else ctx.lineTo(x,y);
    });
    ctx.stroke();
  });
  const ticks = Math.min(rows.length,5);
  for(let i=0;i<ticks;i++){
    const index=ticks===1?rows.length-1:Math.round(i*(rows.length-1)/(ticks-1));
    const x=pad.l+(rows.length===1?pw/2:pw*index/(rows.length-1));
    const row=rows[index];
    const label=row.run_number ? "#"+row.run_number : (row.timestamp||"").slice(5,10);
    ctx.fillStyle="#9aa9c5";ctx.textAlign="center";ctx.fillText(label,x,h-17);
  }
  ctx.textAlign="start";
}

function drawDistribution(){
  const canvas = $("distributionChart");
  const {ctx,w,h} = setupCanvas(canvas);
  ctx.clearRect(0,0,w,h);
  const counts = latest.counts || {};
  const values = RISK_ORDER.map(k=>Number(counts[k]||0));
  const total=values.reduce((a,b)=>a+b,0);
  if(total===0){ctx.fillStyle="#9aa9c5";ctx.font="13px system-ui";ctx.fillText("No hay alertas para mostrar",12,28);return;}
  const cx=w/2, cy=h/2, radius=Math.min(w,h)*0.30, inner=radius*0.62;
  let angle=-Math.PI/2;
  values.forEach((value,i)=>{
    if(!value)return;
    const end=angle+(value/total)*Math.PI*2;
    ctx.beginPath();ctx.arc(cx,cy,radius,angle,end);ctx.arc(cx,cy,inner,end,angle,true);
    ctx.closePath();ctx.fillStyle=palette[RISK_ORDER[i]];ctx.fill();angle=end;
  });
  ctx.textAlign="center";ctx.fillStyle="#edf2ff";ctx.font="bold 25px system-ui";
  ctx.fillText(String(total),cx,cy+2);
  ctx.font="11px system-ui";ctx.fillStyle="#9aa9c5";ctx.fillText("alertas",cx,cy+19);
  ctx.textAlign="start";
}

function renderHistory(filter=""){
  const body=$("historyTable");
  const term=filter.toLowerCase();
  const rows=history.slice().reverse().filter(row =>
    [row.timestamp,row.run_number,row.commit].join(" ").toLowerCase().includes(term));
  if(!rows.length){body.innerHTML='<tr><td colspan="9" class="empty">No hay ejecuciones que coincidan.</td></tr>';return;}
  body.innerHTML=rows.map(row=>{
    const c=row.counts||{};
    const index=history.indexOf(row);
    return `<tr>
      <td>${esc(fmtDate(row.timestamp))}</td><td>#${esc(row.run_number||"—")}</td>
      <td class="high">${Number(c["3"]||0)}</td>
      <td class="medium">${Number(c["2"]||0)}</td>
      <td class="low">${Number(c["1"]||0)}</td>
      <td>${Number(c["0"]||0)}</td>
      <td><strong>${Number(row.total_alerts||0)}</strong></td>
      <td>${esc(row.commit||"—")}</td>
      <td><button data-history-index="${index}">Ver</button></td>
    </tr>`;
  }).join("");
  body.querySelectorAll("button[data-history-index]").forEach(button=>{
    button.addEventListener("click",()=>{
      const row=history[Number(button.dataset.historyIndex)];
      if(row) selectSnapshot(row);
    });
  });
}

function renderAlerts(){
  const body=$("alertsTable");
  const term=$("alertSearch").value.toLowerCase();
  const risk=$("riskFilter").value;
  const alerts=(selected.alerts||[]).filter(a=>{
    const matchesRisk=!risk || String(a.riskcode)===risk;
    const matchesText=[a.name,a.description,a.url,a.solution].join(" ").toLowerCase().includes(term);
    return matchesRisk&&matchesText;
  });
  if(!alerts.length){body.innerHTML='<tr><td colspan="5" class="empty">No hay alertas que coincidan.</td></tr>';return;}
  body.innerHTML=alerts.map(a=>{
    const code=String(a.riskcode==null?"0":a.riskcode);
    const desc=String(a.description||"").replace(/<[^>]*>/g," ").replace(/\s+/g," ").trim();
    return `<tr>
      <td><span class="risk risk-${esc(code)}">${esc(a.risk||labels[code]||"Desconocido")}</span></td>
      <td><strong>${esc(a.name)}</strong></td>
      <td>${Number(a.instances||0)}</td>
      <td>${esc(desc.slice(0,450))}${desc.length>450?"…":""}</td>
      <td>${a.url?`<a href="${esc(a.url)}" target="_blank" rel="noopener noreferrer">${esc(a.url)}</a>`:"—"}</td>
    </tr>`;
  }).join("");
  setText("alertsTitle","Alertas de la ejecución "+(selected.run_number?"#"+selected.run_number:"seleccionada"));
}

function selectSnapshot(snapshot){
  selected=snapshot;
  const index=history.indexOf(snapshot);
  const previous=index>0?history[index-1]:null;
  const currentKeys=new Set((snapshot.alerts||[]).map(a=>a.name+"||"+a.riskcode));
  const previousKeys=new Set((previous?.alerts||[]).map(a=>a.name+"||"+a.riskcode));
  const comparison=previous?{
    new:[...currentKeys].filter(k=>!previousKeys.has(k)).length,
    resolved:[...previousKeys].filter(k=>!currentKeys.has(k)).length,
    continuing:[...currentKeys].filter(k=>previousKeys.has(k)).length
  }:{new:0,resolved:0,continuing:0};
  renderSummary(snapshot,comparison);
  renderAlerts();
}

$("historySearch").addEventListener("input",e=>renderHistory(e.target.value));
$("alertSearch").addEventListener("input",renderAlerts);
$("riskFilter").addEventListener("change",renderAlerts);
$("latestButton").addEventListener("click",()=>selectSnapshot(latest));
$("downloadHistory").addEventListener("click",()=>{
  const blob=new Blob([JSON.stringify(history,null,2)],{type:"application/json"});
  const url=URL.createObjectURL(blob);
  const a=document.createElement("a");a.href=url;a.download="security-lab-history.json";
  document.body.appendChild(a);a.click();a.remove();URL.revokeObjectURL(url);
});
window.addEventListener("resize",()=>{drawTrend();drawDistribution();});
renderSummary(latest,DATA.comparison||{new:0,resolved:0,continuing:0});
renderHistory();
renderAlerts();
drawTrend();
drawDistribution();
})();
</script>
</body>
</html>
"""
    return template.replace("__DATA__", page_data)


def main():
    if not REPORT_PATH.exists():
        raise SystemExit(
            f"No se encontró {REPORT_PATH}. Ejecuta primero el análisis de ZAP."
        )

    report = read_json(REPORT_PATH)
    if not isinstance(report, dict) or "site" not in report:
        raise SystemExit("El archivo report.json no tiene el formato esperado de OWASP ZAP.")

    DOCS_DIR.mkdir(parents=True, exist_ok=True)
    history = read_json(HISTORY_PATH, default=[])
    if not isinstance(history, list):
        history = []

    snapshot = make_snapshot(report)

    # Reemplaza el registro si se vuelve a ejecutar el generador en el mismo run.
    run_id = snapshot.get("run_id")
    replaced = False
    if run_id:
        for index, old in enumerate(history):
            if old.get("run_id") == run_id:
                history[index] = snapshot
                replaced = True
                break

    if not replaced:
        history.append(snapshot)

    history = history[-MAX_HISTORY:]
    write_json(HISTORY_PATH, history)
    HTML_PATH.write_text(generate_html(history), encoding="utf-8")

    print(f"Dashboard generado: {HTML_PATH}")
    print(f"Historial guardado: {HISTORY_PATH}")
    print(f"Ejecuciones conservadas: {len(history)}")
    print(f"Alertas actuales: {snapshot['total_alerts']}")
    print(f"Instancias actuales: {snapshot['total_instances']}")


if __name__ == "__main__":
    main()
